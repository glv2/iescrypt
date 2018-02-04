;;;; -*- mode: lisp; indent-tabs-mode: nil -*-

#|
This file is part of iescrypt, a program for encrypting, decrypting
and signing files.

Copyright 2015-2017 Guillaume LE VAILLANT

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
|#


(in-package iescrypt)


(defconstant +cipher+ :chacha)
(defconstant +digest+ :blake2)
(defconstant +kdf-iterations+ 10000)
(setf *random-state* (make-random-state t))


(defun get-temporary-filename (&optional (suffix ""))
  "Generate a file name ending with SUFFIX that doesn't match any of the
files in the current directory."
  (let* ((id (random 1000000000))
         (filename (format nil "tmp-~d~a" id suffix)))
    (if (file-exists-p filename)
        (get-temporary-filename suffix)
        filename)))

(defun read-file (filename)
  "Return the content of FILENAME in a byte array."
  (with-open-file (file filename
                        :direction :input
                        :element-type '(unsigned-byte 8))
    (let* ((length (file-length file))
           (buffer (make-array length :element-type '(unsigned-byte 8))))
      (unless (= (read-sequence buffer file) length)
        (error "Could not read complete file."))
      buffer)))

(defun read-passphrase (filename)
  "Return the first line of FILENAME."
  (with-open-file (file filename
                        :direction :input)
    (let ((passphrase (read-line file nil nil)))
      (unless passphrase
        (error "Could not read passphrase from file."))
      passphrase)))

(defun read-public-key (filename)
  "Read a public key for curve25519 or ed25519 from FILENAME."
  (let ((public-key (read-file filename)))
    (unless (= (length public-key) 32)
      (error "Wrong public key size."))
    public-key))

(defun read-private-key (filename)
  "Read a private key for curve25519 or ed25519 from FILENAME."
  (let ((private-key (read-file filename)))
    (unless (= (length private-key) 32)
      (error "Wrong private key size."))
    private-key))

(defun read-signature (filename)
  "Read a ed25519 signature from FILENAME."
  (let ((signature (read-file filename)))
    (unless (= (length signature) 96)
      (error "Wrong signature size."))
    signature))

(defun write-file (filename input)
  "Write the content of INPUT to FILENAME. INPUT can be a byte array
or a byte stream."
  (with-open-file (output filename
                          :direction :output
                          :element-type '(unsigned-byte 8))
    (etypecase input
      (vector (write-sequence input output))
      (stream (do* ((buffer (make-array 32768 :element-type '(unsigned-byte 8)))
                    (length (read-sequence buffer input)
                            (read-sequence buffer input)))
                   ((zerop length))
                (write-sequence buffer output :end length))))))

(defun make-encryption-key-pair (filename)
  "Generate a new key pair for curve25519. The private key is written to
FILENAME and the public key is written to FILENAME.pub."
  (multiple-value-bind (skey pkey) (generate-key-pair :curve25519)
    (write-file filename (curve25519-key-x skey))
    (write-file (concatenate 'string filename ".pub") (curve25519-key-y pkey))))

(defun make-signing-key-pair (filename)
  "Generate a new key pair for ed25519. The private key is written to
FILENAME and the public key is written to FILENAME.pub."
  (multiple-value-bind (skey pkey) (generate-key-pair :ed25519)
    (write-file filename (ed25519-key-x skey))
    (write-file (concatenate 'string filename ".pub") (ed25519-key-y pkey))))

(defun encrypt-file (input-filename output-filename &key passphrase public-key)
  "Encrypt INPUT-FILENAME and write the ciphertext to OUTPUT-FILENAME.
The encryption requires a shared secret that can be derived from a PASSPHRASE
or a PUBLIC-KEY."
  (with-open-file (input input-filename
                         :direction :input
                         :element-type '(unsigned-byte 8))
    (with-open-file (output output-filename
                            :direction :output
                            :element-type '(unsigned-byte 8))
      (cond (passphrase
             (ies-encrypt-stream (string-to-octets passphrase :encoding :utf-8)
                                 +cipher+
                                 +digest+
                                 input
                                 output
                                 :kdf-iterations +kdf-iterations+))

            (public-key
             (ies-encrypt-stream (make-public-key :curve25519 :y public-key)
                                 +cipher+
                                 +digest+
                                 input
                                 output
                                 :kdf-iterations +kdf-iterations+))

            (t
             (error "Passphrase or public key must be specified."))))))

(defun decrypt-file (input-filename output-filename &key passphrase private-key)
  "Decrypt INPUT-FILENAME and write the cleartext to OUTPUT-FILENAME.
The decryption requires a shared secret that can be derived from a PASSPHRASE
or a PUBLIC-KEY."
  (with-open-file (input input-filename
                         :direction :input
                         :element-type '(unsigned-byte 8))
    (with-open-file (output output-filename
                            :direction :output
                            :element-type '(unsigned-byte 8))
      (cond (passphrase
             (ies-decrypt-stream (string-to-octets passphrase :encoding :utf-8)
                                 +cipher+
                                 +digest+
                                 input
                                 output
                                 :kdf-iterations +kdf-iterations+))

            (private-key
             (ies-decrypt-stream (make-private-key :curve25519 :x private-key)
                                 +cipher+
                                 +digest+
                                 input
                                 output
                                 :kdf-iterations +kdf-iterations+))

            (t
             (error "Passphrase or private key must be specified."))))))

(defun sign-file (input-filename private-key &optional signature-filename)
  "Return the signature of INPUT-FILENAME by PRIVATE-KEY.
If a SIGNATURE-FILENAME is specified, also write the signature to it."
  (let* ((privkey (make-private-key :ed25519 :x private-key))
         (public-key (ed25519-key-y privkey))
         (hash (digest-file +digest+ input-filename))
         (signature (concatenate '(simple-array (unsigned-byte 8) (*))
                                 public-key
                                 (sign-message privkey hash))))
    (when signature-filename
      (write-file signature-filename signature))
    signature))

(defun verify-file-signature (input-filename signature &optional public-key)
  "Verify that SIGNATURE is a valid sigature of INPUT-FILENAME.
If a PUBLIC-KEY is specified, also verify that the SIGNATURE was done using
the matching private key."
  (unless (= (length signature) 96)
    (error "Bad signature length."))
  (let* ((signature-public-key (subseq signature 0 32))
         (pubkey (make-public-key :ed25519 :y signature-public-key))
         (signature (subseq signature 32 96))
         (hash (digest-file +digest+ input-filename)))
    (if (and (or (null public-key)
                 (constant-time-equal signature-public-key public-key))
             (verify-signature pubkey hash signature))
        signature-public-key
        (error "Bad signature."))))

(defun sign-and-encrypt-file (input-filename output-filename signature-private-key &key passphrase public-key)
  "Sign INPUT-FILENAME with SIGNATURE-PRIVATE-KEY, encrypt INPUT-FILENAME and
the signature, and write the cyphertext to OUTPUT-FILENAME.
The encryption requires a shared secret that can be derived from a PASSPHRASE
or a PUBLIC-KEY."
  (let ((signature-filename (concatenate 'string input-filename ".sig"))
        (archive-filename (get-temporary-filename ".tar")))
    (unwind-protect
         (progn
           (sign-file input-filename signature-private-key signature-filename)

           (with-open-archive (archive archive-filename :direction :output)
             (write-entry-to-archive archive (create-entry-from-pathname archive input-filename))
             (write-entry-to-archive archive (create-entry-from-pathname archive signature-filename))
             (finalize-archive archive))

           (cond (passphrase
                  (encrypt-file archive-filename output-filename :passphrase passphrase))

                 (public-key
                  (encrypt-file archive-filename output-filename :public-key public-key))

                 (t
                  (error "Passphrase or encryption public key must be specified."))))

      (when (file-exists-p signature-filename)
        (delete-file signature-filename))
      (when (file-exists-p archive-filename)
        (delete-file archive-filename)))))

(defun decrypt-and-verify-file-signature (input-filename output-filename signature-public-key &key passphrase private-key)
  "Decrypt INPUT-FILENAME (which should have been created with the
SIGN-AND-ENCRYPT-FILE function), verify that it has a valid signature, and
write the cleartext to OUTPUT-FILENAME.
If SIGNATURE-PUBLIC-KEY is not NIL, also verify that the signature was done
using the matching private key.
The decryption requires a shared secret that can be derived from a PASSPHRASE
or a PUBLIC-KEY."
  (let ((signature-filename (get-temporary-filename ".sig"))
        (archive-filename (get-temporary-filename ".tar")))
    (unwind-protect
         (progn
           (cond
             (passphrase
              (decrypt-file input-filename archive-filename :passphrase passphrase))

             (private-key
              (decrypt-file input-filename archive-filename :private-key private-key))

             (t
              (error "Passphrase or private key must be specified.")))

           (let (entries)
             (with-open-archive (archive archive-filename :direction :input)
               (do-archive-entries (entry archive)
                 (when (entry-regular-file-p entry)
                   (push (name entry) entries))))

             (unless (= (length entries) 2)
               (error "Unknown decrypted file format."))

             (let ((data-name (first entries))
                   (signature-name (second entries)))
               ;; The name of the signature file "foo.sig" is always longer
               ;; than the name of the data file "foo".
               (when (> (length data-name) (length signature-name))
                 (rotatef data-name signature-name))

               (with-open-archive (archive archive-filename :direction :input)
                 (do-archive-entries (entry archive)
                   (when (entry-regular-file-p entry)
                     (cond ((string= (name entry) data-name)
                            (write-file output-filename (entry-stream entry)))

                           ((string= (name entry) signature-name)
                            (write-file signature-filename (entry-stream entry)))))))))

           (let ((signature (read-signature signature-filename)))
             (verify-file-signature output-filename signature signature-public-key)))

      (when (file-exists-p signature-filename)
        (delete-file signature-filename))
      (when (file-exists-p archive-filename)
        (delete-file archive-filename)))))

(defmacro with-raw-io ((&key (vmin 1) (vtime 0)) &body body)
  "Execute BODY without echoing input IO actions."
  (declare (ignorable vmin vtime))

  #+(and sbcl unix)
  (let ((old (gensym))
        (new (gensym))
        (bits (gensym)))
    `(let ((,old (sb-posix:tcgetattr 0))
           (,new (sb-posix:tcgetattr 0))
           (,bits (logior sb-posix:icanon sb-posix:echo sb-posix:echoe
                          sb-posix:echok sb-posix:echonl)))
       (unwind-protect
            (progn
              (setf (sb-posix:termios-lflag ,new)
                    (logandc2 (sb-posix:termios-lflag ,old) ,bits)
                    (aref (sb-posix:termios-cc ,new) sb-posix:vmin) ,vmin
                    (aref (sb-posix:termios-cc ,new) sb-posix:vtime) ,vtime)
              (sb-posix:tcsetattr 0 sb-posix:tcsadrain ,new)
              ,@body)
         (sb-posix:tcsetattr 0 sb-posix:tcsadrain ,old))))

  #-(and sbcl unix)
  `(progn
     (format *error-output* "Warning: could not disable the terminal echo.~%")
     ,@body))

(defun get-passphrase (verify-passphrase)
  "Get a passphrase from the user."
  (write-string "Enter the passphrase: ")
  (force-output)
  (let ((passphrase (with-raw-io ()
                      (read-line))))
    (terpri)
    (when verify-passphrase
      (write-string "Enter the passphrase again: ")
      (force-output)
      (let ((passphrase-check (with-raw-io ()
                                (read-line))))
        (terpri)
        (unless (string= passphrase passphrase-check)
          (error "Passphrases don't match."))))
    passphrase))

(defun main (&optional (args (uiop:command-line-arguments)))
  "Entry point for standalone program."
  (push "iescrypt" args) ; TODO: remove that
  (handler-case
      ;; Check arguments
      (cond
        ((and (<= 4 (length args) 5)
              (string= (elt args 1) "penc"))
         ;; Encrypt a file using a passphrase
         (let* ((input-filename (elt args 2))
                (output-filename (elt args 3))
                (passphrase-filename (if (= (length args) 5)
                                         (elt args 4)
                                         nil))
                (passphrase (if passphrase-filename
                                (read-passphrase passphrase-filename)
                                (get-passphrase t))))
           (encrypt-file input-filename output-filename :passphrase passphrase)))

        ((and (<= 4 (length args) 5)
              (string= (elt args 1) "pdec"))
         ;; Decrypt a file using a passphrase
         (let* ((input-filename (elt args 2))
                (output-filename (elt args 3))
                (passphrase-filename (if (= (length args) 5)
                                         (elt args 4)
                                         nil))
                (passphrase (if passphrase-filename
                                (read-passphrase passphrase-filename)
                                (get-passphrase nil))))
           (decrypt-file input-filename output-filename :passphrase passphrase)))

        ((and (= (length args) 3)
              (string= (elt args 1) "gen-enc"))
         ;; Generate an encryption key pair
         (let ((key-filename (elt args 2)))
           (make-encryption-key-pair key-filename)))

        ((and (= (length args) 3)
              (string= (elt args 1) "gen-sig"))
         ;; Generate a signature key pair
         (let ((key-filename (elt args 2)))
           (make-signing-key-pair key-filename)))

        ((and (= (length args) 5)
              (string= (elt args 1) "enc"))
         ;; Encrypt a file using a public key
         (let* ((input-filename (elt args 2))
                (output-filename (elt args 3))
                (key-filename (elt args 4))
                (public-key (read-public-key key-filename)))
           (encrypt-file input-filename output-filename :public-key public-key)))

        ((and (= (length args) 5)
              (string= (elt args 1) "dec"))
         ;; Decrypt a file using a private key
         (let* ((input-filename (elt args 2))
                (output-filename (elt args 3))
                (key-filename (elt args 4))
                (private-key (read-private-key key-filename)))
           (decrypt-file input-filename output-filename :private-key private-key)))

        ((and (= (length args) 5)
              (string= (elt args 1) "sign"))
         ;; Sign a file
         (let* ((input-filename (elt args 2))
                (signature-filename (elt args 3))
                (key-filename (elt args 4))
                (private-key (read-private-key key-filename)))
           (sign-file input-filename private-key signature-filename)))

        ((and (<= 4 (length args) 5)
              (string= (elt args 1) "verif"))
         ;; Verify a signature
         (let* ((input-filename (elt args 2))
                (signature (read-signature (elt args 3)))
                (public-key (when (= (length args) 5)
                              (read-public-key (elt args 4))))
                (signature-public-key (verify-file-signature input-filename signature public-key)))
           (when signature-public-key
             (let ((signer (byte-array-to-hex-string signature-public-key)))
               (format t "Valid signature from ~a.~%" signer)))))

        ((and (= (length args) 6)
              (string= (elt args 1) "sign-enc"))
         ;; Sign and encrypt a file using a public key
         (let* ((input-filename (elt args 2))
                (output-filename (elt args 3))
                (signature-private-key (read-private-key (elt args 4)))
                (encryption-public-key (read-public-key (elt args 5))))
           (sign-and-encrypt-file input-filename output-filename signature-private-key :public-key encryption-public-key)))

        ((and (<= 5 (length args) 6)
              (string= (elt args 1) "sign-penc"))
         ;; Sign and encrypt a file using a passphrase
         (let* ((input-filename (elt args 2))
                (output-filename (elt args 3))
                (sig-key-filename (read-private-key (elt args 4)))
                (passphrase (if (= (length args) 6)
                                (read-passphrase (elt args 5))
                                (get-passphrase t))))
           (sign-and-encrypt-file input-filename output-filename sig-key-filename :passphrase passphrase)))

        ((and (<= 5 (length args) 6)
              (string= (elt args 1) "dec-verif"))
         ;; Decrypt and verify a file
         (let* ((input-filename (elt args 2))
                (output-filename (elt args 3))
                (encryption-private-key (read-private-key (elt args 4)))
                (public-key (when (= (length args) 6)
                              (read-public-key (elt args 5))))
                (signature-public-key (decrypt-and-verify-file-signature input-filename output-filename public-key :private-key encryption-private-key)))
           (when signature-public-key
             (let ((signer (byte-array-to-hex-string signature-public-key)))
               (format t "Valid signature from ~a.~%" signer)))))

        ((and (<= 4 (length args) 6)
              (string= (elt args 1) "pdec-verif"))
         ;; Decrypt and verify a file
         (let* ((input-filename (elt args 2))
                (output-filename (elt args 3))
                (passphrase (if (>= (length args) 5)
                                (read-passphrase (elt args 4))
                                (get-passphrase nil)))
                (public-key (when (= (length args) 6)
                              (read-public-key (elt args 5))))
                (signature-public-key (decrypt-and-verify-file-signature input-filename output-filename public-key :passphrase passphrase)))
           (when signature-public-key
             (let ((signer (byte-array-to-hex-string signature-public-key)))
               (format t "Valid signature from ~a.~%" signer)))))

        (t
         (error (format nil "Bad command or arguments.

Usage: iescrypt <command> <arguments>

Commands:

  penc <input file> <output file> [passphrase file]

    Encrypt a file using a passphrase.


  pdec <input file> <output file> [passphrase file]

    Decrypt a file using a passphrase.


  gen-enc <file name>

     Generate a key pair for encryption. The private key is written
     in 'file name' and the public key is written in 'file name.pub'.


  gen-sig <file name>

     Generate a key pair for signature. The private key is written
     in 'file name' and the public key is written in 'file name.pub'.


  enc <input file> <output file> <public key file>

    Encrypt a file for the owner of a public key.


  dec <input file> <output file> <private key file>

    Decrypt a file that was encrypted with a public key using
    the matching private key.


  sign <input file> <signature file> <private key file>

    Sign a file.


  verif <input-file> <signature-file> [public key file]

    Verify a signature of a file.
    If a signature public key is specified, also verify that the signature
    was done with the matching private key.


  sign-enc <input file> <output file> <signature private key file>
           <encryption public key file>

  sign-penc <input file> <output file> <signature private key file>
            [passphrase file]

    Sign and encrypt a file.


  dec-verif <input file> <output file> <encryption private key file>
            [signature public key file]

  pdec-verif <input file> <output file>
             [passphrase file [signature public key file]]

    Decrypt and verify a file.
    If a signature public key is specified, also verify that the signature
    was done with the matching private key.~%"))))

    (t (err) (format *error-output* "Error: ~a~%" err))))
