;;;; -*- mode: lisp; indent-tabs-mode: nil -*-

#|

Copyright 2015-2016 Guillaume LE VAILLANT

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


(in-package clcrypt)


(defconstant +cipher+ :chacha)
(defconstant +digest+ :blake2)
(defconstant +kdf-iterations+ 10000)
(setf *random-state* (make-random-state t))


(defun get-temporary-filename (&optional (suffix ""))
  (let* ((id (random 1000000000))
         (filename (format nil "tmp-~d~a" id suffix)))
    (if (file-exists-p filename)
        (get-temporary-filename)
        filename)))

(defun read-file (filename)
  (with-open-file (file filename
                        :direction :input
                        :element-type '(unsigned-byte 8))
    (let* ((length (file-length file))
           (buffer (make-array length :element-type '(unsigned-byte 8))))
      (unless (= (read-sequence buffer file) length)
        (error "Could not read complete file."))
      buffer)))

(defun read-passphrase (filename)
  (with-open-file (file filename
                        :direction :input)
    (let ((passphrase (read-line file nil nil)))
      (unless passphrase
        (error "Could not read passphrase from file."))
      passphrase)))

(defun read-public-key (filename)
  (let ((public-key (read-file filename)))
    (unless (= (length public-key) 32)
      (error "Public key too short."))
    public-key))

(defun read-private-key (filename)
  (let ((private-key (read-file filename)))
    (unless (= (length private-key) 32)
      (error "Private key too short."))
    private-key))

(defun make-encryption-key-pair (filename)
  (with-open-file (file-skey filename
                             :direction :output
                             :element-type '(unsigned-byte 8))
    (with-open-file (file-pkey (concatenate 'string filename ".pub")
                               :direction :output
                               :element-type '(unsigned-byte 8))
      (multiple-value-bind (skey pkey) (generate-key-pair :curve25519)
        (write-sequence (curve25519-key-x skey) file-skey)
        (write-sequence (curve25519-key-y pkey) file-pkey)))))

(defun make-signing-key-pair (filename)
  (with-open-file (file-skey filename
                             :direction :output
                             :element-type '(unsigned-byte 8))
    (with-open-file (file-pkey (concatenate 'string filename ".pub")
                               :direction :output
                               :element-type '(unsigned-byte 8))
      (multiple-value-bind (skey pkey) (generate-key-pair :ed25519)
        (write-sequence (ed25519-key-x skey) file-skey)
        (write-sequence (ed25519-key-y pkey) file-pkey)))))

(defun encrypt-file (input-filename output-filename &key passphrase public-key)
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
  (let* ((privkey (make-private-key :ed25519 :x private-key))
         (public-key (ed25519-key-y privkey))
         (hash (digest-file +digest+ input-filename))
         (signature (concatenate '(simple-array (unsigned-byte 8) (*))
                                 public-key
                                 (sign-message privkey hash))))
    (when signature-filename
      (with-open-file (signature-file signature-filename
                                      :direction :output
                                      :element-type '(unsigned-byte 8))
        (write-sequence signature signature-file)))
    signature))

(defun verify-file-signature (input-filename signature &optional public-key)
  (unless (= (length signature) 96)
    (error "Bad signature length."))
  (let* ((signature-public-key (subseq signature 0 32))
         (pubkey (make-public-key :ed25519 :y signature-public-key))
         (signature (subseq signature 32 96))
         (hash (digest-file +digest+ input-filename)))
    (if (and (or (null public-key)
                 (equalp signature-public-key public-key))
             (verify-signature pubkey hash signature))
        signature-public-key
        (error "Bad signature."))))

(defun sign-and-encrypt-file (input-filename output-filename signature-private-key &key passphrase public-key)
  (let ((signature-filename (concatenate 'string input-filename ".sig"))
        (archive-filename (get-temporary-filename ".tar")))
    (unwind-protect
         (progn
           (sign-file input-filename signature-private-key signature-filename)
           (with-open-archive (archive archive-filename :direction :output)
             (flet ((make-entry (archive filename)
                      (let ((entry (create-entry-from-pathname archive filename)))
                        (write-entry-to-archive archive entry))))
               (make-entry archive input-filename)
               (make-entry archive signature-filename))
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
               ;; Name of signature file "foo.sig" is always longer than name of data file "foo"
               (when (> (length data-name) (length signature-name))
                 (rotatef data-name signature-name))
               (flet ((write-file (stream filename)
                        (with-open-file (output filename
                                                :direction :output
                                                :element-type '(unsigned-byte 8))
                          (do* ((buffer (make-array 32768 :element-type '(unsigned-byte 8)))
                                (length (read-sequence buffer stream)
                                        (read-sequence buffer stream)))
                               ((zerop length))
                            (write-sequence buffer output :end length)))))
                 (with-open-archive (archive archive-filename :direction :input)
                   (do-archive-entries (entry archive)
                     (when (entry-regular-file-p entry)
                       (cond ((string= (name entry) data-name)
                              (write-file (entry-stream entry) output-filename))
                             ((string= (name entry) signature-name)
                              (write-file (entry-stream entry) signature-filename)))))))))
           (let ((signature (read-file signature-filename)))
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

(defun main (argv)
  "Entry point for standalone program."
  (handler-case
      ;; Check arguments
      (cond
        ((and (<= 4 (length argv) 5)
              (string= (elt argv 1) "penc"))
         ;; Encrypt a file using a passphrase
         (let* ((input-filename (elt argv 2))
                (output-filename (elt argv 3))
                (passphrase-filename (if (= (length argv) 5)
                                         (elt argv 4)
                                         nil))
                (passphrase (if passphrase-filename
                                (read-passphrase passphrase-filename)
                                (get-passphrase t))))
           (encrypt-file input-filename output-filename :passphrase passphrase)))

        ((and (<= 4 (length argv) 5)
              (string= (elt argv 1) "pdec"))
         ;; Decrypt a file using a passphrase
         (let* ((input-filename (elt argv 2))
                (output-filename (elt argv 3))
                (passphrase-filename (if (= (length argv) 5)
                                         (elt argv 4)
                                         nil))
                (passphrase (if passphrase-filename
                                (read-passphrase passphrase-filename)
                                (get-passphrase nil))))
           (decrypt-file input-filename output-filename :passphrase passphrase)))

        ((and (= (length argv) 3)
              (string= (elt argv 1) "gen-enc"))
         ;; Generate an encryption key pair
         (let ((key-filename (elt argv 2)))
           (make-encryption-key-pair key-filename)))

        ((and (= (length argv) 3)
              (string= (elt argv 1) "gen-sig"))
         ;; Generate a signature key pair
         (let ((key-filename (elt argv 2)))
           (make-signing-key-pair key-filename)))

        ((and (= (length argv) 5)
              (string= (elt argv 1) "enc"))
         ;; Encrypt a file using a public key
         (let* ((input-filename (elt argv 2))
                (output-filename (elt argv 3))
                (key-filename (elt argv 4))
                (public-key (read-public-key key-filename)))
           (encrypt-file input-filename output-filename :public-key public-key)))

        ((and (= (length argv) 5)
              (string= (elt argv 1) "dec"))
         ;; Decrypt a file using a private key
         (let* ((input-filename (elt argv 2))
                (output-filename (elt argv 3))
                (key-filename (elt argv 4))
                (private-key (read-private-key key-filename)))
           (decrypt-file input-filename output-filename :private-key private-key)))

        ((and (= (length argv) 5)
              (string= (elt argv 1) "sign"))
         ;; Sign a file
         (let* ((input-filename (elt argv 2))
                (signature-filename (elt argv 3))
                (key-filename (elt argv 4))
                (private-key (read-private-key key-filename)))
           (sign-file input-filename private-key signature-filename)))

        ((and (<= 4 (length argv) 5)
              (string= (elt argv 1) "verif"))
         ;; Verify a signature
         (let* ((input-filename (elt argv 2))
                (signature (read-file (elt argv 3)))
                (public-key (when (= (length argv) 5)
                              (read-public-key (elt argv 4))))
                (signature-public-key (verify-file-signature input-filename signature public-key)))
           (when signature-public-key
             (let ((signer (byte-array-to-hex-string signature-public-key)))
               (format t "Valid signature from ~a.~%" signer)))))

        ((and (= (length argv) 6)
              (string= (elt argv 1) "sign-enc"))
         ;; Sign and encrypt a file using a public key
         (let* ((input-filename (elt argv 2))
                (output-filename (elt argv 3))
                (signature-private-key (read-private-key (elt argv 4)))
                (encryption-public-key (read-public-key (elt argv 5))))
           (sign-and-encrypt-file input-filename output-filename signature-private-key :public-key encryption-public-key)))

        ((and (<= 5 (length argv) 6)
              (string= (elt argv 1) "sign-penc"))
         ;; Sign and encrypt a file using a passphrase
         (let* ((input-filename (elt argv 2))
                (output-filename (elt argv 3))
                (sig-key-filename (read-private-key (elt argv 4)))
                (passphrase (if (= (length argv) 6)
                                (read-passphrase (elt argv 5))
                                (get-passphrase t))))
           (sign-and-encrypt-file input-filename output-filename sig-key-filename :passphrase passphrase)))

        ((and (<= 5 (length argv) 6)
              (string= (elt argv 1) "dec-verif"))
         ;; Decrypt and verify a file
         (let* ((input-filename (elt argv 2))
                (output-filename (elt argv 3))
                (encryption-private-key (read-private-key (elt argv 4)))
                (public-key (when (= (length argv) 6)
                              (read-public-key (elt argv 5))))
                (signature-public-key (decrypt-and-verify-file-signature input-filename output-filename public-key :private-key encryption-private-key)))
           (when signature-public-key
             (let ((signer (byte-array-to-hex-string signature-public-key)))
               (format t "Valid signature from ~a.~%" signer)))))

        ((and (<= 4 (length argv) 6)
              (string= (elt argv 1) "pdec-verif"))
         ;; Decrypt and verify a file
         (let* ((input-filename (elt argv 2))
                (output-filename (elt argv 3))
                (passphrase (if (>= (length argv) 5)
                                (read-passphrase (elt argv 4))
                                (get-passphrase nil)))
                (public-key (when (= (length argv) 6)
                              (read-public-key (elt argv 5))))
                (signature-public-key (decrypt-and-verify-file-signature input-filename output-filename public-key :passphrase passphrase)))
           (when signature-public-key
             (let ((signer (byte-array-to-hex-string signature-public-key)))
               (format t "Valid signature from ~a.~%" signer)))))

        (t
         (error (format nil "Bad command or arguments.

Usage: clcrypt <command> <arguments>

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
    Create a signature of a file.

  verif <input-file> <signature-file> [public key file]
    Verify a signature of a file.

  sign-enc <input file> <output file> <signature private key file> <public key file>
  sign-penc <input file> <output file> <signature private key file> [passphrase file]
    Sign and encrypt a file.

  dec-verif <input file> <output file> <decryption private key file> [signature public key file]
  pdec-verif <input file> <output file> [passphrase file [signature public key file]]
    Decrypt and verify a file.~%"))))

    (t (err) (format *error-output* "Error: ~a~%" err))))
