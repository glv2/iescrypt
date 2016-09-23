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
                             :element-type '(unsigned-byte 8)
                             :if-exists :supersede)
    (with-open-file (file-pkey (concatenate 'string filename ".pub")
                               :direction :output
                               :element-type '(unsigned-byte 8)
                               :if-exists :supersede)
      (multiple-value-bind (skey pkey) (generate-key-pair :curve25519)
        (write-sequence (curve25519-key-x skey) file-skey)
        (write-sequence (curve25519-key-y pkey) file-pkey)))))

(defun make-signing-key-pair (filename)
  (with-open-file (file-skey filename
                             :direction :output
                             :element-type '(unsigned-byte 8)
                             :if-exists :supersede)
    (with-open-file (file-pkey (concatenate 'string filename ".pub")
                               :direction :output
                               :element-type '(unsigned-byte 8)
                               :if-exists :supersede)
      (multiple-value-bind (skey pkey) (generate-key-pair :ed25519)
        (write-sequence (ed25519-key-x skey) file-skey)
        (write-sequence (ed25519-key-y pkey) file-pkey)))))

(defun encrypt-file (input-filename output-filename &key passphrase public-key)
  (with-open-file (input input-filename
                         :direction :input
                         :element-type '(unsigned-byte 8))
    (with-open-file (output output-filename
                            :direction :output
                            :element-type '(unsigned-byte 8)
                            :if-exists :supersede)
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
                            :element-type '(unsigned-byte 8)
                            :if-exists :supersede)
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

(defun sign-file (input-filename signature-filename private-key-filename)
  (let* ((sk (read-private-key private-key-filename))
         (private-key (make-private-key :ed25519 :x sk))
         (hash (digest-file +digest+ input-filename))
         (signature (sign-message private-key hash)))
    (with-open-file (file-sig signature-filename
                              :direction :output
                              :element-type '(unsigned-byte 8)
                              :if-exists :supersede)
      (write-sequence signature file-sig))))

(defun verify-file-signature (input-filename signature-file public-key-filename)
  (let* ((pk (read-public-key public-key-filename))
         (public-key (make-public-key :ed25519 :y pk))
         (hash (digest-file +digest+ input-filename))
         (signature (read-file signature-file)))
    (unless (= (length signature) 64)
      (error "Bad signature length."))
    (unless (verify-signature public-key hash signature)
      (error "Bad signature."))
    t))

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
        ((and (or (= (length argv) 4) (= (length argv) 5)) (string= (elt argv 1) "pe"))
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

        ((and (or (= (length argv) 4) (= (length argv) 5)) (string= (elt argv 1) "pd"))
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

        ((and (= (length argv) 5) (string= (elt argv 1) "e"))
         ;; Encrypt a file using a public key
         (let* ((input-filename (elt argv 2))
                (output-filename (elt argv 3))
                (key-filename (elt argv 4))
                (public-key (read-public-key key-filename)))
           (encrypt-file input-filename output-filename :public-key public-key)))

        ((and (= (length argv) 5) (string= (elt argv 1) "d"))
         ;; Decrypt a file using a private key
         (let* ((input-filename (elt argv 2))
                (output-filename (elt argv 3))
                (key-filename (elt argv 4))
                (private-key (read-private-key key-filename)))
           (decrypt-file input-filename output-filename :private-key private-key)))

        ((and (= (length argv) 5) (string= (elt argv 1) "s"))
         ;; Sign a file
         (let ((input-filename (elt argv 2))
               (signature-filename (elt argv 3))
               (key-filename (elt argv 4)))
           (sign-file input-filename signature-filename key-filename)))

        ((and (= (length argv) 5) (string= (elt argv 1) "v"))
         ;; Verify a signature
         (let ((input-filename (elt argv 2))
               (signature-filename (elt argv 3))
               (key-filename (elt argv 4)))
           (if (verify-file-signature input-filename signature-filename key-filename)
               (format t "Signature OK.~%"))))

        ((and (= (length argv) 3) (string= (elt argv 1) "ge"))
         ;; Generate an encryption key pair
         (let ((key-filename (elt argv 2)))
           (make-encryption-key-pair key-filename)))

        ((and (= (length argv) 3) (string= (elt argv 1) "gs"))
         ;; Generate a signature key pair
         (let ((key-filename (elt argv 2)))
           (make-signing-key-pair key-filename)))

        (t
         (error (format nil "Usage:

  clcrypt <command> <arguments>

  Commands:

    pe <input file> <output file> [passphrase file]
      Encrypt a file using a passphrase.

    pd <input file> <output file> [passphrase file]
      Decrypt a file using a passphrase.

    e <input file> <output file> <public key file>
      Encrypt a file for the owner of a public key.

    d <input file> <output file> <private key file>
      Decrypt a file that was encrypted with a public key using
      the matching private key.

    s <input file> <signature file> <private key file>
      Create a signature of a file.

    v <input-file> <signature-file> <public key file>
      Verify a signature of a file.

    ge <file name>
       Generate a key pair for encryption. The private key is written
       in 'file name' and the public key is written in 'file name.pub'.

    gs <file name>
       Generate a key pair for signature. The private key is written
       in 'file name' and the public key is written in 'file name.pub'.~%"))))

    (t (err) (format *error-output* "Error: ~a~%" err))))
