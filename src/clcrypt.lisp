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


(defconstant +cipher+ :threefish512)
(defconstant +digest+ :skein512)


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
      (error "Too short for a public key"))
    public-key))

(defun read-private-key (filename)
  (let ((private-key (read-file filename)))
    (unless (= (length private-key) 32)
      (error "Too short for a private key"))
    private-key))

(defun make-key-pair (filename)
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
                                 output))
            (public-key
             (ies-encrypt-stream (make-public-key :curve25519 :y public-key)
                                 +cipher+
                                 +digest+
                                 input
                                 output))
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
                                 output))
            (private-key
             (ies-decrypt-stream (make-private-key :curve25519 :x private-key)
                                 +cipher+
                                 +digest+
                                 input
                                 output))
            (t
             (error "Passphrase or private key must be specified."))))))

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

(defun main (argv)
  "Entry point for standalone program."
  (handler-case
      (let (symmetric-p decrypt-p input-filename output-filename passphrase passphrase-check key key-filename)

        ;; Check arguments
        (cond ((and (= (length argv) 6) (string= (elt argv 1) "-s") (string= (elt argv 2) "-d"))
               (setf symmetric-p t
                     decrypt-p t
                     input-filename (elt argv 3)
                     output-filename (elt argv 4)
                     key-filename (elt argv 5)))

              ((and (= (length argv) 6) (string= (elt argv 1) "-p") (string= (elt argv 2) "-d"))
               (setf decrypt-p t
                     input-filename (elt argv 3)
                     output-filename (elt argv 4)
                     key-filename (elt argv 5)))

              ((and (= (length argv) 5) (string= (elt argv 1) "-s") (string= (elt argv 2) "-d"))
               (setf symmetric-p t
                     decrypt-p t
                     input-filename (elt argv 3)
                     output-filename (elt argv 4)))

              ((and (= (length argv) 5) (string= (elt argv 1) "-s") (string/= (elt argv 2) "-d"))
               (setf symmetric-p t
                     input-filename (elt argv 2)
                     output-filename (elt argv 3)
                     key-filename (elt argv 4)))

              ((and (= (length argv) 5) (string= (elt argv 1) "-p"))
               (setf input-filename (elt argv 2)
                     output-filename (elt argv 3)
                     key-filename (elt argv 4)))

              ((and (= (length argv) 4) (string= (elt argv 1) "-s"))
               (setf symmetric-p t
                     input-filename (elt argv 2)
                     output-filename (elt argv 3)))

              ((and (= (length argv) 3) (string= (elt argv 1) "-g"))
               (setf key-filename (elt argv 2)))

              (t
               (error (format nil "Usage:~%
  Symmetric mode:  clcrypt -s [-d] <input file> <output file> [passphrase file]~%
  Public key mode: clcrypt -p [-d] <input-file> <output file> <key file>~%
  Key generation:  clcrypt -g <output file>~%~%"))))

        (cond (symmetric-p
               ;; Get passphrase
               (if key-filename
                   (setf passphrase (read-passphrase key-filename))
                   (progn
                     (format *standard-output* "Enter the passphrase: ")
                     (force-output *standard-output*)
                     (setf passphrase (with-raw-io ()
                                        (read-line *standard-input*)))
                     (format *standard-output* "~%")
                     (unless (or decrypt-p key-filename)
                       (format *standard-output* "Enter the passphrase again: ")
                       (force-output *standard-output*)
                       (setf passphrase-check (with-raw-io ()
                                                (read-line *standard-input*)))
                       (format *standard-output* "~%")
                       (unless (equal passphrase passphrase-check)
                         (error "Passphrases don't match.")))))

               ;; Encrypt or decrypt
               (if decrypt-p
                   (decrypt-file input-filename output-filename :passphrase passphrase)
                   (encrypt-file input-filename output-filename :passphrase passphrase)))

              (input-filename
               ;; Get public or private key
               (setf key (read-file key-filename))

               ;; Encrypt or decrypt
               (if decrypt-p
                   (decrypt-file input-filename output-filename :private-key key)
                   (encrypt-file input-filename output-filename :public-key key)))

              (t
               (make-key-pair key-filename))))

    (t (err) (progn
               (format *error-output* "~%Error: ~a~%" err)
               (return-from main -1))))
  0)
