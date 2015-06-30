;;;; -*- mode: lisp; indent-tabs-mode: nil -*-

#|

Copyright 2015 Guillaume LE VAILLANT

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


(defparameter *cipher* :threefish512)
(defparameter *digest* :skein512)
(defparameter *block-length* (block-length *cipher*)) ; 64 bytes
(defparameter *tweak-length* 16)
(defparameter *salt-length* 16)
(defparameter *iterations* 1000)
(defparameter *mac-length* (digest-length *digest*)) ; 64 bytes
(defparameter *header-length* (+ *salt-length* *tweak-length* *block-length* *mac-length*))
(defparameter *block-size* (* *block-length* 16384)) ; 1048576 bytes
(defparameter *buffer-size* (/ *block-size* 32)) ; 32768 bytes


(defun passphrase-to-key (passphrase salt)
  "Generate a key from a PASSPHRASE and a SALT."
  (let ((passdata (string-to-octets passphrase :encoding :utf-8)))

    (pbkdf2-hash-password passdata
                          :digest *digest*
                          :salt salt
                          :iterations *iterations*)))

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
      (let (decrypt-p input-filename output-filename passphrase passphrase-check)

        ;; Check arguments
        (cond ((and (= (length argv) 4) (string= (elt argv 1) "-d"))
               (setf decrypt-p t
                     input-filename (elt argv 2)
                     output-filename (elt argv 3)))
              ((= (length argv) 3)
               (setf decrypt-p nil
                     input-filename (elt argv 1)
                     output-filename (elt argv 2)))
              (t
               (error (format nil
                              "Usage: ~a [-d] <input file> <output file>"
                              (elt argv 0)))))

        ;; Get passphrase
        (format *standard-output* "Enter the passphrase: ")
        (force-output *standard-output*)
        (setf passphrase (with-raw-io ()
                           (read-line *standard-input*)))
        (format *standard-output* "~%")
        (unless decrypt-p
          (format *standard-output* "Enter the passphrase again: ")
          (force-output *standard-output*)
          (setf passphrase-check (with-raw-io ()
                                   (read-line *standard-input*)))
          (format *standard-output* "~%")
          (unless (equal passphrase passphrase-check)
            (error "Passphrases don't match.")))

        ;; Encrypt or decrypt
        (if decrypt-p
            (decrypt-file input-filename output-filename passphrase)
            (encrypt-file input-filename output-filename passphrase)))
    (t (err) (progn
               (format *error-output* "~%Error: ~a~%" err)
               (return-from main -1))))
  0)
