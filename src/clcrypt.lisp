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


(defconstant +cipher+ :threefish512)
(defconstant +digest+ :skein512)
(defconstant +cipher-block-length+ (block-length +cipher+)) ; 64 bytes
(defconstant +tweak-length+ 16)
(defconstant +salt-length+ 16)
(defconstant +iterations+ 1000)
(defconstant +mac-length+ (digest-length +digest+)) ; 64 bytes
(defconstant +buffer-size+ 1048576) ; 1 MiB, 16384 cipher blocks of 64 bytes


(defun passphrase-to-key (passphrase salt)
  "Generate a key from a PASSPHRASE and a SALT."
  (let ((passdata (string-to-octets passphrase :encoding :utf-8)))

    (pbkdf2-hash-password passdata
                          :digest +digest+
                          :salt salt
                          :iterations +iterations+)))

(defun encrypt-file (input-filename output-filename passphrase)
  "Read data from INPUT-FILENAME, encrypt it using PASSPHRASE and write the
ciphertext to OUTPUT-FILENAME."
  (with-open-file (input-file input-filename
                              :element-type '(unsigned-byte 8))
    (with-open-file (output-file output-filename
                                 :element-type'(unsigned-byte 8)
                                 :direction :output
                                 :if-exists :supersede)
      (let* ((prng (make-prng :fortuna :seed :random))
             (salt (random-data +salt-length+ prng))
             (tweak (random-data +tweak-length+ prng))
             (iv (random-data +cipher-block-length+ prng))
             (key (passphrase-to-key passphrase salt))
             (cipher (make-cipher +cipher+
                                  :key key
                                  :tweak tweak
                                  :mode :ctr
                                  :initialization-vector iv))
             (mac (make-skein-mac key
                                  :block-length +cipher-block-length+
                                  :digest-length +mac-length+)))

        ;; Write header
        (update-skein-mac mac tweak)
        (update-skein-mac mac iv)
        (write-sequence salt output-file)
        (write-sequence tweak output-file)
        (write-sequence iv output-file)
        (write-sequence (skein-mac-digest mac) output-file)

        (reinitialize-instance mac :key key)
        (do ((buffer (make-array +buffer-size+ :element-type '(unsigned-byte 8)))
             (text-length 0)
             (first-block t)
             (end-of-file nil))
            (end-of-file)

          ;; Read plaintext
          (setf text-length (read-sequence buffer input-file))
          (when (< text-length +buffer-size+)
            (setf end-of-file t))

          (when (or (plusp text-length) first-block)
            (setf first-block nil)

            ;; Encrypt plaintext
            (encrypt-in-place cipher buffer :end text-length)
            (update-skein-mac mac buffer :end text-length)

            ;; Write ciphertext
            (write-sequence buffer output-file :end text-length)))

        ;; Write mac
        (write-sequence (skein-mac-digest mac) output-file)

        (file-length output-file)))))

(defun decrypt-file (input-filename output-filename passphrase)
  "Read data from INPUT-FILENAME, decrypt it using PASSPHRASE and write the
plaintext to OUTPUT-FILENAME."
  (with-open-file (input-file input-filename
                              :element-type '(unsigned-byte 8))
    (with-open-file (output-file output-filename
                                 :element-type'(unsigned-byte 8)
                                 :direction :output
                                 :if-exists :supersede)
      (let ((salt (make-array +salt-length+ :element-type '(unsigned-byte 8)))
            (tweak (make-array +tweak-length+ :element-type '(unsigned-byte 8)))
            (iv (make-array +cipher-block-length+ :element-type '(unsigned-byte 8)))
            (old-mac (make-array +mac-length+ :element-type '(unsigned-byte 8)))
            key cipher mac)

        ;; Read header
        (unless (= (read-sequence salt input-file) +salt-length+)
          (error "Could not read the salt from the input stream."))
        (unless (= (read-sequence tweak input-file) +tweak-length+)
          (error "Could not read the tweak from the input stream."))
        (unless (= (read-sequence iv input-file) +cipher-block-length+)
          (error "Could not read the initialization vector from the input stream."))
        (unless (= (read-sequence old-mac input-file) +mac-length+)
          (error "Could not read the mac from the input stream."))

        ;; Generate key
        (setf key (passphrase-to-key passphrase salt))
        (setf cipher (make-cipher +cipher+
                                  :key key
                                  :tweak tweak
                                  :mode :ctr
                                  :initialization-vector iv))

        ;; Check header mac
        (setf mac (make-skein-mac key
                                  :block-length +cipher-block-length+
                                  :digest-length +mac-length+))
        (update-skein-mac mac tweak)
        (update-skein-mac mac iv)
        (unless (equalp old-mac (skein-mac-digest mac))
          (error "Decryption failed."))

        (reinitialize-instance mac :key key)
        (do ((buffer (make-array (+ +buffer-size+ +mac-length+)
                                 :element-type '(unsigned-byte 8)))
             (text-length 0)
             (first-block t)
             (end-of-file nil))
            (end-of-file)

          ;; Read ciphertext and mac
          (setf text-length (read-sequence buffer input-file :start text-length))
          (when (< text-length (+ +buffer-size+ +mac-length+))
            (setf end-of-file t))

          (when (or (plusp text-length) first-block)
            (setf first-block nil)

            ;; Check that we have enough data for the mac
            (when (< text-length +mac-length+)
              (error "Could not read the mac from the input stream."))
            (decf text-length +mac-length+)

            ;; Keep the last +mac-length+ bytes (it might be the mac)
            (replace old-mac buffer :end1 +mac-length+ :start2 text-length)

            ;; Decrypt ciphertext
            (update-skein-mac mac buffer :end text-length)
            (decrypt-in-place cipher buffer :end text-length)

            ;; Write plaintext
            (write-sequence buffer output-file :end text-length)

            ;; Put remaining data at the beginning of buffer
            (replace buffer old-mac)
            (setf text-length +mac-length+)))

        ;; Chech mac
        (unless (equalp old-mac (skein-mac-digest mac))
          (error "Data corrupted."))

        (file-length output-file)))))

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
