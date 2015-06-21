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


This program encrypts and decrypts files.

Cipher: threefish512 (counter mode)
Key derivation: pbkdf2 (1000 iterations of skein512)
Message authentication code: skein-mac (512/512)

Encrypted file format:
| salt (16 B) | tweak (16 B) | iv (64 B) | mac (64 B) | block | ... | block |

Format of a block:
| cipertext (1 MiB) | mac (64 B) |

|#


(defpackage clcrypt
  (:use cl)
  (:import-from ironclad
                block-length
                digest-length
                pbkdf2-hash-password
                make-prng
                random-data
                make-cipher
                encrypt-in-place
                decrypt-in-place
                make-skein-mac
                update-skein-mac
                skein-mac-digest)
  (:import-from babel
                string-to-octets)
  (:export encrypt-file
           decrypt-file
           main))

(in-package clcrypt)


(defparameter *cipher* :threefish512)
(defparameter *digest* :skein512)
(defparameter *block-length* (block-length *cipher*))
(defparameter *tweak-length* 16)
(defparameter *salt-length* 16)
(defparameter *iterations* 1000)
(defparameter *mac-length* (digest-length *digest*))
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
             (salt (random-data *salt-length* prng))
             (tweak (random-data *tweak-length* prng))
             (iv (random-data *block-length* prng))
             (key (passphrase-to-key passphrase salt))
             (cipher (make-cipher *cipher*
                                  :key key
                                  :tweak tweak
                                  :mode :ctr
                                  :initialization-vector iv))
             (mac (make-skein-mac key
                                  :block-length *block-length*
                                  :digest-length *mac-length*)))

        ;; Write header
        (update-skein-mac mac tweak)
        (update-skein-mac mac iv)
        (write-sequence salt output-file)
        (write-sequence tweak output-file)
        (write-sequence iv output-file)
        (write-sequence (skein-mac-digest mac) output-file)

        (reinitialize-instance mac :key key)
        (do ((buffer (make-array *buffer-size* :element-type '(unsigned-byte 8)))
             (text-length 0)
             (end-of-file nil)
             (buffers-by-block (/ *block-size* *buffer-size*))
             (i 0))
            (end-of-file)

          ;; Read plaintext
          (setf text-length (read-sequence buffer input-file))
          (when (zerop text-length)
            (return))
          (when (< text-length *buffer-size*)
            (setf end-of-file t))

          ;; Encrypt plaintext
          (encrypt-in-place cipher buffer :end text-length)
          (update-skein-mac mac buffer :end text-length)

          ;; Write ciphertext
          (write-sequence buffer output-file :end text-length)
          (incf i)

          (when (or (= i buffers-by-block)
                    end-of-file)
            ;; Write mac for current block
            (write-sequence (skein-mac-digest mac) output-file)
            (reinitialize-instance mac :key key)
            (setf i 0)))

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
      (let ((salt (make-array *salt-length* :element-type '(unsigned-byte 8)))
            (tweak (make-array *tweak-length* :element-type '(unsigned-byte 8)))
            (iv (make-array *block-length* :element-type '(unsigned-byte 8)))
            (old-mac (make-array *mac-length* :element-type '(unsigned-byte 8)))
            key cipher mac)

        ;; Read header
        (unless (= (read-sequence salt input-file) *salt-length*)
          (error "Could not read the salt from the input stream."))
        (unless (= (read-sequence tweak input-file) *tweak-length*)
          (error "Could not read the tweak from the input stream."))
        (unless (= (read-sequence iv input-file) *block-length*)
          (error "Could not read the initialization vector from the input stream."))
        (unless (= (read-sequence old-mac input-file) *mac-length*)
          (error "Could not read the mac from the input stream."))

        ;; Generate key
        (setf key (passphrase-to-key passphrase salt))
        (setf cipher (make-cipher *cipher*
                                  :key key
                                  :tweak tweak
                                  :mode :ctr
                                  :initialization-vector iv))

        ;; Check header mac
        (setf mac (make-skein-mac key
                                  :block-length *block-length*
                                  :digest-length *mac-length*))
        (update-skein-mac mac tweak)
        (update-skein-mac mac iv)
        (unless (equalp old-mac (skein-mac-digest mac))
          (error "Decryption failed."))

        (reinitialize-instance mac :key key)
        (do ((buffer (make-array (+ *buffer-size* *mac-length*)
                                 :element-type '(unsigned-byte 8)))
             (read-length 0)
             (text-length 0)
             (end-of-file nil)
             (buffers-by-block (/ *block-size* *buffer-size*))
             (i 0))
            (end-of-file)

          ;; Read ciphertext and mac
          (setf read-length (read-sequence buffer input-file :start text-length))
          (decf read-length text-length)
          (incf text-length read-length)
          (when (zerop text-length)
            (return))
          (when (< text-length (+ *buffer-size* *mac-length*))
            (setf end-of-file t))

          ;; Check that we have enough data for the mac
          (when (< text-length *mac-length*)
            (error "Could not read the mac from the input stream."))
          (decf text-length *mac-length*)

          ;; Decrypt ciphertext
          (update-skein-mac mac buffer :end text-length)
          (decrypt-in-place cipher buffer :end text-length)

          ;; Write plaintext
          (write-sequence buffer output-file :end text-length)
          (incf i)

          (if (or (= i buffers-by-block)
                  end-of-file)
              (progn
                ;; Check mac for current block
                (unless (equalp (subseq buffer text-length (+ text-length *mac-length*))
                                (skein-mac-digest mac))
                  (error "Data corrupted."))
                (setf text-length 0)
                (reinitialize-instance mac :key key)
                (setf i 0))
              (progn
                (replace buffer buffer :end1 *mac-length* :start2 text-length)
                (setf text-length *mac-length*))))

        (file-length output-file)))))

(defmacro with-raw-io ((&key (vmin 1) (vtime 0)) &body body)
  "Execute BODY without echoing input IO actions."
  (declare (ignorable vmin vtime))

  #+sbcl
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

  #-sbcl
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
