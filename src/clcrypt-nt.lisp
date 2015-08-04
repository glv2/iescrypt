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
        (do ((buffer (make-array +block-size+ :element-type '(unsigned-byte 8)))
             (text-length 0)
             (first-block t)
             (end-of-file nil))
            (end-of-file)

          ;; Read plaintext
          (setf text-length (read-sequence buffer input-file))
          (when (< text-length +block-size+)
            (setf end-of-file t))

          (when (or (plusp text-length) first-block)
            (setf first-block nil)

            ;; Encrypt plaintext
            (encrypt-in-place cipher buffer :end text-length)
            (update-skein-mac mac buffer :end text-length)

            ;; Write ciphertext and mac
            (write-sequence buffer output-file :end text-length)
            (write-sequence (skein-mac-digest mac) output-file)
            (reinitialize-instance mac :key key)))

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
        (do ((buffer (make-array (+ +block-size+ +mac-length+)
                                 :element-type '(unsigned-byte 8)))
             (text-length 0)
             (first-block t)
             (end-of-file nil))
            (end-of-file)

          ;; Read ciphertext and mac
          (setf text-length (read-sequence buffer input-file))
          (when (< text-length (+ +block-size+ +mac-length+))
            (setf end-of-file t))


          (when (or (plusp text-length) first-block)
            (setf first-block nil)

            ;; Check that we have enough data for the mac
            (when (< text-length +mac-length+)
              (error "Could not read the mac from the input stream."))
            (decf text-length +mac-length+)

            ;; Decrypt ciphertext
            (update-skein-mac mac buffer :end text-length)
            (unless (equalp (subseq buffer text-length (+ text-length +mac-length+))
                            (skein-mac-digest mac))
              (error "Data corrupted."))
            (decrypt-in-place cipher buffer :end text-length)

            ;; Write plaintext
            (write-sequence buffer output-file :end text-length)
            (reinitialize-instance mac :key key)))

        (file-length output-file)))))
