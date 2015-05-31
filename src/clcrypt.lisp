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
Key derivation: pbkdf2 (10000 iterations of skein512)
Message authentication code: skein-mac (512/512)

Encrypted file format (sizes are in bytes):
| salt (16) | mac (64) | tweak (16) | iv (64) | ciphertext |

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
                encrypt
                decrypt
                make-skein-mac
                update-skein-mac
                skein-mac-digest)
  (:import-from babel
                string-to-octets)
  (:import-from bordeaux-threads
                make-lock
                acquire-lock
                release-lock
                current-thread
                thread-name
                make-thread
                join-thread)
  (:export encrypt-file
           decrypt-file
           main))

(in-package clcrypt)


(defparameter *cipher* :threefish512)
(defparameter *digest* :skein512)
(defparameter *block-length* (block-length *cipher*))
(defparameter *tweak-length* 16)
(defparameter *salt-length* 16)
(defparameter *iterations* 10000)
(defparameter *mac-length* (digest-length *digest*))
(defparameter *header-length* (+ *salt-length* *mac-length* *tweak-length* *block-length*))
(defparameter *buffer-size* 32768)
(defparameter *block-batch* (max 1 (ceiling *buffer-size* *block-length*)))

(defparameter *key* nil)
(defparameter *tweak* nil)
(defparameter *iv* nil)
(defparameter *salt* nil)
(defparameter *mac* nil)
(defparameter *input-file* nil)
(defparameter *input-file-lock* nil)
(defparameter *output-file* nil)
(defparameter *output-file-lock* nil)
(defparameter *threads* nil)
(defparameter *boundaries* nil)


(defun max-number-of-threads ()
  #+linux
  (with-open-file (cpuinfo #p"/proc/cpuinfo")
    (do ((n 0)
         (line (read-line cpuinfo nil nil) (read-line cpuinfo nil nil)))
        ((null line) n)
      (when (string= (subseq line 0 (min (length line) 9)) "processor")
        (incf n))))

  #-linux
  1)

(defun passphrase-to-key (passphrase salt)
  "Generate a key from a PASSPHRASE and a SALT."
  (let ((passdata (string-to-octets passphrase :encoding :utf-8)))
    (pbkdf2-hash-password passdata
                          :digest *digest*
                          :salt salt
                          :iterations *iterations*)))

(defun increment-counter-block (block n)
  (let ((length (length block))
        (carry n))
    (loop for i from (1- length) downto 0
          until (zerop carry) do
          (let ((sum (+ (aref block i) carry)))
            (setf (aref block i) (ldb (byte 8 0) sum)
                  carry (ash sum -8))))
    (values)))

(defun read-header (input-file)
  (setf *salt* (make-array *salt-length* :element-type '(unsigned-byte 8))
        *mac* (make-array *mac-length* :element-type '(unsigned-byte 8))
        *tweak* (make-array *tweak-length* :element-type '(unsigned-byte 8))
        *iv* (make-array *block-length* :element-type '(unsigned-byte 8)))

  (unless (= (read-sequence *salt* input-file) *salt-length*)
    (error "Could not read the salt from the input stream."))
  (unless (= (read-sequence *mac* input-file) *mac-length*)
    (error "Could not read the mac from the input stream."))
  (unless (= (read-sequence *tweak* input-file) *tweak-length*)
    (error "Could not read the tweak from the input stream."))
  (unless (= (read-sequence *iv* input-file) *block-length*)
    (error "Could not read the initialization vector from the input stream."))
  (+ *salt-length* *mac-length* *tweak-length* *block-length*))

(defun write-header (output-file)
  (let* ((prng (make-prng :fortuna :seed :random))
         (fake-mac (random-data *mac-length* prng)))
    (setf *salt* (random-data *salt-length* prng)
          *tweak* (random-data *tweak-length* prng)
          *iv* (random-data *block-length* prng))
    (write-sequence *salt* output-file)
    (write-sequence fake-mac output-file)
    (write-sequence *tweak* output-file)
    (write-sequence *iv* output-file)
    (+ *salt-length* *mac-length* *tweak-length* *block-length*)))

(defun safe-read-from-file (file lock offset buffer &key (start 0) end)
  (let (n)
    (acquire-lock lock)
    (file-position file offset)
    (setf n (read-sequence buffer file :start start :end end))
    (release-lock lock)
    n))

(defun safe-write-to-file (file lock offset buffer &key (start 0) end)
  (let (s)
    (acquire-lock lock)
    (file-position file offset)
    (setf s (write-sequence buffer file :start start :end end))
    (release-lock lock)
    s))

(defun encryption-thread ()
  (let* ((current-thread (current-thread))
         (id (parse-integer (thread-name current-thread)))
         (start (car (aref *boundaries* id)))
         (count (cdr (aref *boundaries* id)))
         (iv (copy-seq *iv*))
         cipher)
    ;; Prepare cipher
    (increment-counter-block iv start)
    (setf cipher (make-cipher *cipher*
                              :key *key*
                              :tweak *tweak*
                              :mode :ctr
                              :initialization-vector iv))

    (do* ((i 0)
          (nblocks (min count *block-batch*))
          (offset (* start *block-length*))
          (plaintext (make-array (* nblocks *block-length*)
                                 :element-type '(unsigned-byte 8)
                                 :initial-element 0))
          (text-length 0)
          (ciphertext (make-array (* nblocks *block-length*)
                                  :element-type '(unsigned-byte 8)
                                  :initial-element 0)))
         ((= i count))
      ;; Read plaintext blocks
      (setf text-length
            (safe-read-from-file *input-file*
                                 *input-file-lock*
                                 offset
                                 plaintext
                                 :end (* nblocks *block-length*)))

      ;; Encrypt plaintext
      (encrypt cipher plaintext ciphertext :plaintext-end text-length)

      ;; Write ciphertext blocks
      (safe-write-to-file *output-file*
                          *output-file-lock*
                          (+ *header-length* offset)
                          ciphertext
                          :end text-length)
      (incf offset text-length)
      (incf i nblocks)
      (setf nblocks (min (- count i) *block-batch*)))))

(defun decryption-thread ()
  (let* ((current-thread (current-thread))
         (id (parse-integer (thread-name current-thread)))
         (start (car (aref *boundaries* id)))
         (count (cdr (aref *boundaries* id)))
         (iv (copy-seq *iv*))
         cipher)
    ;; Prepare cipher
    (increment-counter-block iv start)
    (setf cipher (make-cipher *cipher*
                              :key *key*
                              :tweak *tweak*
                              :mode :ctr
                              :initialization-vector iv))

    (do* ((i 0)
          (nblocks (min count *block-batch*))
          (offset (* start *block-length*))
          (ciphertext (make-array (* nblocks *block-length*)
                                  :element-type '(unsigned-byte 8)
                                  :initial-element 0))
          (text-length 0)
          (plaintext (make-array (* nblocks *block-length*)
                                 :element-type '(unsigned-byte 8)
                                 :initial-element 0)))
         ((= i count))
      ;; Read ciphertext blocks
      (setf text-length
            (safe-read-from-file *input-file*
                                 *input-file-lock*
                                 (+ *header-length* offset)
                                 ciphertext
                                 :end (* nblocks *block-length*)))

      ;; Decrypt ciphertext
      (decrypt cipher ciphertext plaintext :ciphertext-end text-length)

      ;; Write plaintext blocks
      (safe-write-to-file *output-file*
                          *output-file-lock*
                          offset
                          plaintext
                          :end text-length)
      (incf offset text-length)
      (incf i nblocks)
      (setf nblocks (min (- count i) *block-batch*)))))

(defun compute-mac (input-file key)
  (do* ((mac (make-skein-mac key
                             :block-length *block-length*
                             :digest-length *mac-length*))
        (buffer (make-array *buffer-size*
                            :element-type '(unsigned-byte 8)
                            :initial-element 0))
        (length *buffer-size*))
       ((zerop length) (skein-mac-digest mac))
    (setf length (read-sequence buffer input-file))
    (update-skein-mac mac buffer :end length)))

(defun encrypt-file (input-filename output-filename passphrase &optional (with-mac t))
  "Read data from INPUT-FILENAME, encrypt it using PASSPHRASE and write the
ciphertext to OUTPUT-FILENAME. If WITH-MAC is NIL, the authenticity code will
not be computed, and will contain random data instead."
  (let (nthreads mac nblocks)
    (with-open-file (input-file input-filename
                                :element-type '(unsigned-byte 8))
      (with-open-file (output-file output-filename
                                   :element-type'(unsigned-byte 8)
                                   :direction :io
                                   :if-exists :supersede)
        (setf *input-file* input-file
              *input-file-lock* (make-lock)
              *output-file* output-file
              *output-file-lock* (make-lock))

        ;; Make header (salt, fake-mac, tweak, iv)
        (write-header *output-file*)

        ;; Generate key
        (setf *key* (passphrase-to-key passphrase *salt*))

        ;; Create threads
        (setf nthreads (max-number-of-threads))
        (setf nblocks (max 1 (ceiling (file-length *input-file*) *block-length*)))
        (when (< nblocks nthreads)
          (setf nthreads nblocks))
        (setf *threads* (make-array nthreads))
        (setf *boundaries* (make-array nthreads))
        (multiple-value-bind (q r)
            (floor nblocks nthreads)
          (dotimes (i nthreads)
            (let ((name (format nil "~d" i)))
              (setf (aref *boundaries* i) (cons (* i q)
                                                (if (= i (1- nthreads))
                                                    (+ q r)
                                                    q)))
              (setf (aref *threads* i)
                    (make-thread #'encryption-thread :name name)))))

        ;; Wait for threads to finish
        (dotimes (i nthreads)
          (join-thread (aref *threads* i)))

        ;; Compute message authentication code
        (when with-mac
          (file-position *output-file* (+ *salt-length* *mac-length*))
          (setf mac (compute-mac *output-file* *key*))
          (file-position *output-file* *salt-length*)
          (write-sequence mac *output-file*))

        (file-length *output-file*)))))

(defun decrypt-file (input-filename output-filename passphrase &optional (with-mac t))
  "Read data from INPUT-FILENAME, decrypt it using PASSPHRASE and write the
plaintext to OUTPUT-FILENAME. If WITH-MAC is NIL, the authenticity of the
decrypted data will not be checked."
  (let (nthreads mac nblocks)
    (with-open-file (input-file input-filename
                                :element-type '(unsigned-byte 8))
      (with-open-file (output-file output-filename
                                   :element-type'(unsigned-byte 8)
                                   :direction :output
                                   :if-exists :supersede)
        (setf *input-file* input-file
              *input-file-lock* (make-lock)
              *output-file* output-file
              *output-file-lock* (make-lock))

        ;; Read header (salt, tweak, iv, mac)
        (read-header *input-file*)

        ;; Generate key
        (setf *key* (passphrase-to-key passphrase *salt*))

        ;; Compute and check message authentication code
        (when with-mac
          (file-position *input-file* (+ *salt-length* *mac-length*))
          (setf mac (compute-mac *input-file* *key*))
          (unless (equalp mac *mac*)
            (error "Decryption failed.")))

        ;; Create threads
        (setf nthreads (max-number-of-threads))
        (setf nblocks (max 1 (ceiling (- (file-length *input-file*) *header-length*)
                                      *block-length*)))
        (when (< nblocks nthreads)
          (setf nthreads nblocks))
        (setf *threads* (make-array nthreads))
        (setf *boundaries* (make-array nthreads))
        (multiple-value-bind (q r)
            (floor nblocks nthreads)
          (dotimes (i nthreads)
            (let ((name (format nil "~d" i)))
              (setf (aref *boundaries* i) (cons (* i q)
                                                (if (= i (1- nthreads))
                                                    (+ q r)
                                                    q)))
              (setf (aref *threads* i)
                    (make-thread #'decryption-thread :name name)))))

        ;; Wait for threads to finish
        (dotimes (i nthreads)
          (join-thread (aref *threads* i)))
        
        (file-length *output-file*)))))

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
      (let (decrypt-p input-filename output-filename passphrase)
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
               (progn
                 (format *error-output*
                         "Usage: ~a [-d] <input file> <output file>~%"
                         (elt argv 0))
                 (return-from main -1))))

        ;; Get passphrase
        (format *standard-output* "Enter the passphrase: ")
        (force-output *standard-output*)
        (setf passphrase (with-raw-io ()
                           (read-line *standard-input*)))
        (format *standard-output* "~%")

        ;; Encrypt or decrypt
        (if decrypt-p
            (decrypt-file input-filename output-filename passphrase)
            (encrypt-file input-filename output-filename passphrase)))
    (t (err) (progn
               (format *error-output* "~%Error: ~a~%" err)
               (return-from main -1))))
  0)
