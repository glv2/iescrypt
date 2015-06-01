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
(defparameter *iterations* 1000)
(defparameter *mac-length* (digest-length *digest*))
(defparameter *header-length* (+ *salt-length* *tweak-length* *block-length* *mac-length*))
(defparameter *block-size* (* *block-length* 16384)) ; 1048576 bytes
(defparameter *buffer-size* (/ *block-size* 32)) ; 32768 bytes

(defparameter *key* nil)
(defparameter *tweak* nil)
(defparameter *iv* nil)
(defparameter *input-file* nil)
(defparameter *input-file-lock* nil)
(defparameter *output-file* nil)
(defparameter *output-file-lock* nil)
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
  (handler-case
      (let* ((current-thread (current-thread))
             (id (parse-integer (thread-name current-thread)))
             (start (car (aref *boundaries* id)))
             (count (cdr (aref *boundaries* id)))
             (iv (copy-seq *iv*))
             cipher
             mac)

        ;; Prepare cipher
        (increment-counter-block iv (* start (/ *block-size* *block-length*)))
        (setf cipher (make-cipher *cipher*
                                  :key *key*
                                  :tweak *tweak*
                                  :mode :ctr
                                  :initialization-vector iv))
        (setf mac (make-skein-mac *key*
                                  :block-length *block-length*
                                  :digest-length *mac-length*))

        (do ((offset-in  (* start *block-size*))
             (offset-out (+ *header-length* (* start (+ *block-size* *mac-length*))))
             (buffer (make-array *buffer-size* :element-type '(unsigned-byte 8)))
             (text-length 0)
             (end-of-file nil)
             (buffers-by-block (/ *block-size* *buffer-size*))
             (i 0)
             (b 0 (1+ b)))
            ((or (= b (* count buffers-by-block))
                 end-of-file))

          ;; Read plaintext
          (setf text-length (safe-read-from-file *input-file*
                                                 *input-file-lock*
                                                 offset-in
                                                 buffer))
          (when (< text-length *buffer-size*)
            (setf end-of-file t))
          (incf offset-in text-length)

          ;; Encrypt plaintext
          (encrypt-in-place cipher buffer :end text-length)
          (update-skein-mac mac buffer :end text-length)

          ;; Write ciphertext
          (safe-write-to-file *output-file*
                              *output-file-lock*
                              offset-out
                              buffer
                              :end text-length)
          (incf offset-out text-length)
          (incf i)

          (when (or (= i buffers-by-block)
                    end-of-file)
            ;; Write mac for current block
            (safe-write-to-file *output-file*
                                *output-file-lock*
                                offset-out
                                (skein-mac-digest mac))
            (incf offset-out *mac-length*)
            (reinitialize-instance mac :key *key*)
            (setf i 0))))
    (t (err) (progn
               (format *error-output* "~%Error: ~a~%" err)
               (return-from encryption-thread)))))

(defun decryption-thread ()
  (handler-case
      (let* ((current-thread (current-thread))
             (id (parse-integer (thread-name current-thread)))
             (start (car (aref *boundaries* id)))
             (count (cdr (aref *boundaries* id)))
             (iv (copy-seq *iv*))
             cipher
             mac)

        ;; Prepare cipher
        (increment-counter-block iv (* start (/ *block-size* *block-length*)))
        (setf cipher (make-cipher *cipher*
                                  :key *key*
                                  :tweak *tweak*
                                  :mode :ctr
                                  :initialization-vector iv))
        (setf mac (make-skein-mac *key*
                                  :block-length *block-length*
                                  :digest-length *mac-length*))

        (do ((offset-in (+ *header-length* (* start (+ *block-size* *mac-length*))))
             (offset-out (* start *block-size*))
             (buffer (make-array (+ *buffer-size* *mac-length*)
                                 :element-type '(unsigned-byte 8)))
             (read-length 0)
             (text-length 0)
             (end-of-file nil)
             (buffers-by-block (/ *block-size* *buffer-size*))
             (i 0)
             (b 0 (1+ b)))
            ((or (= b (* count buffers-by-block))
                 end-of-file))

          ;; Read ciphertext and mac
          (setf read-length (safe-read-from-file *input-file*
                                                 *input-file-lock*
                                                 offset-in
                                                 buffer
                                                 :start text-length))
          (decf read-length text-length)
          (incf text-length read-length)
          (when (< text-length (+ *buffer-size* *mac-length*))
            (setf end-of-file t))
          (incf offset-in read-length)

          ;; Check that we have enough data for the mac
          (when (< text-length *mac-length*)
            (error "Could not read the mac from the input stream."))
          (decf text-length *mac-length*)

          ;; Decrypt ciphertext
          (update-skein-mac mac buffer :end text-length)
          (decrypt-in-place cipher buffer :end text-length)

          ;; Write plaintext
          (safe-write-to-file *output-file*
                              *output-file-lock*
                              offset-out
                              buffer
                              :end text-length)
          (incf offset-out text-length)
          (incf i)

          (if (or (= i buffers-by-block)
                  end-of-file)
              (progn
                ;; Check mac for current block
                (unless (equalp (subseq buffer text-length (+ text-length *mac-length*))
                                (skein-mac-digest mac))
                  (error "Data corrupted."))
                (setf text-length 0)
                (reinitialize-instance mac :key *key*)
                (setf i 0))
              (progn
                (replace buffer buffer :end1 *mac-length* :start2 text-length)
                (setf text-length *mac-length*)))))
    (t (err) (progn
               (format *error-output* "~%Error: ~a~%" err)
               (return-from decryption-thread)))))

(defun encrypt-file (input-filename output-filename passphrase)
  "Read data from INPUT-FILENAME, encrypt it using PASSPHRASE and write the
ciphertext to OUTPUT-FILENAME. If WITH-MAC is NIL, the authenticity code will
not be computed, and will contain random data instead."
  (with-open-file (input-file input-filename
                              :element-type '(unsigned-byte 8))
    (with-open-file (output-file output-filename
                                 :element-type'(unsigned-byte 8)
                                 :direction :output
                                 :if-exists :supersede)
      (let ((prng (make-prng :fortuna :seed :random))
            salt threads nthreads mac nblocks)

        (setf *input-file* input-file
              *input-file-lock* (make-lock)
              *output-file* output-file
              *output-file-lock* (make-lock))

        ;; Make header
        (setf salt (random-data *salt-length* prng)
              *tweak* (random-data *tweak-length* prng)
              *iv* (random-data *block-length* prng))

        ;; Generate key
        (setf *key* (passphrase-to-key passphrase salt))

        ;; Write header
        (setf mac (make-skein-mac *key*
                                  :block-length *block-length*
                                  :digest-length *mac-length*))
        (update-skein-mac mac *tweak*)
        (update-skein-mac mac *iv*)
        (write-sequence salt output-file)
        (write-sequence *tweak* output-file)
        (write-sequence *iv* output-file)
        (write-sequence (skein-mac-digest mac) output-file)

        ;; Create threads
        (setf nthreads (max-number-of-threads))
        (setf nblocks (max 1 (ceiling (file-length *input-file*) *block-size*)))
        (when (< nblocks nthreads)
          (setf nthreads nblocks))
        (setf threads (make-array nthreads))
        (setf *boundaries* (make-array nthreads))
        (multiple-value-bind (q r)
            (floor nblocks nthreads)
          (dotimes (i nthreads)
            (let ((name (format nil "~d" i)))
              (setf (aref *boundaries* i) (cons (* i q)
                                                (if (= i (1- nthreads))
                                                    (+ q r)
                                                    q)))
              (setf (aref threads i)
                    (make-thread #'encryption-thread :name name)))))

        ;; Wait for threads to finish
        (dotimes (i nthreads)
          (join-thread (aref threads i)))

        (file-length *output-file*)))))

(defun decrypt-file (input-filename output-filename passphrase)
  "Read data from INPUT-FILENAME, decrypt it using PASSPHRASE and write the
plaintext to OUTPUT-FILENAME. If WITH-MAC is NIL, the authenticity of the
decrypted data will not be checked."
  (with-open-file (input-file input-filename
                              :element-type '(unsigned-byte 8))
    (with-open-file (output-file output-filename
                                 :element-type'(unsigned-byte 8)
                                 :direction :output
                                 :if-exists :supersede)
      (let (salt threads nthreads mac old-mac nblocks)

        (setf *input-file* input-file
              *input-file-lock* (make-lock)
              *output-file* output-file
              *output-file-lock* (make-lock))

        ;; Read header
        (setf salt (make-array *salt-length* :element-type '(unsigned-byte 8))
              *tweak* (make-array *tweak-length* :element-type '(unsigned-byte 8))
              *iv* (make-array *block-length* :element-type '(unsigned-byte 8))
              old-mac (make-array *mac-length* :element-type '(unsigned-byte 8)))
        (unless (= (read-sequence salt input-file) *salt-length*)
          (error "Could not read the salt from the input stream."))
        (unless (= (read-sequence *tweak* input-file) *tweak-length*)
          (error "Could not read the tweak from the input stream."))
        (unless (= (read-sequence *iv* input-file) *block-length*)
          (error "Could not read the initialization vector from the input stream."))
        (unless (= (read-sequence old-mac input-file) *mac-length*)
          (error "Could not read the mac from the input stream."))

        ;; Generate key
        (setf *key* (passphrase-to-key passphrase salt))

        ;; Check header mac
        (setf mac (make-skein-mac *key*
                                  :block-length *block-length*
                                  :digest-length *mac-length*))
        (update-skein-mac mac *tweak*)
        (update-skein-mac mac *iv*)
        (unless (equalp old-mac (skein-mac-digest mac))
          (error "Decryption failed."))

        ;; Create threads
        (setf nthreads (max-number-of-threads))
        (setf nblocks (max 1 (ceiling (- (file-length *input-file*) *header-length*)
                                      (+ *block-size* *mac-length*))))
        (when (< nblocks nthreads)
          (setf nthreads nblocks))
        (setf threads (make-array nthreads))
        (setf *boundaries* (make-array nthreads))
        (multiple-value-bind (q r)
            (floor nblocks nthreads)
          (dotimes (i nthreads)
            (let ((name (format nil "~d" i)))
              (setf (aref *boundaries* i) (cons (* i q)
                                                (if (= i (1- nthreads))
                                                    (+ q r)
                                                    q)))
              (setf (aref threads i)
                    (make-thread #'decryption-thread :name name)))))

        ;; Wait for threads to finish
        (dotimes (i nthreads)
          (join-thread (aref threads i)))

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
