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


(defparameter *max-number-of-threads* nil)
(defparameter *key* nil)
(defparameter *tweak* nil)
(defparameter *iv* nil)
(defparameter *input-file* nil)
(defparameter *input-file-lock* nil)
(defparameter *output-file* nil)
(defparameter *output-file-lock* nil)
(defparameter *boundaries* nil)


(defun max-number-of-threads ()
  (let ((cores 1))
    (handler-case
        (progn
          #+linux
          (with-open-file (cpuinfo #p"/proc/cpuinfo")
            (do ((n 0)
                 (line (read-line cpuinfo nil nil) (read-line cpuinfo nil nil)))
                ((null line) (setf cores n))
              (when (string= (subseq line 0 (min (length line) 9)) "processor")
                (incf n))))

          #+windows
          (let ((buffer (run/s "wmic cpu get NumberOfCores /format:List")))
            (with-input-from-string (in buffer)
              (do ((n 0)
                   (line (read-line in nil nil) (read-line in nil nil)))
                  ((null line) (setf cores n))
                (when (string= (subseq line 0 (min (length line) 14)) "NumberOfCores=")
                  (incf n (parse-integer (subseq line 14)))))))

          #+(or darwin freebsd netbsd openbsd)
          (let ((buffer (run/s "sysctl hw.logicalcpu")))
            (with-input-from-string (in buffer)
              (do ((n 0)
                   (line (read-line in nil nil) (read-line in nil nil)))
                  ((null line) (setf cores n))
                (when (string= (subseq line 0 (min (length line) 15)) "hw.logicalcpu: ")
                  (incf n (parse-integer (subseq line 15))))))))
      (t () (progn
              (setf cores 1)
              (format *error-output* "Warning: could not determine the number of processing cores.~%"))))

    (setf cores (max 1 cores))
    (format *error-output* "Info: using ~d thread~:p.~%" cores)
    cores))

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
    (t (err) (return-from encryption-thread (format nil "~a" err)))))

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
    (t (err) (return-from decryption-thread (format nil "~a" err)))))

(defun encrypt-file (input-filename output-filename passphrase)
  "Read data from INPUT-FILENAME, encrypt it using PASSPHRASE and write the
ciphertext to OUTPUT-FILENAME."
  (with-open-file (input-file input-filename
                              :element-type '(unsigned-byte 8))
    (with-open-file (output-file output-filename
                                 :element-type'(unsigned-byte 8)
                                 :direction :output
                                 :if-exists :supersede)
      (let ((prng (make-prng :fortuna :seed :random))
            salt threads nthreads mac nblocks ret err)

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
        (unless *max-number-of-threads*
          (setf *max-number-of-threads* (max-number-of-threads)))
        (setf nthreads *max-number-of-threads*)
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
          (setf ret (join-thread (aref threads i)))
          (when (and (null err) (stringp ret))
            (setf err ret)))
        (when err
          (error err))

        (file-length *output-file*)))))

(defun decrypt-file (input-filename output-filename passphrase)
  "Read data from INPUT-FILENAME, decrypt it using PASSPHRASE and write the
plaintext to OUTPUT-FILENAME."
  (with-open-file (input-file input-filename
                              :element-type '(unsigned-byte 8))
    (with-open-file (output-file output-filename
                                 :element-type'(unsigned-byte 8)
                                 :direction :output
                                 :if-exists :supersede)
      (let (salt threads nthreads mac old-mac nblocks ret err)

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
        (unless *max-number-of-threads*
          (setf *max-number-of-threads* (max-number-of-threads)))
        (setf nthreads *max-number-of-threads*)
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
          (setf ret (join-thread (aref threads i)))
          (when (and (null err) (stringp ret))
            (setf err ret)))
        (when err
          (error err))

        (file-length *output-file*)))))
