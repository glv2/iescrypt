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

(defun encrypt+mac (job-id tweak key counter plaintext len)
  (let* ((cipher (make-cipher *cipher*
                              :key key
                              :tweak tweak
                              :mode :ctr
                              :initialization-vector counter))
         (mac (make-skein-mac key
                              :block-length *block-length*
                              :digest-length *mac-length*))
         (ciphertext (make-array (+ len *mac-length*) :element-type '(unsigned-byte 8))))
    (encrypt cipher plaintext ciphertext :plaintext-end len)
    (update-skein-mac mac ciphertext :end len)
    (replace ciphertext (skein-mac-digest mac) :start1 len)
    (list job-id ciphertext)))

(defun decrypt+check (job-id tweak key counter ciphertext+mac len)
  (let* ((cipher (make-cipher *cipher*
                              :key key
                              :tweak tweak
                              :mode :ctr
                              :initialization-vector counter))
         (mac (make-skein-mac key
                              :block-length *block-length*
                              :digest-length *mac-length*))
         (ciphertext-len (- len *mac-length*))
         (plaintext (make-array ciphertext-len :element-type '(unsigned-byte 8)))
         (old-mac (subseq ciphertext+mac ciphertext-len len)))
    (update-skein-mac mac ciphertext+mac :end ciphertext-len)
    (decrypt cipher ciphertext+mac plaintext :ciphertext-end ciphertext-len)
    (if (equalp old-mac (skein-mac-digest mac))
        (list job-id plaintext nil)
        (list job-id nil "Data corrupted."))))

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
            salt key tweak iv mac)

        ;; Make header
        (setf salt (random-data *salt-length* prng)
              tweak (random-data *tweak-length* prng)
              iv (random-data *block-length* prng))

        ;; Generate key
        (setf key (passphrase-to-key passphrase salt))

        ;; Write header
        (setf mac (make-skein-mac key
                                  :block-length *block-length*
                                  :digest-length *mac-length*))
        (update-skein-mac mac tweak)
        (update-skein-mac mac iv)
        (write-sequence salt output-file)
        (write-sequence tweak output-file)
        (write-sequence iv output-file)
        (write-sequence (skein-mac-digest mac) output-file)

        (unless *kernel*
          (setf *kernel* (make-kernel (max-number-of-threads))))

        (do ((channel (make-channel))
             (results (make-hash-table))
             (running-tasks 0)
             (job-id 0)
             (next-job-id 0)
             (counter iv)
             (counter-increment (/ *block-size* *block-length*))
             (end-of-file nil))
            ((and end-of-file (zerop running-tasks)))

          ;; Add new encryption tasks
          (do (plaintext len)
              ((or end-of-file (>= running-tasks (kernel-worker-count))))

            ;; Read plaintext block
            (setf plaintext (make-array *block-size* :element-type '(unsigned-byte 8)))
            (setf len (read-sequence plaintext input-file))
            (when (< len *block-size*)
              (setf end-of-file t))

            ;; Submit task (only the first task can have no data to encrypt)
            (unless (and (zerop len) (plusp job-id))
              (submit-task channel #'encrypt+mac job-id tweak key (copy-seq counter) plaintext len)
              (incf running-tasks)
              (increment-counter-block counter counter-increment)
              (incf job-id)))

          ;; Get the results of the finished encryption tasks (job-id cyphertext+mac)
          (unless (zerop running-tasks)
            (do ((res (receive-result channel) (try-receive-result channel)))
                ((null res))
              (setf (gethash (first res) results) (second res))
              (decf running-tasks)))

          ;; Write ciphertext and mac blocks
          (do ((data (gethash next-job-id results) (gethash next-job-id results)))
              ((null data))
            (write-sequence data output-file)
            (remhash next-job-id results)
            (incf next-job-id)))

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
      (let (salt key tweak iv mac old-mac)

        ;; Read header
        (setf salt (make-array *salt-length* :element-type '(unsigned-byte 8))
              tweak (make-array *tweak-length* :element-type '(unsigned-byte 8))
              iv (make-array *block-length* :element-type '(unsigned-byte 8))
              old-mac (make-array *mac-length* :element-type '(unsigned-byte 8)))
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

        ;; Check header mac
        (setf mac (make-skein-mac key
                                  :block-length *block-length*
                                  :digest-length *mac-length*))
        (update-skein-mac mac tweak)
        (update-skein-mac mac iv)
        (unless (equalp old-mac (skein-mac-digest mac))
          (error "Decryption failed."))

        (unless *kernel*
          (setf *kernel* (make-kernel (max-number-of-threads))))

        (do ((channel (make-channel))
             (results (make-hash-table))
             (running-tasks 0)
             (job-id 0)
             (next-job-id 0)
             (counter iv)
             (counter-increment (/ *block-size* *block-length*))
             (end-of-file nil))
            ((and end-of-file (zerop running-tasks)))

          ;; Add new decryption tasks
          (do (ciphertext+mac len)
              ((or end-of-file (>= running-tasks (kernel-worker-count))))

            ;; Read ciphertext and mac
            (setf ciphertext+mac (make-array (+ *block-size* *mac-length*)
                                             :element-type '(unsigned-byte 8)))
            (setf len (read-sequence ciphertext+mac input-file))
            (when (< len (+ *block-size* *mac-length*))
              (setf end-of-file t))

            ;; Submit task
            (unless (zerop len)
              (when (< len *mac-length*)
                (error "Could not read the mac from the input stream."))
              (submit-task channel #'decrypt+check job-id tweak key (copy-seq counter) ciphertext+mac len)
              (incf running-tasks)
              (increment-counter-block counter counter-increment)
              (incf job-id)))

          ;; Get the resultes of the finished decryption tasks (job-id plaintext error)
          (unless (zerop running-tasks)
            (do ((res (receive-result channel) (try-receive-result channel)))
                ((null res))
              (when (third res)
                (error (third res)))
              (setf (gethash (first res) results) (second res))
              (decf running-tasks)))

          ;; Write plaintext blocks
          (do ((plaintext (gethash next-job-id results) (gethash next-job-id results)))
              ((null plaintext))
            (write-sequence plaintext output-file)
            (remhash next-job-id results)
            (incf next-job-id)))

        (file-length output-file)))))
