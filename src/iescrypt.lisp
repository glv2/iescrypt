;;;; This file is part of iescrypt
;;;; Copyright 2015-2018 Guillaume LE VAILLANT
;;;; Distributed under the GNU GPL v3 or later.
;;;; See the file LICENSE for terms of use and distribution.


(defpackage :iescrypt
  (:use :cl :archive :babel :ironclad :uiop)
  (:export #:make-encryption-key-pair
           #:make-signing-key-pair
           #:encrypt-file-with-key
           #:decrypt-file-with-key
           #:encrypt-file-with-passphrase
           #:decrypt-file-with-passphrase
           #:sign-file
           #:verify-file-signature
           #:sign-and-encrypt-file-with-key
           #:decrypt-file-with-key-and-verify-signature
           #:sign-and-encrypt-file-with-passphrase
           #:decrypt-file-with-passphrase-and-verify-signature
           #:main))

(in-package :iescrypt)


;;;
;;; Parameters
;;;

(defconstant +cipher+ :xchacha)
(defconstant +cipher-mode+ :stream)
(defconstant +cipher-key-length+ 32)
(defconstant +iv-length+ 24)
(defconstant +mac+ :poly1305)
(defconstant +mac-key-length+ 32)
(defconstant +mac-length+ 16)
(defconstant +salt-length+ 16)
(defconstant +dh-key-length+ 32)
(defconstant +parameter-length+ 32)
(defun generate-dh-key-pair ()
  (generate-key-pair :curve25519))
(defun get-dh-private-key (key)
  (curve25519-key-x key))
(defun get-dh-public-key (key)
  (curve25519-key-y key))
(defun make-dh-private-key (private-key)
  (make-private-key :curve25519 :x private-key))
(defun make-dh-public-key (public-key)
  (make-public-key :curve25519 :y public-key))
(defconstant +signature-key-length+ 32)
(defconstant +signature-length+ 64)
(defun generate-signature-key-pair ()
  (generate-key-pair :ed25519))
(defun get-signature-private-key (key)
  (ed25519-key-x key))
(defun get-signature-public-key (key)
  (ed25519-key-y key))
(defun make-signature-private-key (private-key)
  (make-private-key :ed25519 :x private-key))
(defun make-signature-public-key (public-key)
  (make-public-key :ed25519 :y public-key))
(defconstant +digest+ :blake2)
(defconstant +buffer-length+ 4096)


;;;
;;; Integrated encryption scheme
;;;

(defun derive-keys (shared-secret salt)
  "Derive a cipher key, an initialization vector and a message
authentication key from a SHARED-SECRET and a SALT."
  (let* ((kdf (make-kdf :argon2i :block-count 4096))
         (data (derive-key kdf shared-secret salt 3 (+ +cipher-key-length+ +iv-length+ +mac-key-length+)))
         (cipher-key (subseq data 0 +cipher-key-length+))
         (iv (subseq data +cipher-key-length+ (+ +cipher-key-length+ +iv-length+)))
         (mac-key (subseq data (+ +cipher-key-length+ +iv-length+))))
    (values cipher-key iv mac-key)))

;; (defun ies-encrypt-stream (shared-secret salt input-stream output-stream)
;;   "Write the encryption of INPUT-STREAM to OUTPUT-STREAM and return
;; a message authentication code of what was written to OUTPUT-STREAM.
;; The encryption parameters (key, initialization vector) are derived
;; from the SHARED-SECRET and the SALT."
;;   (multiple-value-bind (cipher-key iv mac-key)
;;       (derive-keys shared-secret salt)
;;     (with-authenticating-stream (mac-stream +mac+ mac-key)
;;       (with-open-stream (out-stream (make-broadcast-stream output-stream mac-stream))
;;         (with-encrypting-stream (cipher-stream out-stream +cipher+ +cipher-mode+ cipher-key :initialization-vector iv)
;;           (copy-stream-to-stream input-stream cipher-stream :element-type '(unsigned-byte 8))))
;;       (produce-mac mac-stream))))
(defun ies-encrypt-stream (shared-secret salt input-stream output-stream)
  "Write the encryption of INPUT-STREAM to OUTPUT-STREAM and return
a message authentication code of what was written to OUTPUT-STREAM.
The encryption parameters (key, initialization vector) are derived
from the SHARED-SECRET and the SALT."
  (multiple-value-bind (cipher-key iv mac-key)
      (derive-keys shared-secret salt)
    (do* ((cipher (make-cipher +cipher+ :mode +cipher-mode+ :key cipher-key :initialization-vector iv))
          (mac (make-mac +mac+ mac-key))
          (buffer (make-array +buffer-length+ :element-type '(unsigned-byte 8)))
          (n (read-sequence buffer input-stream) (read-sequence buffer input-stream)))
         ((zerop n) (produce-mac mac))
      (encrypt cipher buffer buffer :plaintext-end n)
      (write-sequence buffer output-stream :end n)
      (update-mac mac buffer :end n))))

;; (defun ies-decrypt-stream (shared-secret salt input-stream output-stream)
;;   "Write the decryption of INPUT-STREAM to OUTPUT-STREAM and return
;; a message authentication code of what was read from INPUT-STREAM. The
;; decryption parameters (key, initialization vector) are derived from
;; the SHARED-SECRET and the SALT."
;;   (multiple-value-bind (cipher-key iv mac-key)
;;       (derive-keys shared-secret salt)
;;     (with-authenticating-stream (mac-stream +mac+ mac-key)
;;       (with-open-stream (in-stream (make-echo-stream input-stream mac-stream))
;;         (with-decrypting-stream (cipher-stream in-stream +cipher+ +cipher-mode+ cipher-key :initialization-vector iv)
;;           (copy-stream-to-stream cipher-stream output-stream :element-type '(unsigned-byte 8))))
;;       (produce-mac mac-stream))))
(defun ies-decrypt-stream (shared-secret salt input-stream output-stream)
  "Write the decryption of INPUT-STREAM to OUTPUT-STREAM and return
a message authentication code of what was read from INPUT-STREAM. The
decryption parameters (key, initialization vector) are derived from
the SHARED-SECRET and the SALT."
  (multiple-value-bind (cipher-key iv mac-key)
      (derive-keys shared-secret salt)
    (do* ((cipher (make-cipher +cipher+ :mode +cipher-mode+ :key cipher-key :initialization-vector iv))
          (mac (make-mac +mac+ mac-key))
          (buffer (make-array +buffer-length+ :element-type '(unsigned-byte 8)))
          (n (read-sequence buffer input-stream) (read-sequence buffer input-stream)))
         ((zerop n) (produce-mac mac))
      (update-mac mac buffer :end n)
      (decrypt cipher buffer buffer :ciphertext-end n)
      (write-sequence buffer output-stream :end n))))


;;;
;;; Utils
;;;

(defun get-temporary-filename (&optional (suffix ""))
  "Generate a file name ending with SUFFIX that doesn't match any of the
files in the current directory."
  (let* ((id (random-bits 32))
         (filename (format nil "tmp-~d~a" id suffix)))
    (if (file-exists-p filename)
        (get-temporary-filename suffix)
        filename)))

(defun read-file (filename &optional expected-length)
  "Return the content of FILENAME in a byte array."
  (with-open-file (file filename
                        :direction :input
                        :element-type '(unsigned-byte 8))
    (let ((length (file-length file)))
      (when (and expected-length (/= length expected-length))
        (error "The file \"~a\" is not ~d bytes long" filename expected-length))
      (let ((buffer (make-array length :element-type '(unsigned-byte 8))))
        (unless (= (read-sequence buffer file) length)
          (error "Could not read file \"~a\" completely" filename))
        buffer))))

(defun write-file (filename input)
  "Write the content of INPUT to FILENAME. INPUT can be a byte array
or a byte stream."
  (with-open-file (output filename
                          :direction :output
                          :element-type '(unsigned-byte 8))
    (etypecase input
      (vector (write-sequence input output))
      (stream (copy-stream-to-stream input output :element-type '(unsigned-byte 8))))))

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
     (format *error-output* "Warning: could not disable the terminal echo~%")
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
          (error "Passphrases don't match"))))
    passphrase))


;;;
;;; Encryption, decryption, signature and verification functions
;;;

(defun make-encryption-key-pair (filename)
  "Generate a new key pair for Diffie-Hellman key exchanges. The
private key is written to FILENAME and the public key is written to
FILENAME.pub."
  (multiple-value-bind (sk pk)
      (generate-dh-key-pair)
    (write-file filename (get-dh-private-key sk))
    (write-file (concatenate 'string filename ".pub") (get-dh-public-key pk))))

(defun make-signing-key-pair (filename)
  "Generate a new key pair for signatures. The private key is written
to FILENAME and the public key is written to FILENAME.pub."
  (multiple-value-bind (sk pk)
      (generate-signature-key-pair)
    (write-file filename (get-signature-private-key sk))
    (write-file (concatenate 'string filename ".pub") (get-signature-public-key pk))))

(defun encrypt-file-with-key (input-file output-file public-key-file)
  "Encrypt INPUT-FILE using the public key in PUBLIC-KEY-FILE and
write the ciphertext to OUTPUT-FILE."
  (with-open-file (input-stream input-file :element-type '(unsigned-byte 8))
    (with-open-file (output-stream output-file :direction :output :element-type '(unsigned-byte 8))
      (multiple-value-bind (sk2 pk2)
          (generate-dh-key-pair)
        (let* ((public-key (read-file public-key-file +dh-key-length+))
               (pk1 (make-dh-public-key public-key))
               (parameter (get-dh-public-key pk2))
               (shared-secret (diffie-hellman sk2 pk1))
               (salt (random-data +salt-length+)))
          (write-sequence salt output-stream)
          (write-sequence parameter output-stream)
          (file-position output-stream (+ +salt-length+ +parameter-length+ +mac-length+))
          (let ((mac (ies-encrypt-stream shared-secret salt input-stream output-stream)))
            (file-position output-stream (+ +salt-length+ +parameter-length+))
            (write-sequence mac output-stream)))))))

(defun decrypt-file-with-key (input-file output-file private-key-file)
  "Decrypt INPUT-FILE using the private key in PRIVATE-KEY-FILE and
write the cleartext to OUTPUT-FILE."
  (with-open-file (input-stream input-file :element-type '(unsigned-byte 8))
    (with-open-file (output-stream output-file :direction :output :element-type '(unsigned-byte 8))
      (let ((salt (make-array +salt-length+ :element-type '(unsigned-byte 8)))
            (parameter (make-array +parameter-length+ :element-type '(unsigned-byte 8)))
            (mac (make-array +mac-length+ :element-type '(unsigned-byte 8))))
        (unless (and (= (read-sequence salt input-stream) +salt-length+)
                     (= (read-sequence parameter input-stream) +parameter-length+)
                     (= (read-sequence mac input-stream) +mac-length+))
          (error "Input stream too short"))
        (let* ((private-key (read-file private-key-file +dh-key-length+))
               (sk1 (make-dh-private-key private-key))
               (pk2 (make-dh-public-key parameter))
               (shared-secret (diffie-hellman sk1 pk2))
               (computed-mac (ies-decrypt-stream shared-secret salt input-stream output-stream)))
          (or (constant-time-equal mac computed-mac)
              (error "Invalid message authentication code")))))))

(defun encrypt-file-with-passphrase (input-file output-file &optional passphrase-file)
  "Encrypt INPUT-FILE and write the ciphertext to OUTPUT-FILE. The
passphrase used to encrypt is read from PASSPHRASE-FILE if it is
specified, and asked to the user otherwise."
  (with-open-file (input-stream input-file :element-type '(unsigned-byte 8))
    (with-open-file (output-stream output-file :direction :output :element-type '(unsigned-byte 8))
      (let* ((passphrase (if passphrase-file
                             (read-file-line passphrase-file)
                             (get-passphrase t)))
             (parameter (random-data +parameter-length+))
             (shared-secret (string-to-octets passphrase :encoding :utf-8))
             (salt (random-data +salt-length+)))
        (write-sequence salt output-stream)
        (write-sequence parameter output-stream)
        (file-position output-stream (+ +salt-length+ +parameter-length+ +mac-length+))
        (let ((mac (ies-encrypt-stream shared-secret salt input-stream output-stream)))
          (file-position output-stream (+ +salt-length+ +parameter-length+))
          (write-sequence mac output-stream))))))

(defun decrypt-file-with-passphrase (input-file output-file &optional passphrase-file)
  "Decrypt INPUT-FILE and write the cleartext to OUTPUT-FILE. The
passphrase used to decrypt is read from PASSPHRASE-FILE if it is
specified, and asked to the user otherwise."
  (with-open-file (input-stream input-file :element-type '(unsigned-byte 8))
    (with-open-file (output-stream output-file :direction :output :element-type '(unsigned-byte 8))
      (let ((salt (make-array +salt-length+ :element-type '(unsigned-byte 8)))
            (parameter (make-array +parameter-length+ :element-type '(unsigned-byte 8)))
            (mac (make-array +mac-length+ :element-type '(unsigned-byte 8))))
        (unless (and (= (read-sequence salt input-stream) +salt-length+)
                     (= (read-sequence parameter input-stream) +parameter-length+)
                     (= (read-sequence mac input-stream) +mac-length+))
          (error "Input stream too short"))
        (let* ((passphrase (if passphrase-file
                               (read-file-line passphrase-file)
                               (get-passphrase nil)))
               (shared-secret (string-to-octets passphrase :encoding :utf-8))
               (computed-mac (ies-decrypt-stream shared-secret salt input-stream output-stream)))
          (or (constant-time-equal mac computed-mac)
              (error "Invalid message authentication code")))))))

(defun sign-file (input-file signature-file private-key-file)
  "Write the signature of INPUT-FILE by the private key in
PRIVATE-KEY-FILE to SIGNATURE-FILE."
  (let* ((private-key (make-signature-private-key (read-file private-key-file +signature-key-length+)))
         (public-key (get-signature-public-key private-key))
         (hash (digest-file +digest+ input-file))
         (signature (concatenate '(simple-array (unsigned-byte 8) (*))
                                 public-key
                                 (sign-message private-key hash))))
    (write-file signature-file signature)))

(defun verify-file-signature (input-file signature-file &optional public-key-file)
  "Verify that SIGNATURE-FILE contains a valid sigature of INPUT-FILE.
If a PUBLIC-KEY-FILE is specified, also verify that the signature was
made using the matching private key."
  (let* ((signature (read-file signature-file (+ +signature-key-length+ +signature-length+)))
         (public-key (when public-key-file
                       (read-file public-key-file +signature-key-length+)))
         (signature-public-key (subseq signature 0 +signature-key-length+))
         (pk (make-signature-public-key signature-public-key))
         (sig (subseq signature +signature-key-length+))
         (hash (digest-file +digest+ input-file)))
    (if (and (or (null public-key) (constant-time-equal public-key signature-public-key))
             (verify-signature pk hash sig))
        (let ((signer (byte-array-to-hex-string signature-public-key)))
          (format t "Valid signature from ~a~%" signer)
          t)
        (error "Bad signature"))))

(defun sign-and-encrypt-file-with-key (input-file output-file signature-private-key-file encryption-public-key-file)
  "Sign INPUT-FILE with the private key in SIGNATURE-PRIVATE-KEY-FILE,
then encrypt INPUT-FILE and the signature using the public key in
ENCRYPTION-PUBLIC-KEY-FILE, and write the cyphertext to OUTPUT-FILE."
  (let ((signature-file (concatenate 'string input-file ".sig"))
        (archive-file (get-temporary-filename ".tar")))
    (unwind-protect
         (progn
           (sign-file input-file signature-file signature-private-key-file)
           (with-open-archive (archive archive-file :direction :output)
             (write-entry-to-archive archive (create-entry-from-pathname archive input-file))
             (write-entry-to-archive archive (create-entry-from-pathname archive signature-file))
             (finalize-archive archive))
           (encrypt-file-with-key archive-file output-file encryption-public-key-file))
      (delete-file-if-exists signature-file)
      (delete-file-if-exists archive-file))))

(defun decrypt-file-with-key-and-verify-signature (input-file output-file encryption-private-key-file &optional signature-public-key-file)
  "Decrypt INPUT-FILE (which should have been created with the
SIGN-AND-ENCRYPT-FILE-WITH-KEY function) using the private key in
ENCRYPTION-PRIVATE-KEY-FILE, verify that it has a valid signature, and
write the cleartext to OUTPUT-FILE. If SIGNATURE-PUBLIC-KEY-FILE is
specified, also verify that the signature was made using the matching
private key."
  (let ((signature-file (get-temporary-filename ".sig"))
        (archive-file (get-temporary-filename ".tar")))
    (unwind-protect
         (let (entries)
           (decrypt-file-with-key input-file archive-file encryption-private-key-file)
           (with-open-archive (archive archive-file :direction :input)
             (do-archive-entries (entry archive)
               (when (entry-regular-file-p entry)
                 (push (name entry) entries))))
           (unless (= (length entries) 2)
             (error "Unknown decrypted file format"))
           (let ((data-name (first entries))
                 (signature-name (second entries)))
             (when (> (length data-name) (length signature-name))
               ;; The name of the signature file ("foo.sig") is always
               ;; longer than the name of the data file ("foo").
               (rotatef data-name signature-name))
             (with-open-archive (archive archive-file :direction :input)
               (do-archive-entries (entry archive)
                 (when (entry-regular-file-p entry)
                   (cond ((string= (name entry) data-name)
                          (write-file output-file (entry-stream entry)))
                         ((string= (name entry) signature-name)
                          (write-file signature-file (entry-stream entry))))))))
           (verify-file-signature output-file signature-file signature-public-key-file)))
    (delete-file-if-exists signature-file)
    (delete-file-if-exists archive-file)))

(defun sign-and-encrypt-file-with-passphrase (input-file output-file signature-private-key-file &optional passphrase-file)
  "Sign INPUT-FILE with the private key in SIGNATURE-PRIVATE-KEY-FILE,
then encrypt INPUT-FILE and the signature, and write the cyphertext to
OUTPUT-FILE. The passphrase used to encrypt is read from
PASSPHRASE-FILE if it is specified, and asked to the user otherwise."
  (let ((signature-file (concatenate 'string input-file ".sig"))
        (archive-file (get-temporary-filename ".tar")))
    (unwind-protect
         (progn
           (sign-file input-file signature-file signature-private-key-file)
           (with-open-archive (archive archive-file :direction :output)
             (write-entry-to-archive archive (create-entry-from-pathname archive input-file))
             (write-entry-to-archive archive (create-entry-from-pathname archive signature-file))
             (finalize-archive archive))
           (encrypt-file-with-passphrase archive-file output-file passphrase-file))
      (delete-file-if-exists signature-file)
      (delete-file-if-exists archive-file))))

(defun decrypt-file-with-passphrase-and-verify-signature (input-file output-file &optional passphrase-file  signature-public-key-file)
  "Decrypt INPUT-FILE (which should have been created with the
SIGN-AND-ENCRYPT-FILE-WITH-PASSPHRASE function), verify that it has
a valid signature, and write the cleartext to OUTPUT-FILE. The
passphrase used to decrypt is read from PASSPHRASE-FILE if it is
specified, and asked to the user otherwise. If
SIGNATURE-PUBLIC-KEY-FILE is specified, also verify that the signature
was made using the matching private key."
  (let ((signature-file (get-temporary-filename ".sig"))
        (archive-file (get-temporary-filename ".tar")))
    (unwind-protect
         (let (entries)
           (decrypt-file-with-passphrase input-file archive-file passphrase-file)
           (with-open-archive (archive archive-file :direction :input)
             (do-archive-entries (entry archive)
               (when (entry-regular-file-p entry)
                 (push (name entry) entries))))
           (unless (= (length entries) 2)
             (error "Unknown decrypted file format"))
           (let ((data-name (first entries))
                 (signature-name (second entries)))
             (when (> (length data-name) (length signature-name))
               ;; The name of the signature file ("foo.sig") is always
               ;; longer than the name of the data file ("foo").
               (rotatef data-name signature-name))
             (with-open-archive (archive archive-file :direction :input)
               (do-archive-entries (entry archive)
                 (when (entry-regular-file-p entry)
                   (cond ((string= (name entry) data-name)
                          (write-file output-file (entry-stream entry)))
                         ((string= (name entry) signature-name)
                          (write-file signature-file (entry-stream entry))))))))
           (verify-file-signature output-file signature-file signature-public-key-file)))
    (delete-file-if-exists signature-file)
    (delete-file-if-exists archive-file)))


;;;
;;; Commands for standalone program
;;;

(defparameter *command-table*
  (list (cons "gen-enc" (list #'make-encryption-key-pair 1 1))
        (cons "gen-sig" (list #'make-signing-key-pair 1 1))
        (cons "enc" (list #'encrypt-file-with-key 3 3))
        (cons "dec" (list #'decrypt-file-with-key 3 3))
        (cons "penc" (list #'encrypt-file-with-passphrase 2 3))
        (cons "pdec" (list #'decrypt-file-with-passphrase 2 3))
        (cons "sig" (list #'sign-file 3 3))
        (cons "ver" (list #'verify-file-signature 2 3))
        (cons "sig-enc" (list #'sign-and-encrypt-file-with-key 4 4))
        (cons "dec-ver" (list #'decrypt-file-with-key-and-verify-signature 3 4))
        (cons "sig-penc" (list #'sign-and-encrypt-file-with-passphrase 3 4))
        (cons "pdec-ver" (list #'decrypt-file-with-passphrase-and-verify-signature 2 4))))

(defparameter *usage*
  "
Usage: iescrypt <command> <arguments>

Commands:

  gen-enc <file>

     Generate a key pair for encryption. The private key is written
     to 'file' and the public key is written to 'file.pub'.


  gen-sig <file>

     Generate a key pair for signature. The private key is written
     to 'file' and the public key is written to 'file.pub'.


  enc <input file> <output file> <public key file>

    Encrypt a file with a public key.


  dec <input file> <output file> <private key file>

    Decrypt a file that was encrypted with a public key using
    the matching private key.


  penc <input file> <output file> [passphrase file]

    Encrypt a file using a passphrase.


  pdec <input file> <output file> [passphrase file]

    Decrypt a file using a passphrase.


  sig <input file> <signature file> <private key file>

    Sign a file with a private key.


  ver <input-file> <signature-file> [public key file]

    Verify a signature of a file.
    If a public key file is specified, also verify that the signature
    was made with the matching private key.


  sig-enc <input file> <output file> <signature private key file>
          <encryption public key file>

    Sign a file with a private key and encrypt the file and the signature
    with a public key.


  dec-ver <input file> <output file> <encryption private key file>
          [signature public key file]

    Decrypt a file with a private key and verify that it has a valid
    signature. If a signature public key is specified, also verify that
    the signature was made with the matching private key.


  sig-penc <input file> <output file> <signature private key file>
           [passphrase file]

    Sign a file with a private key and encrypt the file and the signature
    with a passphrase.


  pdec-ver <input file> <output file>
           [passphrase file [signature public key file]]

    Decrypt a file with a passphrase and verify that it has a valid
    signature. If a signature public key is specified, also verify that
    the signature was made with the matching private key.
")

(defun main (&optional (args (command-line-arguments)))
  "Entry point for standalone program."
  (handler-case
      (let ((nargs (length args)))
        (when (zerop nargs)
          (format *error-output* "~a~%" *usage*)
          (error "Invalid command"))
        (let* ((command-info (cdr (assoc (elt args 0) *command-table* :test #'string-equal)))
               (command (car command-info))
               (min-args (cadr command-info))
               (max-args (caddr command-info)))
          (if (and command (<= min-args (1- nargs) max-args))
              (progn
                (apply command (rest args))
                (quit 0))
              (progn
                (format *error-output* "~a~%" *usage*)
                (error "Invalid command")))))
    (t (err)
      (format *error-output* "Error: ~a~%" err)
      (quit -1))))
