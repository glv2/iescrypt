;;;; This file is part of iescrypt
;;;; Copyright 2015-2018 Guillaume LE VAILLANT
;;;; Distributed under the GNU GPL v3 or later.
;;;; See the file LICENSE for terms of use and distribution.


(defpackage :iescrypt/tests
  (:use :cl :fiveam :iescrypt :uiop))

(in-package :iescrypt/tests)


(defconstant +message-length+ 1000000)
(defconstant +passphrase-length+ 20)
(setf *random-state* (make-random-state t))

(defun tmp-filename ()
  (iescrypt::get-temporary-filename))

(defun tmp-file ()
  (let ((tmp (tmp-filename)))
    (with-open-file (out tmp :direction :output :if-exists :supersede :element-type '(unsigned-byte 8))
      (loop repeat +message-length+
            do (write-byte (random 256) out)))
    tmp))

(defun tmp-passphrase ()
  (let ((tmp (tmp-filename))
        (characters "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz,;.:?!/\\$()[]{}'\"~&=+-*%#|`_@ "))
    (with-open-file (out tmp :direction :output :if-exists :supersede)
      (loop with l = (length characters)
            repeat +passphrase-length+
            do (write-char (char characters (random l)) out)))
    tmp))

(defun same-content-p (file-1 file-2)
  (with-open-file (f1 file-1 :element-type '(unsigned-byte 8))
    (with-open-file (f2 file-2 :element-type '(unsigned-byte 8))
      (and (= (file-length f1) (file-length f2))
           (loop for b1 = (read-byte f1 nil nil)
                 for b2 = (read-byte f2 nil nil)
                 until (null b1)
                 always (= b1 b2))))))


(def-suite iescrypt-tests
  :description "Unit tests for iescrypt")

(in-suite iescrypt-tests)


(test make-encryption-key-pair
  (let* ((key (tmp-filename))
         (key.pub (concatenate 'string key ".pub")))
    (unwind-protect
         (progn
           (make-encryption-key-pair key)
           (is-true (file-exists-p key))
           (is-true (file-exists-p key.pub)))
      (delete-file-if-exists key)
      (delete-file-if-exists key.pub))))

(test make-signing-key-pair
  (let* ((key (tmp-filename))
         (key.pub (concatenate 'string key ".pub")))
    (unwind-protect
         (progn
           (make-encryption-key-pair key)
           (is-true (file-exists-p key))
           (is-true (file-exists-p key.pub)))
      (delete-file-if-exists key)
      (delete-file-if-exists key.pub))))

(test encrypt-file-with-key
  (let* ((message (tmp-file))
         (ciphertext (tmp-filename))
         (key (tmp-filename))
         (key.pub (concatenate 'string key ".pub")))
    (unwind-protect
         (progn
           (make-encryption-key-pair key)
           (encrypt-file-with-key message ciphertext key.pub)
           (is-true (file-exists-p ciphertext)))
      (delete-file-if-exists message)
      (delete-file-if-exists ciphertext)
      (delete-file-if-exists key)
      (delete-file-if-exists key.pub))))

(test decrypt-file-with-key
  (let* ((message (tmp-file))
         (ciphertext (tmp-filename))
         (cleartext (tmp-filename))
         (key (tmp-filename))
         (key.pub (concatenate 'string key ".pub")))
    (unwind-protect
         (progn
           (make-encryption-key-pair key)
           (encrypt-file-with-key message ciphertext key.pub)
           (decrypt-file-with-key ciphertext cleartext key)
           (is-true (file-exists-p cleartext))
           (is-true (same-content-p message cleartext)))
      (delete-file-if-exists message)
      (delete-file-if-exists ciphertext)
      (delete-file-if-exists cleartext)
      (delete-file-if-exists key)
      (delete-file-if-exists key.pub))))

(test encrypt-file-with-passphrase
  (let ((message (tmp-file))
        (ciphertext (tmp-filename))
        (passphrase (tmp-passphrase)))
    (unwind-protect
         (progn
           (encrypt-file-with-passphrase message ciphertext passphrase)
           (is-true (file-exists-p ciphertext)))
      (delete-file-if-exists message)
      (delete-file-if-exists ciphertext)
      (delete-file-if-exists passphrase))))

(test decrypt-file-with-passphrase
  (let ((message (tmp-file))
        (ciphertext (tmp-filename))
        (cleartext (tmp-filename))
        (passphrase (tmp-passphrase)))
    (unwind-protect
         (progn
           (encrypt-file-with-passphrase message ciphertext passphrase)
           (decrypt-file-with-passphrase ciphertext cleartext passphrase)
           (is-true (file-exists-p cleartext))
           (is-true (same-content-p message cleartext)))
      (delete-file-if-exists message)
      (delete-file-if-exists ciphertext)
      (delete-file-if-exists cleartext)
      (delete-file-if-exists passphrase))))

(test sign-file
  (let* ((message (tmp-file))
         (signature (tmp-filename))
         (key (tmp-filename))
         (key.pub (concatenate 'string key ".pub")))
    (unwind-protect
         (progn
           (make-signing-key-pair key)
           (sign-file message signature key)
           (is-true (file-exists-p signature)))
      (delete-file-if-exists message)
      (delete-file-if-exists signature)
      (delete-file-if-exists key)
      (delete-file-if-exists key.pub))))


(test verify-file-signature
  (let* ((message (tmp-file))
         (signature (tmp-filename))
         (key (tmp-filename))
         (key.pub (concatenate 'string key ".pub")))
    (unwind-protect
         (progn
           (make-signing-key-pair key)
           (sign-file message signature key)
           (is-true (file-exists-p signature))
           (is-true (verify-file-signature message signature key.pub)))
      (delete-file-if-exists message)
      (delete-file-if-exists signature)
      (delete-file-if-exists key)
      (delete-file-if-exists key.pub))))

(test sign-and-encrypt-file-with-key
  (let* ((message (tmp-file))
         (ciphertext (tmp-filename))
         (enc-key (tmp-filename))
         (enc-key.pub (concatenate 'string enc-key ".pub"))
         (sig-key (tmp-filename))
         (sig-key.pub (concatenate 'string sig-key ".pub")))
    (unwind-protect
         (progn
           (make-encryption-key-pair enc-key)
           (make-signing-key-pair sig-key)
           (sign-and-encrypt-file-with-key message ciphertext sig-key enc-key.pub)
           (is-true (file-exists-p ciphertext)))
      (delete-file-if-exists message)
      (delete-file-if-exists ciphertext)
      (delete-file-if-exists enc-key)
      (delete-file-if-exists enc-key.pub)
      (delete-file-if-exists sig-key)
      (delete-file-if-exists sig-key.pub))))

(test decrypt-file-with-key-and-verify-signature
  (let* ((message (tmp-file))
         (ciphertext (tmp-filename))
         (cleartext (tmp-filename))
         (enc-key (tmp-filename))
         (enc-key.pub (concatenate 'string enc-key ".pub"))
         (sig-key (tmp-filename))
         (sig-key.pub (concatenate 'string sig-key ".pub")))
    (unwind-protect
         (progn
           (make-encryption-key-pair enc-key)
           (make-signing-key-pair sig-key)
           (sign-and-encrypt-file-with-key message ciphertext sig-key enc-key.pub)
           (is-true (decrypt-file-with-key-and-verify-signature ciphertext cleartext enc-key sig-key.pub))
           (is-true (file-exists-p cleartext))
           (is-true (same-content-p message cleartext)))
      (delete-file-if-exists message)
      (delete-file-if-exists ciphertext)
      (delete-file-if-exists cleartext)
      (delete-file-if-exists enc-key)
      (delete-file-if-exists enc-key.pub)
      (delete-file-if-exists sig-key)
      (delete-file-if-exists sig-key.pub))))

(test sign-and-encrypt-file-with-passphrase
  (let* ((message (tmp-file))
         (ciphertext (tmp-filename))
         (passphrase (tmp-passphrase))
         (sig-key (tmp-filename))
         (sig-key.pub (concatenate 'string sig-key ".pub")))
    (unwind-protect
         (progn
           (make-signing-key-pair sig-key)
           (sign-and-encrypt-file-with-passphrase message ciphertext sig-key passphrase)
           (is-true (file-exists-p ciphertext)))
      (delete-file-if-exists message)
      (delete-file-if-exists ciphertext)
      (delete-file-if-exists passphrase)
      (delete-file-if-exists sig-key)
      (delete-file-if-exists sig-key.pub))))

(test decrypt-file-with-passphrase-and-verify-signature
  (let* ((message (tmp-file))
         (ciphertext (tmp-filename))
         (cleartext (tmp-filename))
         (passphrase (tmp-passphrase))
         (sig-key (tmp-filename))
         (sig-key.pub (concatenate 'string sig-key ".pub")))
    (unwind-protect
         (progn
           (make-signing-key-pair sig-key)
           (sign-and-encrypt-file-with-passphrase message ciphertext sig-key passphrase)
           (is-true (decrypt-file-with-passphrase-and-verify-signature ciphertext cleartext passphrase sig-key.pub))
           (is-true (file-exists-p cleartext))
           (is-true (same-content-p message cleartext)))
      (delete-file-if-exists message)
      (delete-file-if-exists ciphertext)
      (delete-file-if-exists cleartext)
      (delete-file-if-exists passphrase)
      (delete-file-if-exists sig-key)
      (delete-file-if-exists sig-key.pub))))
