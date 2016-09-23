;;;; -*- mode: lisp; indent-tabs-mode: nil -*-

#|

Copyright 2015-2016 Guillaume LE VAILLANT

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


(in-package :ironclad)


(defgeneric ies-encrypt-stream (public-key cipher-name digest-name input-stream output-stream
                                &key kdf-iterations shared1 shared2))
(defgeneric ies-decrypt-stream (private-key cipher-name digest-name input-stream output-stream
                                &key kdf-iterations shared1 shared2))

(defun ies-encrypt-stream-common (parameter shared-secret kdf-salt kdf-iterations cipher-name digest-name input output
                                  &key shared1 shared2)
  (let* ((passphrase (if shared1
                         (concatenate '(simple-array (unsigned-byte 8) (*)) shared-secret shared1)
                         shared-secret))
         (cipher-key-length (apply #'max (key-lengths cipher-name)))
         (keys (pbkdf2-derive-key digest-name
                                  passphrase
                                  kdf-salt
                                  kdf-iterations
                                  (+ (* 2 cipher-key-length) (block-length cipher-name))))
         (enc-key (subseq keys 0 cipher-key-length))
         (mac-key (subseq keys cipher-key-length (* 2 cipher-key-length)))
         (iv (subseq keys (* 2 cipher-key-length)))
         (cipher (if (= 1 (block-length cipher-name))
                     (make-cipher cipher-name
                                  :key enc-key
                                  :mode :stream)
                     (make-cipher cipher-name
                                  :key enc-key
                                  :mode :ctr
                                  :initialization-vector iv)))
         (mac (make-hmac mac-key digest-name)))
    (write-sequence kdf-salt output)
    (write-sequence parameter output)
    (do* ((buffer (make-array 32768 :element-type '(unsigned-byte 8)))
          (len (read-sequence buffer input)
               (read-sequence buffer input)))
         ((zerop len))
      (encrypt-in-place cipher buffer :end len)
      (update-hmac mac buffer :end len)
      (write-sequence buffer output :end len))
    (when shared2
      (update-hmac mac shared2))
    (write-sequence (hmac-digest mac) output))
  t)

(defun ies-decrypt-stream-common (parameter shared-secret kdf-salt kdf-iterations cipher-name digest-name input output
                                  &key shared1 shared2)
  (let* ((passphrase (if shared1
                         (concatenate '(simple-array (unsigned-byte 8) (*)) shared-secret shared1)
                         shared-secret))
         (cipher-key-length (apply #'max (key-lengths cipher-name)))
         (keys (pbkdf2-derive-key digest-name
                                  passphrase
                                  kdf-salt
                                  kdf-iterations
                                  (+ (* 2 cipher-key-length) (block-length cipher-name))))
         (enc-key (subseq keys 0 cipher-key-length))
         (mac-key (subseq keys cipher-key-length (* 2 cipher-key-length)))
         (iv (subseq keys (* 2 cipher-key-length)))
         (cipher (if (= 1 (block-length cipher-name))
                     (make-cipher cipher-name
                                  :key enc-key
                                  :mode :stream)
                     (make-cipher cipher-name
                                  :key enc-key
                                  :mode :ctr
                                  :initialization-vector iv)))
         (mac (make-hmac mac-key digest-name))
         (mac-length (digest-length digest-name))
         (buffer (make-array (+ 32768 mac-length) :element-type '(unsigned-byte 8))))
    (unless (= (read-sequence buffer input :end mac-length) mac-length)
      (error "Input stream too short"))
    (do ((len (- (read-sequence buffer input :start mac-length) mac-length)
              (- (read-sequence buffer input :start mac-length) mac-length)))
        ((zerop len))
      (update-hmac mac buffer :end len)
      (decrypt-in-place cipher buffer :end len)
      (write-sequence buffer output :end len)
      (replace buffer buffer :end1 mac-length :start2 len))
    (when shared2
      (update-hmac mac shared2))
    (unless (equalp (hmac-digest mac) (subseq buffer 0 mac-length))
      (error "Invalid MAC")))
  t)

(defmethod ies-encrypt-stream ((public-key curve25519-public-key) cipher-name digest-name input output
                               &key (kdf-iterations 10000) shared1 shared2)
  (let* ((prng (or *prng* (make-prng :fortuna :seed :random)))
         (kdf-salt (random-data 32 prng)))
    (multiple-value-bind (sk pk)
        (generate-key-pair :curve25519)
      (let ((p (curve25519-key-y pk))
            (s (diffie-hellman sk public-key)))
        (ies-encrypt-stream-common p s kdf-salt kdf-iterations cipher-name digest-name input output
                                   :shared1 shared1 :shared2 shared2)))))

(defmethod ies-decrypt-stream ((private-key curve25519-private-key) cipher-name digest-name input output
                               &key (kdf-iterations 10000) shared1 shared2)
  (let* ((kdf-salt (make-array 32 :element-type '(unsigned-byte 8)))
         (parameter-length (/ +curve25519-bits+ 8))
         (p (make-array parameter-length :element-type '(unsigned-byte 8))))
    (unless (= (read-sequence kdf-salt input) 32)
      (error "Input stream too short"))
    (unless (= (read-sequence p input) parameter-length)
      (error "Input stream too short"))
    (let* ((pk (make-public-key :curve25519 :y p))
           (s (diffie-hellman private-key pk)))
      (ies-decrypt-stream-common p s kdf-salt kdf-iterations cipher-name digest-name input output
                                 :shared1 shared1 :shared2 shared2))))

(defmethod ies-encrypt-stream ((public-key elgamal-public-key) cipher-name digest-name input output
                               &key (kdf-iterations 10000) shared1 shared2)
  (let* ((prng (or *prng* (make-prng :fortuna :seed :random)))
         (kdf-salt (random-data 32 prng))
         (p (elgamal-key-p public-key))
         (pbits (integer-length p))
         (g (elgamal-key-g public-key))
         (y (elgamal-key-y public-key))
         (r (+ 2 (strong-random (- p 3) prng)))
         (k (integer-to-octets (expt-mod g r p) :n-bits pbits))
         (s (integer-to-octets (expt-mod y r p) :n-bits pbits)))
    (ies-encrypt-stream-common k s kdf-salt kdf-iterations cipher-name digest-name input output
                               :shared1 shared1 :shared2 shared2)))

(defmethod ies-decrypt-stream ((private-key elgamal-private-key) cipher-name digest-name input output
                               &key (kdf-iterations 10000) shared1 shared2)
  (let* ((kdf-salt (make-array 32 :element-type '(unsigned-byte 8)))
         (p (elgamal-key-p private-key))
         (pbits (integer-length p))
         (g (elgamal-key-g private-key))
         (x (elgamal-key-x private-key))
         (parameter-length (/ +curve25519-bits+ 8))
         (k (make-array parameter-length :element-type '(unsigned-byte 8))))
    (unless (= (read-sequence kdf-salt input) 32)
      (error "Input stream too short"))
    (unless (= (read-sequence k input) parameter-length)
      (error "Input stream too short"))
    (let* ((a (octets-to-integer k))
           (s (integer-to-octets (expt-mod a x p) :n-bits pbits)))
      (ies-decrypt-stream-common k s kdf-salt kdf-iterations cipher-name digest-name input output
                                 :shared1 shared1 :shared2 shared2))))

(defmethod ies-encrypt-stream ((passphrase simple-array) cipher-name digest-name input output
                               &key (kdf-iterations 10000) shared1 shared2)
  (let* ((prng (or *prng* (make-prng :fortuna :seed :random)))
         (kdf-salt (random-data 32 prng))
         (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (ies-encrypt-stream-common empty passphrase kdf-salt kdf-iterations cipher-name digest-name input output
                               :shared1 shared1 :shared2 shared2)))

(defmethod ies-decrypt-stream ((passphrase simple-array) cipher-name digest-name input output
                             &key (kdf-iterations 10000) shared1 shared2)
  (let ((kdf-salt (make-array 32 :element-type '(unsigned-byte 8)))
        (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (unless (= (read-sequence kdf-salt input) 32)
      (error "Input stream too short"))
    (ies-decrypt-stream-common empty passphrase kdf-salt kdf-iterations cipher-name digest-name input output
                               :shared1 shared1 :shared2 shared2)))
