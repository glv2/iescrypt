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


(defpackage clcrypt
  (:use cl)
  (:import-from ironclad
                byte-array-to-hex-string
                curve25519-key-x
                curve25519-key-y
                digest-file
                ed25519-key-x
                ed25519-key-y
                generate-key-pair
                ies-decrypt-stream
                ies-encrypt-stream
                make-private-key
                make-public-key
                sign-message
                verify-signature)
  (:import-from babel
                string-to-octets)
  (:export encrypt-file
           decrypt-file
           sign-file
           verify-file-signature
           make-encryption-key-pair
           make-signature-key-pair
           read-public-key
           read-private-key
           read-passphrase
           main))
