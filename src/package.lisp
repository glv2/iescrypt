;;;; -*- mode: lisp; indent-tabs-mode: nil -*-

#|
This file is part of iescrypt, a program for encrypting, decrypting
and signing files.

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


(defpackage iescrypt
  (:use cl)
  (:import-from archive
                create-entry-from-pathname
                do-archive-entries
                entry-regular-file-p
                entry-stream
                finalize-archive
                name
                with-open-archive
                write-entry-to-archive)
  (:import-from babel
                string-to-octets)
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
  (:import-from uiop
                copy-stream-to-stream
                file-exists-p)
  (:export decrypt-and-verify-file-signature
           decrypt-file
           encrypt-file
           main
           make-encryption-key-pair
           make-signature-key-pair
           read-passphrase
           read-private-key
           read-public-key
           read-signature
           sign-and-encrypt-file
           sign-file
           verify-file-signature))
