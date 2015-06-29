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


(defpackage clcrypt
  (:use cl qt)
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
  (:export gui))
