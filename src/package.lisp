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
  (:use cl)
  (:import-from babel
                string-to-octets)
  #-linux (:import-from inferior-shell
                        run/s)
  (:import-from ironclad
                block-length
                decrypt-in-place
                digest-length
                encrypt-in-place
                make-cipher
                make-prng
                make-skein-mac
                pbkdf2-hash-password
                random-data
                skein-mac-digest
                update-skein-mac)
  (:import-from lparallel
                *kernel*
                kernel-worker-count
                make-channel
                make-kernel
                receive-result
                submit-task
                try-receive-result)
  (:export encrypt-file
           decrypt-file
           main))
