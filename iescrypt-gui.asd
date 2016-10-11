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


(defsystem iescrypt-gui
  :name iescrypt-gui
  :description "Tool to encrypt and decrypt files"
  :version "1.0"
  :author "Guillaume LE VAILLANT"
  :license "GPL-3"
  :depends-on (iescrypt qt)
  :components ((:module "src"
                :components ((:file "gui" :depends-on ("package-gui"))
                             (:file "package-gui")))))
