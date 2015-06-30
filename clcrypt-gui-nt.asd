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


(defsystem clcrypt-gui-nt
  :name clcrypt
  :description "Tool to encrypt and decrypt files"
  :version "1.0"
  :author "Guillaume LE VAILLANT"
  :license "GPL-3"
  :depends-on (babel ironclad qt)
  :components ((:module "src"
                        :components ((:file "clcrypt-nt" :depends-on ("common" "package-gui-nt"))
                                     (:file "common" :depends-on ("package-gui-nt"))
                                     (:file "gui" :depends-on ("clcrypt-nt" "package-gui-nt"))
                                     (:file "package-gui-nt")))))
