;;;; This file is part of iescrypt
;;;; Copyright 2015-2018 Guillaume LE VAILLANT
;;;; Distributed under the GNU GPL v3 or later.
;;;; See the file LICENSE for terms of use and distribution.


(cl:in-package :asdf-user)

;; Redefine 'program-op' to actvate compression
#+sbcl
(defmethod perform ((o program-op) (c system))
  (uiop:dump-image (output-file o c) :executable t :compression t))

(defsystem "iescrypt"
  :name "iescrypt"
  :description "Tool to encrypt and decrypt files"
  :version "1.0"
  :author "Guillaume LE VAILLANT"
  :license "GPL-3"
  :depends-on ("archive" "babel" "ironclad" "uiop")
  :build-operation program-op
  :build-pathname "iescrypt"
  :entry-point "iescrypt:main"
  :components ((:module "src"
                :components ((:file "iescrypt")))))
