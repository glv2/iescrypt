;;;; This file is part of iescrypt
;;;; Copyright 2015-2018 Guillaume LE VAILLANT
;;;; Distributed under the GNU GPL v3 or later.
;;;; See the file LICENSE for terms of use and distribution.


(cl:in-package :asdf-user)

;; Redefine 'program-op' to actvate compression
#+(and sbcl sb-core-compression)
(defmethod perform ((o program-op) (c system))
  (uiop:dump-image (output-file o c) :executable t :compression t))

(defsystem "iescrypt"
  :name "iescrypt"
  :description "Tool to encrypt and decrypt files"
  :version "2.0"
  :author "Guillaume LE VAILLANT"
  :license "GPL-3"
  :depends-on ("archive" "babel" "ironclad" "uiop")
  :in-order-to ((test-op (test-op "iescrypt/tests")))
  :build-operation program-op
  :build-pathname "iescrypt"
  :entry-point "iescrypt:main"
  :components ((:module "src"
                :components ((:module "lisp"
                              :components ((:file "iescrypt")))))))

(defsystem "iescrypt/tests"
  :name "iescrypt/tests"
  :description "Tests for iescrypt"
  :version "2.0"
  :author "Guillaume LE VAILLANT"
  :license "GPL-3"
  :depends-on ("fiveam" "iescrypt" "uiop")
  :in-order-to ((test-op (load-op "iescrypt/tests")))
  :perform (test-op (o s)
             (let ((tests (uiop:find-symbol* 'iescrypt-tests :iescrypt/tests)))
               (uiop:symbol-call :fiveam 'run! tests)))
  :components ((:module "tests"
                :components ((:file "tests")))))
