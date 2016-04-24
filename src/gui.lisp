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


(in-package clcrypt)


(named-readtables:in-readtable :qt)

(defclass passphrase-dialog ()
  ((passphrase :accessor passphrase)
   (passphrase-check :accessor passphrase-check))
  (:metaclass qt-class)
  (:qt-superclass "QDialog")
  (:signals ("valid-passphrase(QString)"))
  (:slots ("validate-passphrase()" validate-passphrase)
          ("cancel-passphrase()" cancel-passphrase)))

(defmethod validate-passphrase ((instance passphrase-dialog))
  (if (and (passphrase-check instance)
           (not (equalp (#_text (passphrase instance))
                        (#_text (passphrase-check instance)))))
      (progn
        (let ((msgbox (#_new QMessageBox instance)))
          (#_setText msgbox "The two passphrases entered are different.")
          (#_setStandardButtons msgbox (#_QMessageBox::Ok))
          (#_setIcon msgbox (#_QMessageBox::Critical))
          (#_exec msgbox)))
      (progn
        (emit-signal instance "valid-passphrase(QString)" (#_text (passphrase instance)))
        (#_close instance))))

(defmethod initialize-instance :after ((instance passphrase-dialog) &key check parent)
  (if parent
      (new instance parent)
      (new instance))
  (let ((ok-button (#_new QPushButton "Ok"))
        (cancel-button (#_new QPushButton "Cancel"))
        (layout (#_new QVBoxLayout))
        (layout-linedits (#_new QGridLayout))
        (layout-buttons (#_new QHBoxLayout)))

    (setf (passphrase instance) (#_new QLineEdit))
    (#_setEchoMode (passphrase instance) (#_QLineEdit::Password))
    (if check
        (progn
          (setf (passphrase-check instance) (#_new QLineEdit))
          (#_setEchoMode (passphrase-check instance) (#_QLineEdit::Password)))
        (setf (passphrase-check instance) nil))

    (connect ok-button "clicked()" instance "validate-passphrase()")
    (connect cancel-button "clicked()" instance "close()")

    (#_addWidget layout-linedits (#_new QLabel "Enter passphrase:") 0 0)
    (#_addWidget layout-linedits (passphrase instance) 0 1)
    (when check
      (#_addWidget layout-linedits (#_new QLabel "Enter passphrase again:") 1 0)
      (#_addWidget layout-linedits (passphrase-check instance) 1 1))
    (#_addStretch layout-buttons)
    (#_addWidget layout-buttons ok-button)
    (#_addStretch layout-buttons)
    (#_addWidget layout-buttons cancel-button)
    (#_addStretch layout-buttons)
    (#_addLayout layout layout-linedits)
    (#_addLayout layout layout-buttons)
    (#_setLayout instance layout)))

(defclass main-window ()
  ((input-file :accessor input-file)
   (output-file :accessor output-file)
   (passphrase :accessor passphrase))
  (:metaclass qt-class)
  (:qt-superclass "QWidget")
  (:slots ("browse-input()" browse-input)
          ("browse-output()" browse-output)
          ("set-passphrase(QString)" set-passphrase)
          ("encrypt()" encryption)
          ("decrypt()" decryption)))

(defmethod browse-input ((instance main-window))
  (#_setText (input-file instance) (#_QFileDialog::getOpenFileName)))

(defmethod browse-output ((instance main-window))
  (#_setText (output-file instance) (#_QFileDialog::getSaveFileName)))

(defmethod set-passphrase ((instance main-window) passphrase)
  (setf (passphrase instance) passphrase))

(defmethod encryption ((instance main-window))
  (let ((input-file (#_text (input-file instance)))
        (output-file (#_text (output-file instance)))
        (passphrase-dialog (make-instance 'passphrase-dialog :check t :parent instance))
        passphrase
        error)

    (setf (passphrase instance) nil)
    (connect passphrase-dialog "valid-passphrase(QString)" instance "set-passphrase(QString)")
    (#_exec passphrase-dialog)
    (setf passphrase (passphrase instance))
    (when passphrase
      (#_setWindowTitle instance "clcrypt - encrypting...")
      (#_repaint instance)
      (handler-case
          (encrypt-file input-file output-file :passphrase passphrase)
        (t (err) (setf error (format nil "~a" err))))
      (#_setWindowTitle instance "clcrypt")
      (#_repaint instance)
      (let ((msgbox (#_new QMessageBox instance)))
        (if error
            (progn
              (#_setText msgbox "The encryption failed.")
              (#_setInformativeText msgbox error)
              (#_setIcon msgbox (#_QMessageBox::Critical))
              (#_setStandardButtons msgbox (#_QMessageBox::Ok)))
            (progn
              (#_setText msgbox "The encryption succeeded.")
              (#_setIcon msgbox (#_QMessageBox::Information))
              (#_setStandardButtons msgbox (#_QMessageBox::Ok))))
        (#_exec msgbox)))))

(defmethod decryption ((instance main-window))
  (let ((input-file (#_text (input-file instance)))
        (output-file (#_text (output-file instance)))
        (passphrase-dialog (make-instance 'passphrase-dialog :parent instance))
        passphrase
        error)

    (setf (passphrase instance) nil)
    (connect passphrase-dialog "valid-passphrase(QString)" instance "set-passphrase(QString)")
    (#_exec passphrase-dialog)
    (setf passphrase (passphrase instance))
    (when passphrase
      (#_setWindowTitle instance "clcrypt - decrypting...")
      (#_repaint instance)
      (handler-case
          (decrypt-file input-file output-file :passphrase passphrase)
        (t (err) (setf error (format nil "~a" err))))
      (#_setWindowTitle instance "clcrypt")
      (#_repaint instance)
      (let ((msgbox (#_new QMessageBox instance)))
        (if error
            (progn
              (#_setText msgbox "The decryption failed.")
              (#_setInformativeText msgbox error)
              (#_setIcon msgbox (#_QMessageBox::Critical))
              (#_setStandardButtons msgbox (#_QMessageBox::Ok)))
            (progn
              (#_setText msgbox "The decryption succeeded.")
              (#_setIcon msgbox (#_QMessageBox::Information))
              (#_setStandardButtons msgbox (#_QMessageBox::Ok))))
        (#_exec msgbox)))))

(defmethod initialize-instance :after ((instance main-window) &key)
  (new instance)
  (let ((browse-in-button (#_new QPushButton "Browse..."))
        (browse-out-button (#_new QPushButton "Browse..."))
        (encrypt-button (#_new QPushButton "Encrypt"))
        (decrypt-button (#_new QPushButton "Decrypt"))
        (layout (#_new QVBoxLayout))
        (layout-linedits (#_new QGridLayout))
        (layout-buttons (#_new QHBoxLayout)))

    (setf (input-file instance) (#_new QLineEdit)
          (output-file instance) (#_new QLineEdit)
          (passphrase instance) nil)
    

    (connect browse-in-button "clicked()" instance "browse-input()")
    (connect browse-out-button "clicked()" instance "browse-output()")
    (connect encrypt-button "clicked()" instance "encrypt()")
    (connect decrypt-button "clicked()" instance "decrypt()")

    (#_setWindowTitle instance "clcrypt")
    (#_addWidget layout-linedits (#_new QLabel "Input file:") 0 0)
    (#_addWidget layout-linedits (input-file instance) 0 1)
    (#_addWidget layout-linedits browse-in-button 0 2)
    (#_addWidget layout-linedits (#_new QLabel "Output file:") 1 0)
    (#_addWidget layout-linedits (output-file instance) 1 1)
    (#_addWidget layout-linedits browse-out-button 1 2)
    (#_addStretch layout-buttons)
    (#_addWidget layout-buttons encrypt-button)
    (#_addStretch layout-buttons)
    (#_addWidget layout-buttons decrypt-button)
    (#_addStretch layout-buttons)
    (#_addLayout layout layout-linedits)
    (#_addLayout layout layout-buttons)
    (#_setLayout instance layout)
    (#_resize instance 400 100)))

(defun mk-qapplication (name &rest args)
  "A rewrite of QT:MAKE-QAPPLICATION to allow setting an application name other than 'argv0dummy'."
  (cond (*qapplication*)
        (t
         (ensure-smoke :qtcore)
         (ensure-smoke :qtgui)
         (let ((instance (#_QCoreApplication::instance)))
           (setf *qapplication*
                 (if (null-qobject-p instance)
                     (qt::%make-qapplication (cons name args))
                     instance))))))

(defun gui (&rest args)
  (declare (ignore args))
  (mk-qapplication "clcrypt")
  (with-main-window (window (make-instance 'main-window))))
