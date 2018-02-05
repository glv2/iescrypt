# This file is part of iescrypt
# Copyright 2015-2018 Guillaume LE VAILLANT
# Distributed under the GNU GPL v3 or later.
# See the file LICENSE for terms of use and distribution.

LISP ?= sbcl
asdf_system := iescrypt

all:
	${LISP} \
		--load "${asdf_system}.asd" \
		--eval "(asdf:make \"${asdf_system}\")" \
		--eval "(uiop:quit)"

clean:
	rm -f iescrypt
