# This file is part of iescrypt
# Copyright 2015-2018 Guillaume LE VAILLANT
# Distributed under the GNU GPL v3 or later.
# See the file LICENSE for terms of use and distribution.

LISP ?= sbcl
asdf_system := iescrypt
lisp_sources = ${asdf_system}.asd src/lisp/iescrypt.lisp
c_headers = src/c/monocypher.h src/c/sha512.h
c_sources = src/c/iescrypt.c src/c/monocypher.c src/c/sha512.c

all: iescrypt iescrypt-c

iescrypt: ${lisp_sources}
	${LISP} \
		--load "${asdf_system}.asd" \
		--eval "(asdf:make \"${asdf_system}\")" \
		--eval "(uiop:quit)"

iescrypt-c: ${c_headers} ${c_sources}
	${CC} -O2 -march=native -DEDD25519_SHA512 -o iescrypt-c ${c_sources}

clean:
	rm -f iescrypt iescrypt-c
