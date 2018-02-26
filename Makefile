# This file is part of iescrypt
# Copyright 2015-2018 Guillaume LE VAILLANT
# Distributed under the GNU GPL v3 or later.
# See the file LICENSE for terms of use and distribution.

LISP ?= sbcl
lisp_sources = \
	iescrypt.asd \
	src/lisp/iescrypt.lisp
c_headers = \
	src/c/microtar.h \
	src/c/monocypher.h \
	src/c/sha512.h
c_sources = \
	src/c/iescrypt.c \
	src/c/microtar.c \
	src/c/monocypher.c \
	src/c/sha512.c

all: iescrypt iescrypt-c

iescrypt: ${lisp_sources}
	${LISP} \
		--load "iescrypt.asd" \
		--eval "(asdf:make \"iescrypt\")" \
		--eval "(uiop:quit)"

iescrypt-c: ${c_headers} ${c_sources}
	${CC} -O3 -march=native -DED25519_SHA512 -o iescrypt-c ${c_sources}

clean:
	rm -f iescrypt iescrypt-c
