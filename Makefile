# This file is part of iescrypt
# Copyright 2015-2020 Guillaume LE VAILLANT
# Distributed under the GNU GPL v3 or later.
# See the file LICENSE for terms of use and distribution.

LISP ?= sbcl
lisp_sources = \
	iescrypt.asd \
	src/lisp/iescrypt.lisp
CFLAGS ?= -O3 -march=native -fPIC
c_headers = \
	src/c/microtar/microtar.h \
	src/c/monocypher/monocypher.h \
	src/c/monocypher/sha512.h
c_sources = \
	src/c/iescrypt.c \
	src/c/microtar/microtar.c \
	src/c/monocypher/monocypher.c \
	src/c/monocypher/sha512.c

all: iescrypt iescrypt-c

iescrypt: ${lisp_sources}
	${LISP} \
		--load "iescrypt.asd" \
		--eval "(asdf:make \"iescrypt\")" \
		--eval "(uiop:quit)"

iescrypt-c: ${c_headers} ${c_sources}
	${CC} ${CFLAGS} -DED25519_SHA512 -o iescrypt-c ${c_sources}

check: iescrypt iescrypt-c
	cd tests && ./test-iescrypt.sh ../iescrypt
	cd tests && ./test-iescrypt.sh ../iescrypt-c

clean:
	rm -f iescrypt iescrypt-c
