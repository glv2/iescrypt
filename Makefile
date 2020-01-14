# This file is part of iescrypt
# Copyright 2015-2020 Guillaume LE VAILLANT
# Distributed under the GNU GPL v3 or later.
# See the file LICENSE for terms of use and distribution.

LISP = sbcl

CC = gcc
CFLAGS ?= -O3 -march=native -fPIC


all: iescrypt iescrypt-c


iescrypt: iescrypt.asd src/iescrypt.lisp
	$(LISP) \
		--eval "(require :asdf)" \
		--eval '(asdf:load-asd (truename "iescrypt.asd"))' \
		--eval '(asdf:make "iescrypt")' \
		--eval "(uiop:quit)"


iescrypt-c: src/iescrypt.o external/microtar/libmicrotar.a external/monocypher/lib/libmonocypher.a
	$(CC) $(LDFLAGS) -o $@ $^

src/iescrypt.o: src/iescrypt.c
	$(CC) \
		$(CFLAGS) \
		-I external/microtar \
		-I external/monocypher/src \
		-I external/monocypher/src/optional \
		-o $@ -c $<

external/microtar/libmicrotar.a:
	$(MAKE) -C external/microtar static-library

external/monocypher/lib/libmonocypher.a:
	$(MAKE) -C external/monocypher USE_ED25519=true static-library


check: check-lisp check-c

check-lisp: iescrypt
	tests/test-iescrypt.sh iescrypt

check-c: iescrypt-c
	tests/test-iescrypt.sh iescrypt-c

clean:
	$(MAKE) -C external/microtar $@
	$(MAKE) -C external/monocypher $@
	rm -f src/iescrypt.o

mrproper: clean
	rm -f iescrypt iescrypt-c
