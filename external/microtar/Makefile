# This file is part of iescrypt
# Copyright 2020 Guillaume LE VAILLANT
# Distributed under the GNU GPL v3 or later.
# See the file LICENSE for terms of use and distribution.

CC = gcc
AR = ar
CFLAGS ?= -O3 -march=native -fPIC

static-library: libmicrotar.a

libmicrotar.a: microtar.c microtar.h
	$(CC) $(CFLAGS) -o microtar.o -c $<
	$(AR) cr $@ microtar.o

clean:
	rm -f libmicrotar.a microtar.o
