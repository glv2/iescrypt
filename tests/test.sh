#!/bin/bash

SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
IESCRYPT=$(cd "${SCRIPTDIR}" && pwd)/../iescrypt
FAILURE=0
CURRDIR=${PWD}
WORKDIR=$(mktemp -d)

cd "${WORKDIR}"
if test ! -d "${WORKDIR}";
then
    echo "failed to create work directory"
    exit 1
fi

if ${IESCRYPT} gen-enc ekey && test -f ekey && test -f ekey.pub;
then
    echo "gen-enc test succeeded"
else
    echo "gen-enc test failed"
    FAILURE=1
fi

if ${IESCRYPT} gen-sig skey && test -f skey && test -f skey.pub;
then
    echo "gen-sig test succeeded"
else
    echo "gen-sig test failed"
    FAILURE=1
fi

echo "aZerty6" > passphrase

dd if=/dev/urandom bs=1M count=100 > m.dat 2> /dev/null

if ${IESCRYPT} penc m.dat c.dat passphrase && test -f c.dat && ${IESCRYPT} pdec c.dat d.dat passphrase && test -f d.dat && diff -q m.dat d.dat;
then
    echo "penc/pdec test succeeded"
else
    echo "penc/pdec test failed"
    FAILURE=1
fi

if ${IESCRYPT} enc m.dat c.dat ekey.pub && test -f c.dat && ${IESCRYPT} dec c.dat d.dat ekey && test -f d.dat && diff -q m.dat d.dat;
then
    echo "enc/dec test succeeded"
else
    echo "enc/dec test failed"
    FAILURE=1
fi

if ${IESCRYPT} sig m.dat m.dat.sig skey && test -f m.dat.sig && test -n "$(${IESCRYPT} ver m.dat m.dat.sig skey.pub | grep 'Valid signature')";
then
    echo "sig/ver test succeeded"
else
    echo "sig/ver test failed"
    FAILURE=1
fi

if ${IESCRYPT} sig-penc m.dat c.dat skey passphrase && test -f c.dat && test -n "$(${IESCRYPT} pdec-ver c.dat d.dat passphrase skey.pub | grep 'Valid signature')" && diff -q m.dat d.dat;
then
    echo "sig-penc/pdec-ver test succeeded"
else
    echo "sig-penc/pdec-ver test failed"
    FAILURE=1
fi

if ${IESCRYPT} sig-enc m.dat c.dat skey ekey.pub && test -f c.dat && test -n "$(${IESCRYPT} dec-ver c.dat d.dat ekey skey.pub | grep 'Valid signature')" && diff -q m.dat d.dat;
then
    echo "sig-enc/dec-ver test succeeded"
else
    echo "sig-enc/dec-ver test failed"
    FAILURE=1
fi

echo
cd "${PWD}"
if test ${FAILURE} -eq 1;
then
    echo "FAILURE"
    exit 1
else
    rm -fr "${WORKDIR}"
    echo "OK"
fi
