#!/bin/bash

SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
IESCRYPT=$(cd "${SCRIPTDIR}" && pwd)/../iescrypt-c
FAILURE=0
CURRDIR=${PWD}
WORKDIR=$(mktemp -d)

cd "${WORKDIR}"
if test ! -d "${WORKDIR}";
then
    echo "failed to create work directory"
    exit 1
fi

rm -f ekey ekey.pub
if ${IESCRYPT} gen-enc ekey && test -f ekey && test -f ekey.pub;
then
    echo "gen-enc test succeeded"
else
    echo "gen-enc test failed"
    FAILURE=1
fi

rm -f skey skey.pub
if ${IESCRYPT} gen-sig skey && test -f skey && test -f skey.pub;
then
    echo "gen-enc test succeeded"
else
    echo "gen-enc test failed"
    FAILURE=1
fi

echo "aZerty6" > passphrase

dd if=/dev/urandom bs=1M count=100 > m.dat 2> /dev/null

rm -f c.dat d.dat
if ${IESCRYPT} penc m.dat c.dat passphrase && test -f c.dat && ${IESCRYPT} pdec c.dat d.dat passphrase && test -f d.dat && diff -q m.dat d.dat;
then
    echo "penc/pdec test succeeded"
else
    echo "penc/pdec test failed"
    FAILURE=1
fi

rm -f c.dat d.dat
if ${IESCRYPT} enc m.dat c.dat ekey.pub && test -f c.dat && ${IESCRYPT} dec c.dat d.dat ekey && test -f d.dat && diff -q m.dat d.dat;
then
    echo "enc/dec test succeeded"
else
    echo "enc/dec test failed"
    FAILURE=1
fi

rm -f m.dat.sig
if ${IESCRYPT} sig m.dat m.dat.sig skey && test -f m.dat.sig && test -n "$(${IESCRYPT} ver m.dat m.dat.sig skey.pub | grep 'Valid signature')";
then
    echo "sig/ver test succeeded"
else
    echo "sig/ver test failed"
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
