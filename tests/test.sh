#!/bin/bash

FAILURE=0

rm -f ekey ekey.pub
if iescrypt gen-enc ekey && test -f ekey && test -f ekey.pub;
then
    echo "gen-enc test succeeded"
else
    echo "gen-enc test failed"
    FAILURE=1
fi

rm -f skey skey.pub
if iescrypt gen-sig skey && test -f skey && test -f skey.pub;
then
    echo "gen-enc test succeeded"
else
    echo "gen-enc test failed"
    FAILURE=1
fi

echo "aZerty6" > passphrase

dd if=/dev/urandom bs=1M count=100 > m.dat 2> /dev/null

rm -f c.dat d.dat
if iescrypt penc m.dat c.dat passphrase && test -f c.dat && iescrypt pdec c.dat d.dat passphrase && test -f d.dat && diff -q m.dat d.dat;
then
    echo "penc/pdec test succeeded"
else
    echo "penc/pdec test failed"
    FAILURE=1
fi

rm -f c.dat d.dat
if iescrypt enc m.dat c.dat ekey.pub && test -f c.dat && iescrypt dec c.dat d.dat ekey && test -f d.dat && diff -q m.dat d.dat;
then
    echo "enc/dec test succeeded"
else
    echo "enc/dec test failed"
    FAILURE=1
fi

rm -f m.dat.sig
if iescrypt sig m.dat m.dat.sig skey && test -f m.dat.sig && test -n "$(iescrypt ver m.dat m.dat.sig skey.pub | grep 'Valid signature')";
then
    echo "sig/ver test succeeded"
else
    echo "sig/ver test failed"
    FAILURE=1
fi

rm -f c.dat d.dat m.dat.sig
if iescrypt sig-penc m.dat c.dat skey passphrase && test -f c.dat && test -n "$(iescrypt pdec-ver c.dat d.dat passphrase skey.pub | grep 'Valid signature')" && diff -q m.dat d.dat;
then
    echo "sig-penc/pdec-ver test succeeded"
else
    echo "sig-penc/pdec-ver test failed"
    FAILURE=1
fi

rm -f c.dat d.dat m.dat.sig
if iescrypt sig-enc m.dat c.dat skey ekey.pub && test -f c.dat && test -n "$(iescrypt dec-ver c.dat d.dat ekey skey.pub | grep 'Valid signature')" && diff -q m.dat d.dat;
then
    echo "sig-enc/dec-ver test succeeded"
else
    echo "sig-enc/dec-ver test failed"
    FAILURE=1
fi

echo
if test ${FAILURE} -eq 1;
then
    echo "FAILURE"
else
    rm -f ekey ekey.pub skey skey.pub passphrase m.dat c.dat d.dat m.dat.sig
    echo "OK"
fi