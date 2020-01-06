#!/usr/bin/env bash

CURRDIR=${PWD}
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
SCRIPTDIR=$(cd "${SCRIPTDIR}" && pwd)
FAILURE=0
WORKDIR=$(mktemp -d)
if test -z "$1";
then
    IESCRYPT="${SCRIPTDIR}/../iescrypt"
else
    IESCRYPTDIR=$(dirname "$1")
    IESCRYPTDIR=$(cd "${IESCRYPTDIR}" && pwd)
    IESCRYPT="${IESCRYPTDIR}/$(basename $1)"
fi
if test ! -f "${IESCRYPT}";
then
    echo "failed to find iescrypt program"
    exit 1
fi

cd "${WORKDIR}"
if test ! -d "${WORKDIR}";
then
    echo "failed to create work directory"
    exit 1
fi
cp "${SCRIPTDIR}/ekey" "${WORKDIR}"
cp "${SCRIPTDIR}/ekey.pub" "${WORKDIR}"
cp "${SCRIPTDIR}/skey" "${WORKDIR}"
cp "${SCRIPTDIR}/skey.pub" "${WORKDIR}"
cp "${SCRIPTDIR}/message" "${WORKDIR}"
cp "${SCRIPTDIR}/passphrase" "${WORKDIR}"
cp "${SCRIPTDIR}/signature" "${WORKDIR}"
cp "${SCRIPTDIR}/ciphertext-key" "${WORKDIR}"
cp "${SCRIPTDIR}/ciphertext-passphrase" "${WORKDIR}"
cp "${SCRIPTDIR}/ciphertext-sig-key" "${WORKDIR}"
cp "${SCRIPTDIR}/ciphertext-sig-passphrase" "${WORKDIR}"
dd if=/dev/urandom bs=1M count=100 > m.dat 2> /dev/null

# Encryption key generation
if ${IESCRYPT} gen-enc enckey && test -f enckey && test -f enckey.pub;
then
    echo "gen-enc test succeeded"
else
    echo "gen-enc test failed"
    FAILURE=1
fi

# Signing key generation
if ${IESCRYPT} gen-sig sigkey && test -f sigkey && test -f sigkey.pub;
then
    echo "gen-sig test succeeded"
else
    echo "gen-sig test failed"
    FAILURE=1
fi

# Encryption with a passphrase
if ${IESCRYPT} pdec ciphertext-passphrase cleartext passphrase && test -f cleartext && diff -q message cleartext && ${IESCRYPT} penc m.dat c.dat passphrase && test -f c.dat && ${IESCRYPT} pdec c.dat d.dat passphrase && test -f d.dat && diff -q m.dat d.dat;
then
    echo "penc/pdec test succeeded"
else
    echo "penc/pdec test failed"
    FAILURE=1
fi

# Encryption with a key
if ${IESCRYPT} dec ciphertext-key cleartext ekey && test -f cleartext && diff -q message cleartext && ${IESCRYPT} enc m.dat c.dat ekey.pub && test -f c.dat && ${IESCRYPT} dec c.dat d.dat ekey && test -f d.dat && diff -q m.dat d.dat;
then
    echo "enc/dec test succeeded"
else
    echo "enc/dec test failed"
    FAILURE=1
fi

# Signature
if test -n "$(${IESCRYPT} ver message signature skey.pub | grep 'Valid signature')" && ${IESCRYPT} sig m.dat m.dat.sig skey && test -f m.dat.sig && test -n "$(${IESCRYPT} ver m.dat m.dat.sig skey.pub | grep 'Valid signature')";
then
    echo "sig/ver test succeeded"
else
    echo "sig/ver test failed"
    FAILURE=1
fi

# Signature and encryption with a passphrase
if test -n "$(${IESCRYPT} pdec-ver ciphertext-sig-passphrase cleartext passphrase skey.pub | grep 'Valid signature')" && diff -q message cleartext && ${IESCRYPT} sig-penc m.dat c.dat skey passphrase && test -f c.dat && test -n "$(${IESCRYPT} pdec-ver c.dat d.dat passphrase skey.pub | grep 'Valid signature')" && diff -q m.dat d.dat;
then
    echo "sig-penc/pdec-ver test succeeded"
else
    echo "sig-penc/pdec-ver test failed"
    FAILURE=1
fi

# Signature and encryption with a key
if test -n "$(${IESCRYPT} dec-ver ciphertext-sig-key cleartext ekey skey.pub | grep 'Valid signature')" && diff -q message cleartext && ${IESCRYPT} sig-enc m.dat c.dat skey ekey.pub && test -f c.dat && test -n "$(${IESCRYPT} dec-ver c.dat d.dat ekey skey.pub | grep 'Valid signature')" && diff -q m.dat d.dat;
then
    echo "sig-enc/dec-ver test succeeded"
else
    echo "sig-enc/dec-ver test failed"
    FAILURE=1
fi

echo
cd "${PWD}"
rm -fr "${WORKDIR}"
if test ${FAILURE} -eq 1;
then
    echo "FAILURE"
    exit 1
else
    echo "OK"
fi
