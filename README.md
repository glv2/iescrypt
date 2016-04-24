# clcrypt

The clcrypt program encrypts and decrypts files.

There are two versions of it:

* console
* GUI

## Details

Format of the encrypted file for symmetric mode:

    | salt (32 B) | tweak (16 B) | iv (64 B) | ciphertext | mac (64 B) |

Format of the encrypted file for public key mode:

    | parameter (32 B) | ciphertext | mac (64 B) |

* In symmetric mode, the keys for the cipher (threefish512) and the message
authentication code (skein-mac512) are derived from a salt and a
passphrase (pbkdf2, 1000 iterations of skein512).
* In public key mode, the keys for the cipher (threefish512) and the message
authentication code (skein-mac512) are derived from a parameter and a
key (curve25519).
* The cleartext is encrypted by the cipher in counter mode.
* The mac is computed on the ciphertext.

## Dependencies

* [sbcl](http://www.sbcl.org/) as Common Lisp implementation (it also works
with ccl, ecl and clisp, but 200 times slower).
* [ironclad](http://cliki.net/Ironclad)
* [babel](http://www.cliki.net/Babel)

If you want to use the Qt GUI, you will also need:

* [CommonQt](http://common-lisp.net/project/commonqt)

If you want to build clcrypt as an executable using the Makefile, you will
also need:

* [buildapp](http://www.cliki.net/Buildapp)

These libraries can be installed easily with [quicklisp](http://www.quicklisp.org).

## Examples

To encrypt a file:

    (require 'clcrypt)
    (clcrypt:encrypt-file "cleartext.file" "ciphertext.file" :passphrase "passphrase")

To start the GUI:

    (require 'clcrypt-gui)
    (clcrypt:gui)

## Executable

You can build executables using the Makefile (which uses buildapp).

To build all the versions:

    make

To build the console version:

    make clcrypt

To build the GUI version:

    make clcrypt-gui
