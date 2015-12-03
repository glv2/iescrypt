# clcrypt

The clcrypt program encrypts and decrypts files.

There are two versions of it:

* console
* GUI

## Details

* The key for the cipher (threefish512) and the message authentication
codes (skein-mac512) is derived from a salt and a passphrase (pbkdf2, 1000
iterations of skein512).
* The first mac is computed on the cipher tweak and the initialization vector.
* The cleartext is encrypted by the cipher in counter mode.
* A mac is computed on the ciphertext.

Format of the encrypted file:

    | salt (16 B) | tweak (16 B) | iv (64 B) | mac (64 B) | ciphertext | mac (64 B) |

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
    (clcrypt:encrypt-file "cleartext.file" "ciphertext.file" "passphrase")

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
