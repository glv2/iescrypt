# clcrypt

The clcrypt program encrypts and decrypts files.

There are several version of it:

* multi-threaded (default)
* multi-threaded + GUI
* single-threaded
* single-threaded + GUI

## Details

* The key for the cipher (threefish512) and the message authentication
codes (skein-mac512) is derived from a salt and a passphrase (pbkdf2, 1000
iterations of skein512).
* The first mac is computed on the cipher tweak and the initialization-vector.
* The cleartext is encrypted by the cipher in counter mode.
* A mac is computed on the ciphertext for each 1 MiB block of ciphertext.
* The last block of ciphertext can be smaller than 1 MiB (depending on the
size of the cleartext).

Format of the encrypted file:

    | salt (16 B) | tweak (16 B) | iv (64 B) | mac (64 B) | block | ... | block |

Format of a block:

    | cipertext (1 MiB) | mac (64 B) |

## Dependencies

* [sbcl](http://www.sbcl.org/) as Common Lisp implementation (it also works
with ccl, ecl and clisp, but 200 times slower).
* [ironclad](http://cliki.net/Ironclad)
* [babel](http://www.cliki.net/Babel)

If you want to use the multi-threaded version, you will also need:

* [lparallel](http://lparallel.org/)
* [trivial-features](http://www.cliki.net/trivial-features)

If you want to use the multi-threaded version on an operating system other than
GNU/Linux, you will also need:

* [inferior-shell](http://gitlab.common-lisp.net/qitab/inferior-shell)

If you want to use the Qt GUI, you will also need:

* [CommonQt](http://common-lisp.net/project/commonqt)

If you want to build clcrypt as an executable using the Makefile, you will
also need:

* [buildapp](http://www.cliki.net/Buildapp)

These libraries can be installed easily with [quicklisp](http://www.quicklisp.org).

## Examples

To encrypt a file with the multi-threaded version:

    (require 'clcrypt)
    (clcrypt:encrypt-file "cleartext.file" "ciphertext.file" "passphrase")

To decrypt a file with the single-threaded version:

    (require 'clcrypt-nt)
    (clcrypt:decrypt-file "ciphertext.file" "cleartext.file" "passphrase")

To start the GUI with the multi-threaded version:

    (require 'clcrypt-gui)
    (clcrypt:gui)

To start the GUI with the single-threaded version:

    (require 'clcrypt-gui-nt)
    (clcrypt:gui)

## Executable

You can build executables using the Makefile (which uses buildapp).

To build all the versions:

    make

To build the multi-threaded version:

    make clcrypt

To build the multi-threaded + GUI version:

    make clcrypt-gui

To build the single-threaded version:

    make clcrypt-nt

To build the single-threaded + GUI version:

    make clcrypt-gui-nt
