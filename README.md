# clcrypt

The clcrypt program encrypts and decrypts files.

It can be used in two modes:

* Symmetric mode
* Public key mode

There are two versions of it:

* Console
* GUI

## Symmetric mode

Format of the encrypted file in symmetric mode:

    | salt (32 B) | tweak (16 B) | iv (64 B) | ciphertext | mac (64 B) |

The keys for the cipher (threefish512) and the message authentication
code (hmac using skein512) are derived from a salt and a
passphrase (pbkdf2, 1000 iterations of skein512).
The cleartext is encrypted by the cipher in counter mode.
The mac is computed on the ciphertext.

## Public key mode

Format of the encrypted file in public key mode:

    | parameter (32 B) | ciphertext | mac (64 B) |

The keys for the cipher (threefish512) and the message authentication
code (hmac using skein512) are derived from a parameter and a
key (curve25519).
The cleartext is encrypted by the cipher in counter mode.
The mac is computed on the ciphertext.

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

To encrypt and decrypt a file in symmetric mode:

    (clcrypt:encrypt-file "clear.file" "cipher.file" :passphrase "passphrase")
    (clcrypt:decrypt-file "cipher.file" "clear.file" :passphrase "passphrase")

To encrypt and decrypt a file in public key mode:

    (clcrypt:make-key-pair "key")
    (let ((pubkey (clcrypt:read-public-key "key.pub")
          (privkey (clcrypt:read-private-key "key"))))
      (clcrypt:encrypt-file "clear.file" "cipher.file" :public-key pubkey)
      (clcrypt:decrypt-file "cipher.file" "clear.file" :private-key privkey))

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
