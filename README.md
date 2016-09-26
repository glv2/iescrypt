# clcrypt

The clcrypt program encrypts and decrypts files.

It can be used in two modes:

* Symmetric mode
* Public key mode

There are two versions of it:

* Console
* GUI

## Details

Format of the encrypted file:

    | salt | parameter | ciphertext | mac |

Size of the fields:
* salt: 32 bytes
* parameter: 32 bytes
* mac: 64 bytes

Encryption process:
* The cleartext is encrypted by the cipher (chacha) in counter mode.
* The mac (hmac using blake2) is computed on the ciphertext.
* The key and the initialization vector for the cipher and the key for the
message authentication code are derived from a salt and a passphrase in
symmetric mode, and from a salt, a parameter and an ECC key (curve25519) in
public key mode (pbkdf2, 10000 iterations of blake2). The parameter is not
used in symmetric mode, it just contains random data.


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

    (clcrypt:make-encryption-key-pair "key")
    (let ((pubkey (clcrypt:read-public-key "key.pub")
          (privkey (clcrypt:read-private-key "key"))))
      (clcrypt:encrypt-file "clear.file" "cipher.file" :public-key pubkey)
      (clcrypt:decrypt-file "cipher.file" "clear.file" :private-key privkey))

To sign and verify a file:

    (clcrypt:make-signing-key-pair "key")
    (let ((pubkey (clcrypt:read-public-key "key.pub")
          (privkey (clcrypt:read-private-key "key"))))
      (clcrypt:sign-file "some.file" "some.file.sig" "key")
      (clcrypt:verify-file-signature "some.file" "some.file.sig" "key.pub"))

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
