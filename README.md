# iescrypt

The iescrypt program can encrypt, decrypt and sign files.

The encryption/decryption can be done either with a passphrase or
a curve25519 key pair. The signature/verification is done with an
ed25519 key pair.


## Details

Format of the encrypted file:

    | salt | parameter | ciphertext | mac |

Size of the fields:
* salt: 32 bytes
* parameter: 32 bytes
* mac: 64 bytes

Encryption process:
* The cleartext is encrypted by the cipher (chacha).
* The mac (hmac using blake2) is computed on the ciphertext.
* The key and the initialization vector for the cipher and the key for the
message authentication code are derived either from a salt and a passphrase
or from a salt, a parameter and an ECC (curve25519) key (pbkdf2, 10000
iterations of blake2). The parameter is not used in passphrase mode, it just
contains random data.

When using the command to simultaneously sign and encrypt a file, the
encryption is done on a tar file containing the input file and the signature
of the input file.


## Dependencies

* [sbcl](http://www.sbcl.org/) as Common Lisp implementation (it also works
with ccl, ecl and clisp, but 200 times slower).
* [archive](http://www.cliki.net/Archive)
* [babel](http://www.cliki.net/Babel)
* [ironclad](http://cliki.net/Ironclad)


If you want to use the Qt GUI, you will also need:

* [CommonQt](http://common-lisp.net/project/commonqt)

If you want to build iescrypt as an executable using the Makefile, you will
also need:

* [buildapp](http://www.cliki.net/Buildapp)

These libraries can be installed easily with [quicklisp](http://www.quicklisp.org).


## Examples

Encrypt and decrypt a file with a passphrase:

    (iescrypt:encrypt-file "clear.file" "cipher.file" :passphrase "passphrase")
    (iescrypt:decrypt-file "cipher.file" "clear.file" :passphrase "passphrase")

Encrypt and decrypt a file with a key pair:

    (iescrypt:make-encryption-key-pair "key")
    (let ((pubkey (iescrypt:read-public-key "key.pub")
          (privkey (iescrypt:read-private-key "key"))))
      (iescrypt:encrypt-file "clear.file" "cipher.file" :public-key pubkey)
      (iescrypt:decrypt-file "cipher.file" "clear.file" :private-key privkey))

Sign and verify a file:

    (iescrypt:make-signing-key-pair "key")
    (let ((pubkey (iescrypt:read-public-key "key.pub")
          (privkey (iescrypt:read-private-key "key"))))
      (let ((signature (iescrypt:sign-file "some.file" "key" "some.file.sig")))
        (iescrypt:verify-file-signature "some.file" signature))

Simultaneously sign and encrypt a file:

    (iescrypt:make-encryption-key-pair "enckey")
    (iescrypt:make-signing-key-pair "sigkey")
    (let ((encpubkey (iescrypt:read-public-key "enckey.pub"))
          (encprivkey (iescrypt:read-private-key "enckey"))
          (sigpubkey (iescrypt:read-public-key "sigkey.pub"))
          (sigprivkey (iescrypt:read-private-key "sigkey")))
      (iescrypt:sign-and-encrypt-file "clear.file" "cipher.file" sigkey :public-key enckey.pub)
      (iescrypt:decrypt-and-verify-file "cipher.file" "clear.file" nil :private-key enckey))

Start the GUI:

    (require 'iescrypt-gui)
    (iescrypt:gui)

## Executable

You can build executables using the Makefile (which uses buildapp).

To build all the versions:

    make

To build the console version:

    make iescrypt

To build the GUI version:

    make iescrypt-gui
