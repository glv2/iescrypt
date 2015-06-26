#DESTDIR = /usr/local

all: clcrypt clcrypt-nt

clcrypt: clcrypt.asd src/package.lisp src/common.lisp src/clcrypt.lisp
	buildapp \
		--output "clcrypt" \
		--entry "clcrypt:main" \
		--load-system "clcrypt" \
		--asdf-path "./" \
		--asdf-path "../ironclad/" \
		--asdf-tree "${HOME}/quicklisp/" \
		--compress-core

clcrypt-nt: clcrypt-nt.asd src/package-nt.lisp src/common.lisp src/clcrypt-nt.lisp
	buildapp \
		--output "clcrypt-nt" \
		--entry "clcrypt:main" \
		--load-system "clcrypt-nt" \
		--asdf-path "./" \
		--asdf-path "../ironclad/" \
		--asdf-tree "${HOME}/quicklisp/" \
		--compress-core

#install: clcrypt
#	install -m 755 clcrypt ${DESTDIR}/bin/clcrypt

clean:
	rm -f clcrypt clcrypt-no-threads
