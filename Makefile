DESTDIR = /usr/local

clcrypt: clcrypt.asd src/clcrypt.lisp
	buildapp \
		--output "clcrypt" \
		--entry "clcrypt:main" \
		--load-system "clcrypt" \
		--asdf-path "./" \
		--asdf-path "../ironclad/" \
		--asdf-tree "${HOME}/quicklisp/" \
		--compress-core

all: clcrypt

install: clcrypt
	install -m 755 clcrypt ${DESTDIR}/bin/clcrypt

clean:
	rm -f clcrypt
