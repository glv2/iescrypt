DESTDIR = /usr/local

clcrypt-threads: clcrypt.asd src/clcrypt.lisp
	buildapp \
		--output "clcrypt" \
		--entry "clcrypt:main" \
		--load-system "clcrypt" \
		--asdf-path "./" \
		--asdf-path "../ironclad/" \
		--asdf-tree "${HOME}/quicklisp/" \
		--compress-core

clcrypt-no-threads: clcrypt-no-threads.asd src/clcrypt-no-threads.lisp
	buildapp \
		--output "clcrypt" \
		--entry "clcrypt:main" \
		--load-system "clcrypt-no-threads" \
		--asdf-path "./" \
		--asdf-path "../ironclad/" \
		--asdf-tree "${HOME}/quicklisp/" \
		--compress-core

all: clcrypt-threads

install: clcrypt
	install -m 755 clcrypt ${DESTDIR}/bin/clcrypt

clean:
	rm -f clcrypt
