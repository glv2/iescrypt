#DESTDIR = /usr/local

all: clcrypt clcrypt-gui clcrypt-nt clcrypt-gui-nt

clcrypt: clcrypt.asd src/package.lisp src/common.lisp src/clcrypt.lisp
	buildapp \
		--output "clcrypt" \
		--entry "clcrypt:main" \
		--load-system "clcrypt" \
		--asdf-path "./" \
		--asdf-path "../ironclad/" \
		--asdf-tree "${HOME}/quicklisp/" \
		--compress-core

clcrypt-gui: clcrypt-gui.asd src/package-gui.lisp src/common.lisp src/clcrypt.lisp src/gui.lisp
	buildapp \
		--output "clcrypt-gui" \
		--entry "clcrypt:gui" \
		--load-system "clcrypt-gui" \
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

clcrypt-gui-nt: clcrypt-gui-nt.asd src/package-gui-nt.lisp src/common.lisp src/clcrypt-nt.lisp src/gui.lisp
	buildapp \
		--output "clcrypt-gui-nt" \
		--entry "clcrypt:gui" \
		--load-system "clcrypt-gui-nt" \
		--asdf-path "./" \
		--asdf-path "../ironclad/" \
		--asdf-tree "${HOME}/quicklisp/" \
		--compress-core

#install: clcrypt
#	install -m 755 clcrypt ${DESTDIR}/bin/clcrypt

clean:
	rm -f clcrypt clcrypt-gui clcrypt-nt clcrypt-gui-nt
