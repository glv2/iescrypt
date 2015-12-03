#DESTDIR = /usr/local

all: clcrypt clcrypt-gui

clcrypt: clcrypt.asd src/package.lisp src/clcrypt.lisp
	buildapp \
		--output "clcrypt" \
		--entry "clcrypt:main" \
		--load-system "clcrypt" \
		--asdf-path "./" \
		--asdf-path "../ironclad/" \
		--asdf-tree "${HOME}/quicklisp/" \
		--compress-core

clcrypt-gui: clcrypt-gui.asd src/package-gui.lisp src/clcrypt.lisp src/gui.lisp
	buildapp \
		--output "clcrypt-gui" \
		--entry "clcrypt:gui" \
		--load-system "clcrypt-gui" \
		--asdf-path "./" \
		--asdf-path "../ironclad/" \
		--asdf-tree "${HOME}/quicklisp/" \
		--compress-core

#install: clcrypt
#	install -m 755 clcrypt ${DESTDIR}/bin/clcrypt

clean:
	rm -f clcrypt clcrypt-gui
