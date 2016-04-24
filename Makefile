#DESTDIR = /usr/local

all: clcrypt clcrypt-gui

clcrypt: clcrypt.asd src/package.lisp src/clcrypt.lisp
	sbcl \
		--no-userinit \
		--no-sysinit \
		--non-interactive \
		--load ~/quicklisp/setup.lisp \
		--eval '(ql:quickload :clcrypt)' \
		--eval '(ql:write-asdf-manifest-file "asdf-manifest.txt" :if-exists :supersede)' \
		--eval '(quit)'
	buildapp \
		--manifest-file "asdf-manifest.txt" \
		--load-system "clcrypt" \
		--output "clcrypt" \
		--entry "clcrypt:main" \
		--compress-core

clcrypt-gui: clcrypt-gui.asd src/package-gui.lisp src/clcrypt.lisp src/gui.lisp
	sbcl \
		--no-userinit \
		--no-sysinit \
		--non-interactive \
		--load ~/quicklisp/setup.lisp \
		--eval '(ql:quickload :clcrypt-gui)' \
		--eval '(ql:write-asdf-manifest-file "asdf-manifest.txt" :if-exists :supersede)' \
		--eval '(quit)'
	buildapp \
		--manifest-file "asdf-manifest.txt" \
		--load-system "clcrypt-gui" \
		--output "clcrypt-gui" \
		--entry "clcrypt:gui" \
		--compress-core

#install: clcrypt
#	install -m 755 clcrypt ${DESTDIR}/bin/clcrypt

clean:
	rm -f clcrypt clcrypt-gui
