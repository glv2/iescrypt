#DESTDIR = /usr/local

all: iescrypt iescrypt-gui

iescrypt: iescrypt.asd src/ies.lisp src/package.lisp src/iescrypt.lisp
	sbcl \
		--no-userinit \
		--no-sysinit \
		--non-interactive \
		--load ~/.quicklisp/setup.lisp \
		--eval '(ql:quickload :iescrypt)' \
		--eval '(ql:write-asdf-manifest-file "asdf-manifest.txt" :if-exists :supersede)' \
		--eval '(quit)'
	buildapp \
		--manifest-file "asdf-manifest.txt" \
		--load-system "iescrypt" \
		--output "iescrypt" \
		--entry "iescrypt:main" \
		--compress-core

iescrypt-gui: iescrypt-gui.asd src/ies.lisp src/package-gui.lisp src/iescrypt.lisp src/gui.lisp
	sbcl \
		--no-userinit \
		--no-sysinit \
		--non-interactive \
		--load ~/.quicklisp/setup.lisp \
		--eval '(ql:quickload :iescrypt-gui)' \
		--eval '(ql:write-asdf-manifest-file "asdf-manifest.txt" :if-exists :supersede)' \
		--eval '(quit)'
	buildapp \
		--manifest-file "asdf-manifest.txt" \
		--load-system "iescrypt-gui" \
		--output "iescrypt-gui" \
		--entry "iescrypt-gui:gui" \
		--compress-core

#install: iescrypt
#	install -m 755 iescrypt ${DESTDIR}/bin/iescrypt

clean:
	rm -f iescrypt iescrypt-gui
