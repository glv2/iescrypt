LISP ?= sbcl
asdf_system := iescrypt

all:
	${LISP} \
		--load "${asdf_system}.asd" \
		--eval "(asdf:make \"${asdf_system}\")" \
		--eval "(uiop:quit)"

clean:
	rm -f iescrypt
