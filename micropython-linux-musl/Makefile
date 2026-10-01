all: build

micropython:
	git clone --branch v1.17 https://github.com/micropython/micropython.git

# LINK micropython-minimal
#    text	   data	    bss	    dec	    hex	filename
#  189867	    744	  36748	 227359	  3781f	micropython-minimal
build: micropython
	./zig-mpy-cross.sh
	./zig-port-unix.sh
