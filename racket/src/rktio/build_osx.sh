set -ex
if [ ! -f Makefile ]
then
  ./configure
fi
make -j7
make demo.o
gcc demo.o librktio.a -framework Foundation -liconv -o rktio_demo
clang -fpic -shared -Wl,-all_load librktio.a -framework Foundation -liconv -o librktio.dylib
