set -ex
if [ ! -f Makefile ]
then
  ./configure --enable-standalone
fi
#make -B -j7
#make -B demo.o
#make librktio.a
#gcc demo.o librktio.a -framework Foundation -liconv -o rktio_demo
#clang -fpic -shared -Wl,-all_load librktio.a -framework Foundation -liconv -o librktio.dylib
#gcc demo.o librktio.a -framework Foundation -liconv -o rktio_demo
#make -B librktio.dylib librktio.a rktio_demo
make -B
echo "Try running ./rktio_demo -v --stress"
