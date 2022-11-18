set -ex
if [ ! -f Makefile ]
then
  ./configure --enable-standalone --enable-shared
fi
make -B -j7
