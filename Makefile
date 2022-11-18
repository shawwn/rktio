PHONY: all test clean

all: configure test

clean:
	@cd racket/src/rktio && make clean

racket/src/rktio/Makefile:

configure: racket/src/rktio/Makefile
	@./build.sh

test: configure
	@PYTHONPATH=src python3 -m rktio
