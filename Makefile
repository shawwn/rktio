PHONY: all test clean

all: configure test

clean:
	@cd racket/src/rktio && make clean

racket/src/rktio/Makefile:
	@./build.sh

configure: racket/src/rktio/Makefile

test: configure
	@PYTHONPATH=src python3 -m rktio
