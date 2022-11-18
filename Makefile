PHONY: test

configure: racket/src/rktio/Makefile
	@./build.sh

test: configure
	@PYTHONPATH=src python3 -m rktio
