CC=clang
CFLAGS=-g -O2

$(shell mkdir -p build)

.PHONY: all

all: build/fake-sandbox-preload.so build/fake-sandbox

build/fake-sandbox-preload.so: fake-sandbox-preload.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -ldl

build/fake-sandbox:
	$(CC) $(CFLAGS) --o $@ $<
