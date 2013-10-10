LDFLAGS+=-lelf -ldwarf
CFLAGS+=-Wall -g

core_walk: core_walk.c util.h

.PHONY: clean
clean:
	rm -f core_walk
