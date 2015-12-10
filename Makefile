LDFLAGS+=-lelf -ldwarf
CFLAGS+=-Wall -g

core_walk: core_walk.o
       
core_walk.o: core_walk.c util.h list.h

.PHONY: clean
clean:
	rm -f core_walk core_walk.o
