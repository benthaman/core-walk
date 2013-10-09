LDFLAGS+=-lelf -ldwarf
CFLAGS+=-Wall

core_walk:

.PHONY: clean
clean:
	rm -f core_walk
