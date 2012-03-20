FLAGS += -g -Wall -pedantic -fPIC $(FLAGS_ADD)
CPPFLAGS += $(FLAGS) -std=gnu++0x $(CPPFLAGS_ADD)
CFLAGS   += $(FLAGS) -std=gnu99 -Dinline='inline __attribute__ ((gnu_inline))' $(CFLAGS_ADD)

PREFIX ?= /usr
PKGDST = $(DESTDIR)$(PREFIX)

default: all
all: libflowcalc.so example

libflowcalc.so: libflowcalc.c libflowcalc.h
	g++ $(CPPLAGS) \
		libflowcalc.c -o libflowcalc.so \
		-shared -Wl,-soname,libflowcalc.so.0 \
		-lpjf -lpcre -ltrace -lflowmanager

example: example.c libflowcalc.so
	gcc $(CFLAGS) -L. -lflowcalc -lpjf \
		example.c -o example

install:
	install -m 644 libflowcalc.h $(PKGDST)/include
	install -m 755 libflowcalc.so $(PKGDST)/lib

.PHONY: clean
clean:
	-rm -f *.o libflowcalc.so example
