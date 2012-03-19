FLAGS += -g -Wall -pedantic -fPIC $(FLAGS_ADD)
CPPFLAGS += $(FLAGS) -std=gnu++0x $(CPPFLAGS_ADD)
CFLAGS   += $(FLAGS) -std=gnu99 -Dinline='inline __attribute__ ((gnu_inline))' $(CFLAGS_ADD)

default: all
all: libflowcalc.so flowcalc

libflowcalc.so: libflowcalc.c libflowcalc.h
	g++ $(CPPLAGS) \
		libflowcalc.c -o libflowcalc.so \
		-shared -Wl,-soname,libflowcalc.so.0 \
		-lpjf -lpcre -ltrace -lflowmanager

flowcalc: flowcalc.c libflowcalc.so
	gcc $(CFLAGS) -L. -lflowcalc -lpjf \
		flowcalc.c -o flowcalc

.PHONY: clean
clean:
	-rm -f *.o libflowcalc.so flowcalc
