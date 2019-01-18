CC?=gcc
OPTS=-c -O2 -Wall -Wno-unused-function -fPIC $(CFLAGS) $(CPPFLAGS)
SHARED_OPTS=-shared -fPIC
SOURCES=Kasumi.c SNOW_3G.c ZUC.c KeccakP-1600-3gpp.c comp128.c
OBJECTS=$(SOURCES:.c=.o)

LIBS=Kasumi SNOW_3G ZUC KeccakP-1600-3gpp comp128

.PHONY: all
all: $(OBJECTS)

$(OBJECTS): %.o: %.c
	$(CC) $(OPTS) $< -o $@
	$(CC) $(SHARED_OPTS) -o $*.so $<

clean:
	rm *.so
	rm *.o
