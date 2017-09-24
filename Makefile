CC?=gcc
OPTS=-c -Wall -fPIC $(CFLAGS) $(CPPFLAGS)
SHARED_OPTS=-shared -fPIC
SOURCES=Kasumi.c SNOW_3G.c ZUC.c
OBJECTS=$(SOURCES:.c=.o)

LIBS=Kasumi SNOW_3G ZUC

.PHONY: all
all: $(OBJECTS)

$(OBJECTS): %.o: %.c
	$(CC) $(OPTS) $< -o $@
	$(CC) $(SHARED_OPTS) -o $*.so $<

clean:
	rm *.so
	rm *.o
