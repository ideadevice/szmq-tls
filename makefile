CC = gcc
CFLAGS = -c -Wall -g -fPIC -I../include -I.
SONAME = libszmq.so.1
TARGET = libszmq.so.1.0
LDFLAGS = -shared -Wl,-soname,$(SONAME) 
LIBS = -lc
LIBDIR = /usr/local/lib/
INCDIR = /usr/local/include/
SOURCES = $(wildcard src/*.c)
OBJECTS = $(SOURCES:.c=.o)
HEADERS = src/szmq_callback.h include/szmq.h

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o  $@ $^ $(LIBS)

src/%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f src/*.o *.so*

install: $(TARGET)
	cp $< $(LIBDIR)
	ldconfig -n $(LIBDIR)
	cp include/*.h $(INCDIR)

.PHONY: clean install

