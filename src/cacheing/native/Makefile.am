# $Id: Makefile.am,v 1.2 2000/07/21 20:15:09 thomas Exp $

EXTRA_DIST = cache.c hash.h hash.c

all: cache.o hash.o

%o: %c
	$(CC) $(DEFS) -I../.. -I../../.. $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o $@ $<
