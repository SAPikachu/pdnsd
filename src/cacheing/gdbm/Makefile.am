# $Id: Makefile.am,v 1.1 2000/07/21 20:04:40 thomas Exp $

EXTRA_DIST = cache.h cache.c hash.h hash.c

all:

%o: %c
	$(CC) $(DEFS) -I../.. -I../../.. $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o $@ $<
