# $Id: Makefile.am,v 1.2 2000/07/21 20:15:07 thomas Exp $

EXTRA_DIST =

all:

%o: %c
	$(CC) $(DEFS) -I../.. -I../../.. $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o $@ $<
