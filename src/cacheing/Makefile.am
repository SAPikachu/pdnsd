# $Id: Makefile.am,v 1.3 2000/07/29 18:45:08 thomas Exp $

EXTRA_DIST = cache.h

SUBDIRS = $(cachedbm)

dist-hook:
	for dbm in $(unuseddbms); do \
	  cd $$dbm ; make distclean ; cd .. ; \
	  cp -pr $$dbm $(distdir) ; \
	done
