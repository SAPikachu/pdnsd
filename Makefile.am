# $Id: Makefile.am,v 1.1 2000/07/20 20:03:05 thomas Exp $

SUBDIRS = src

EXTRA_DIST = @PACKAGE@.spec.in config.h config.h.in version file-list.base \
file-list.base.in ChangeLog.old

install-data-hook:
	cp -p doc/pdnsd.conf $(DESTDIR)/etc
	$(mkinstalldirs) $(DESTDIR)@cachedir@
	touch $(DESTDIR)@cachedir@/pdnsd.cache

dist-hook: @PACKAGE@.spec
	cp @PACKAGE@.spec $(distdir)
	cp -pr doc $(distdir)
