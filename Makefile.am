# $Id: Makefile.am,v 1.3 2000/07/29 18:45:02 thomas Exp $

SUBDIRS = src

EXTRA_DIST = @PACKAGE@.spec.in config.h config.h.in version file-list.base \
file-list.base.in ChangeLog.old

install-data-hook:
	cp -p doc/pdnsd.conf $(DESTDIR)/etc
	$(mkinstalldirs) $(DESTDIR)$(cachedir)
	if test "$(cachedbm)" = "native"; then \
	  echo -en "\0\0\0\0" > $(DESTDIR)$(cachedir)/pdnsd.cache; \
	else \
	  touch $(DESTDIR)$(cachedir)/pdnsd.cache; \
	fi

dist-hook: $(PACKAGE).spec
	cp $(PACKAGE).spec $(distdir)
	cp -pr doc $(distdir)
