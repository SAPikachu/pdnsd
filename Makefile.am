# $Id: Makefile.am,v 1.5 2000/07/30 19:01:37 thomas Exp $

SUBDIRS = src

EXTRA_DIST = @PACKAGE@.spec.in config.h config.h.in version file-list.base \
file-list.base.in ChangeLog.old

install-data-hook:
	if [ -f $(DESTDIR)/etc/pdnsd.conf ] ; then cp $(DESTDIR)/etc/pdnsd.conf $(DESTDIR)/etc/pdnsd.conf.old ; echo -e "\n\nBacked up your old pdnsd.conf to pdns.conf.old\n\n" ; fi
	cp -p doc/pdnsd.conf $(DESTDIR)/etc
	$(mkinstalldirs) $(DESTDIR)$(cachedir)
	if test "$(cachedbm)" = "native"; then \
	  echo -en "\0\0\0\0" > $(DESTDIR)$(cachedir)/pdnsd.cache; \
	else \
	  touch $(DESTDIR)$(cachedir)/pdnsd.cache; \
	fi

dist-hook: $(PACKAGE).spec
	cp $(PACKAGE).spec $(distdir)
	echo $(distdir)
	cp -pr doc $(distdir)
