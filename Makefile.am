# $Id: Makefile.am,v 1.6 2000/08/05 16:50:29 thomas Exp $

SUBDIRS = src

EXTRA_DIST = @PACKAGE@.spec.in config.h config.h.in version file-list.base \
file-list.base.in ChangeLog.old \
doc/pdnsd.conf.in doc/html/dl.html doc/html/doc.html doc/html/faq.html \
doc/html/index.html doc/txt/faq.txt doc/txt/intro.txt doc/txt/manual.txt

install-data-hook:
	if [ -f $(DESTDIR)/etc/pdnsd.conf ] ; then cp $(DESTDIR)/etc/pdnsd.conf $(DESTDIR)/etc/pdnsd.conf.old ; echo -e "\n\nBacked up your old pdnsd.conf to pdns.conf.old\n\n" ; fi
	$(mkinstalldirs) $(DESTDIR)/etc
	$(INSTALL) -o root -g root doc/pdnsd.conf $(DESTDIR)/etc/pdnsd.conf
	$(mkinstalldirs) $(DESTDIR)$(cachedir)
	if test "$(cachedbm)" = "native"; then \
	  echo -en "\0\0\0\0" > $(DESTDIR)$(cachedir)/pdnsd.cache; \
	else \
	  touch $(DESTDIR)$(cachedir)/pdnsd.cache; \
	fi

dist-hook: $(PACKAGE).spec
	cp $(PACKAGE).spec $(distdir)
#	cp -pr doc $(distdir)
