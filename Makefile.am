# $Id: Makefile.am,v 1.8 2000/08/26 11:41:27 thomas Exp $

SUBDIRS = src

EXTRA_DIST = @PACKAGE@.spec.in config.h config.h.in version file-list.base \
file-list.base.in ChangeLog.old \
doc/pdnsd.conf.in doc/html/dl.html doc/html/doc.html doc/html/faq.html \
doc/html/index.html doc/txt/faq.txt doc/txt/intro.txt doc/txt/manual.txt

install-data-hook:
	if [ -f $(DESTDIR)/etc/pdnsd.conf ] ; then cp $(DESTDIR)/etc/pdnsd.conf $(DESTDIR)/etc/pdnsd.conf.old ; echo -e "\n\nBacked up your old pdnsd.conf to pdns.conf.old\n\n" ; fi
	$(mkinstalldirs) $(DESTDIR)/etc
	$(INSTALL) -o 0 -g 0 -m 644 doc/pdnsd.conf $(DESTDIR)/etc/pdnsd.conf
	$(mkinstalldirs) $(DESTDIR)$(cachedir)
	if test "$(cachedbm)" = "native"; then \
	  echo -en "\0\0\0\0" > $(DESTDIR)$(cachedir)/pdnsd.cache; \
	else \
	  touch $(DESTDIR)$(cachedir)/pdnsd.cache; \
	fi
	chown $(def_id) $(DESTDIR)$(cachedir)/pdnsd.cache
	chmod 0640 $(DESTDIR)$(cachedir)/pdnsd.cache

dist-hook: $(PACKAGE).spec
	cp $(PACKAGE).spec $(distdir)
#	cp -pr doc $(distdir)
