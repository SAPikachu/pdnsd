# $Id: Makefile.am,v 1.10 2000/10/19 12:49:43 thomas Exp $

SUBDIRS = src

EXTRA_DIST = @PACKAGE@.spec.in config.h config.h.in version file-list.base \
file-list.base.in ChangeLog.old HACKING \
doc/pdnsd.conf.in doc/html/dl.html doc/html/doc.html doc/html/faq.html \
doc/html/index.html doc/txt/faq.txt doc/txt/intro.txt doc/txt/manual.txt

install-data-hook:
	if test -f $(DESTDIR)/etc/pdnsd.conf; then \
	  cp $(DESTDIR)/etc/pdnsd.conf $(DESTDIR)/etc/pdnsd.conf.old ; \
	  echo -e "\n\nBacked up your old pdnsd.conf to pdnsd.conf.old\n\n" ; \
	fi
	$(mkinstalldirs) $(DESTDIR)/etc
	# For both source installs and RPM builds
	if test "$(USER)" = "root"; then \
	  $(INSTALL) -o 0 -g 0 -m 644 doc/pdnsd.conf $(DESTDIR)/etc/pdnsd.conf ; \
	else \
	  $(INSTALL) -m 644 doc/pdnsd.conf $(DESTDIR)/etc/pdnsd.conf ; \
	fi
	$(mkinstalldirs) $(DESTDIR)$(cachedir)
	if test "$(cachedbm)" = "native"; then \
	  echo -en "\0\0\0\0" > $(DESTDIR)$(cachedir)/pdnsd.cache; \
	else \
	  touch $(DESTDIR)$(cachedir)/pdnsd.cache; \
	fi
	if test "$(USER)" = "root"; then \
	  chown $(def_id) $(DESTDIR)$(cachedir)/pdnsd.cache; \
	fi
	chmod 0640 $(DESTDIR)$(cachedir)/pdnsd.cache

dist-hook: $(PACKAGE).spec
	cp $(PACKAGE).spec $(distdir)
#	cp -pr doc $(distdir)

