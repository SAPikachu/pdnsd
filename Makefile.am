# $Id: Makefile.am,v 1.13 2000/11/15 17:26:58 thomas Exp $

SUBDIRS = src
GZIP_ENV=

EXTRA_DIST = @PACKAGE@.spec.in config.h config.h.in version file-list.base \
file-list.base.in ChangeLog.old \
doc/pdnsd.conf.in doc/html/dl.html doc/html/doc.html doc/html/faq.html \
doc/html/index.html doc/txt/faq.txt doc/txt/intro.txt doc/txt/manual.txt

install-data-hook:
#	if test -f $(DESTDIR)/$(sysconfdir)/pdnsd.conf; then \
#	  cp $(DESTDIR)/$(sysconfdir)/pdnsd.conf $(DESTDIR)/$(sysconfdir)/pdnsd.conf.old ; \
#	  echo -e "\n\nBacked up your old pdnsd.conf to pdnsd.conf.old\n\n" ; \
#	fi
	$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)
	# For both source installs and RPM builds
	if test `whoami` = "root"; then \
	  $(INSTALL) -o 0 -g 0 -m 644 doc/pdnsd.conf $(DESTDIR)/$(sysconfdir)/pdnsd.conf.sample ; \
	else \
	  $(INSTALL) -m 644 doc/pdnsd.conf $(DESTDIR)/$(sysconfdir)/pdnsd.conf.sample ; \
	fi
	$(mkinstalldirs) $(DESTDIR)$(cachedir)
	if test "$(cachedbm)" = "native"; then \
	  dd if=/dev/zero of=$(DESTDIR)$(cachedir)/pdnsd.cache bs=1 count=4; \
	else \
	  touch $(DESTDIR)$(cachedir)/pdnsd.cache; \
	fi
	if test `whoami` = "root"; then \
	  chown $(def_id) $(DESTDIR)$(cachedir)/pdnsd.cache; \
	fi
	chmod 0640 $(DESTDIR)$(cachedir)/pdnsd.cache

dist-hook: $(PACKAGE).spec
	cp $(PACKAGE).spec $(distdir)
#	cp -pr doc $(distdir)

