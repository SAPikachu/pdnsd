# $Id: Makefile.am,v 1.20 2001/06/04 19:59:50 tmm Exp $

SUBDIRS = src doc contrib
#GZIP_ENV=

EXTRA_DIST = @PACKAGE@.spec.in config.h config.h.in version file-list.base \
file-list.base.in ChangeLog.old COPYING.BSD

# The sample configuration is handled in doc/Makefile.am
install-data-hook:
	$(mkinstalldirs) $(DESTDIR)$(cachedir)
	if test "$(cachedbm)" = "native"; then \
	  dd if=/dev/zero of=$(DESTDIR)$(cachedir)/pdnsd.cache bs=1 count=4; \
	else \
	  touch $(DESTDIR)$(cachedir)/pdnsd.cache; \
	fi
	if test `whoami` = "root"; then \
	  chown $(def_id) $(DESTDIR)$(cachedir)/pdnsd.cache; \
	  chown $(def_id) $(DESTDIR)$(cachedir); \
	fi
	chmod 0640 $(DESTDIR)$(cachedir)/pdnsd.cache
	chmod 0750 $(DESTDIR)$(cachedir)

dist-hook: $(PACKAGE).spec
	cp $(PACKAGE).spec $(distdir)
#	cp -pr doc $(distdir)

