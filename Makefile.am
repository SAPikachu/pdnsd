# $Id: Makefile.am,v 1.14 2001/01/27 00:11:09 thomas Exp $

SUBDIRS = src doc
GZIP_ENV=

EXTRA_DIST = @PACKAGE@.spec.in config.h config.h.in version file-list.base \
file-list.base.in ChangeLog.old

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
	fi
	chmod 0640 $(DESTDIR)$(cachedir)/pdnsd.cache

dist-hook: $(PACKAGE).spec
	cp $(PACKAGE).spec $(distdir)
#	cp -pr doc $(distdir)

