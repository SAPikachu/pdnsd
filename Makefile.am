# $Id: Makefile.am,v 1.20 2001/06/04 19:59:50 tmm Exp $

SUBDIRS = src doc contrib
#GZIP_ENV=

EXTRA_DIST = @PACKAGE@.spec.in config.h.in version \
file-list.base.in ChangeLog.old COPYING.BSD README.par README.par.old

# The sample configuration is handled in doc/Makefile.am
install-data-hook:
	$(mkinstalldirs) $(DESTDIR)$(cachedir)
	test -f $(DESTDIR)$(cachedir)/pdnsd.cache || \
	  touch $(DESTDIR)$(cachedir)/pdnsd.cache
	if test `whoami` = "root"; then \
	  chown $(def_id) $(DESTDIR)$(cachedir)/pdnsd.cache; \
	  chown $(def_id) $(DESTDIR)$(cachedir); \
	fi
	chmod 0640 $(DESTDIR)$(cachedir)/pdnsd.cache
	chmod 0750 $(DESTDIR)$(cachedir)

dist-hook: $(PACKAGE).spec
	cp $(PACKAGE).spec $(distdir)
#	cp -pr doc $(distdir)

