# $Id: Makefile.am,v 1.1 2001/01/27 00:11:16 thomas Exp $

man_MANS = pdnsd-ctl.8

EXTRA_DIST = pdnsd.conf.in html/dl.html html/doc.html html/faq.html \
html/index.html txt/faq.txt txt/intro.txt txt/manual.txt $(man_MANS)

install-data-hook:
	$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)
	# For both source installs and RPM builds
	if test `whoami` = "root"; then \
	  $(INSTALL) -o 0 -g 0 -m 644 pdnsd.conf $(DESTDIR)/$(sysconfdir)/pdnsd.conf.sample ; \
	else \
	  $(INSTALL) -m 644 pdnsd.conf $(DESTDIR)/$(sysconfdir)/pdnsd.conf.sample ; \
	fi
