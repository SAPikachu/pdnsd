# $Id: Makefile.am,v 1.2 2001/12/30 15:32:54 tmm Exp $

man_MANS = pdnsd.8 pdnsd-ctl.8 pdnsd.conf.5

EXTRA_DIST = pdnsd.conf.in html/dl.html html/doc.html html/faq.html \
html/index.html txt/faq.txt txt/intro.txt txt/manual.txt $(man_MANS)

# XXX: Do not insist to set the config file owner to root to avoid breaking RPM
# builds
install-data-hook:
	$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)
	if test `whoami` = "root"; then \
	  $(INSTALL) -o 0 -g 0 -m 644 pdnsd.conf $(DESTDIR)/$(sysconfdir)/pdnsd.conf.sample ; \
	else \
	  $(INSTALL) -m 644 pdnsd.conf $(DESTDIR)/$(sysconfdir)/pdnsd.conf.sample ; \
	fi
