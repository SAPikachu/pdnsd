# $Id: Makefile.am,v 1.3 2000/08/05 16:50:39 thomas Exp $
EXTRA_DIST = pdnsd

DISTRO = @distribution@

install-exec-local:
	if [ "$(DISTRO)" = "Debian" ] ; then \
	  CURDIR=`pwd`; \
	  $(mkinstalldirs) $(DESTDIR)/etc/init; \
	  $(INSTALL_SCRIPT) $(srcdir)/pdnsd $(DESTDIR)/etc/init; \
	  update-rc.d pdnsd defaults 19 ;\
	fi
