# $Id: Makefile.am,v 1.5 2000/10/17 20:34:50 thomas Exp $
#EXTRA_DIST = pdnsd

DISTRO = @distribution@

install-exec-local:
	if [ "$(DISTRO)" = "Debian" ] ; then \
	  CURDIR=`pwd`; \
	  $(mkinstalldirs) $(DESTDIR)/etc/init.d; \
	  $(INSTALL_SCRIPT) $(srcdir)/pdnsd $(DESTDIR)/etc/init.d; \
	  update-rc.d pdnsd defaults 19 ;\
	fi
