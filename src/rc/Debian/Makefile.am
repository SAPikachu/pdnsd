# $Id: Makefile.am,v 1.2 2000/07/30 19:01:42 thomas Exp $
EXTRA_DIST = pdnsd

DISTRO = @distribution@

install-exec-local:
	if [ "$(DISTRO)" = "Debian" ] ; then \
	  CURDIR=`pwd`; \
	  $(mkinstalldirs) /etc/init; \
	  $(INSTALL_SCRIPT) $(srcdir)/pdnsd /etc/init; \
	  update-rc.d pdnsd defaults 19 ;\
	fi
