# $Id: Makefile.am,v 1.1 2000/07/29 21:29:37 thomas Exp $
EXTRA_DIST = pdnsd

DISTRO = @distribution@

install-exec-local:
	if [ "$(DISTRO)" = "Debian" ]; then \
	  CURDIR=`pwd`; \
	  $(mkinstalldirs) /etc/init; \
	  $(INSTALL_SCRIPT) $(srcdir)/pdnsd /etc/init; \
	  update-rc.d pdnsd defaults 19 \
	fi
