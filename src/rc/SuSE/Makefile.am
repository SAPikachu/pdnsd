# $Id: Makefile.am,v 1.2 2000/07/29 21:29:40 thomas Exp $
EXTRA_DIST = pdnsd

DISTRO = @distribution@

install-exec-local:
	if [ "$(DISTRO)" = "SuSE" ]; then \
	  CURDIR=`pwd`; \
	  $(mkinstalldirs) /sbin/init.d; \
	  $(INSTALL_SCRIPT) $(srcdir)/pdnsd /sbin/init.d/pdnsd; \
	  $(mkinstalldirs) /sbin/init.d/rc2.d; \
	  cd /sbin/init.d/rc2.d; \
	  ln -fs ../pdnsd K34pdnsd; ln -s ../pdnsd S11pdnsd; \
	  cd $$CURDIR ; \
	  $(mkinstalldirs) /sbin/init.d/rc3.d; \
	  cd /sbin/init.d/rc3.d; \
	  ln -fs ../pdnsd K34pdnsd; ln -s ../pdnsd S11pdnsd; \
	  cd $$CURDIR ; \
	fi
