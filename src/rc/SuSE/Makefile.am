# $Id: Makefile.am,v 1.3 2000/07/30 19:01:44 thomas Exp $
EXTRA_DIST = pdnsd

DISTRO = @distribution@

install-exec-local:
	if [ "$(DISTRO)" = "SuSE" ] ; then \
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
	  grep "START_PDNSD" /etc/rc.config > /dev/null ; \
	  if [ $$? -ne 0 ] ; then \
	    echo -e "\n\n#\n# Set to yes to start pdnsd at boot time\n#\nSTART_PDNSD=yes" >> /etc/rc.config ; \
	  fi \
	fi
