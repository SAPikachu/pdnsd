# $Id: Makefile.am,v 1.5 2000/10/16 21:44:37 thomas Exp $
#EXTRA_DIST = pdnsd

DISTRO = @distribution@

install-exec-local:
	if [ "$(DISTRO)" = "SuSE" ] ; then \
	  CURDIR=`pwd`; \
	  $(mkinstalldirs) $(DESTDIR)/sbin/init.d; \
	  $(INSTALL_SCRIPT) $(srcdir)/pdnsd $(DESTDIR)/sbin/init.d/pdnsd; \
	  $(mkinstalldirs) $(DESTDIR)/sbin/init.d/rc2.d; \
	  cd $(DESTDIR)/sbin/init.d/rc2.d; \
	  ln -fs ../pdnsd K34pdnsd; ln -s ../pdnsd S11pdnsd; \
	  cd $$CURDIR ; \
	  $(mkinstalldirs) $(DESTDIR)/sbin/init.d/rc3.d; \
	  cd $(DESTDIR)/sbin/init.d/rc3.d; \
	  ln -fs ../pdnsd K34pdnsd; ln -s ../pdnsd S11pdnsd; \
	  cd $$CURDIR ; \
	  grep "START_PDNSD" $(DESTDIR)/etc/rc.config > /dev/null ; \
	  if [ $$? -ne 0 ] ; then \
	    echo -e "\n\n#\n# Set to yes to start pdnsd at boot time\n#\nSTART_PDNSD=yes" >> /etc/rc.config ; \
	  fi \
	fi



