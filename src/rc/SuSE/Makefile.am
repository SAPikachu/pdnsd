# $Id: Makefile.am,v 1.7 2000/11/21 20:01:36 thomas Exp $
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
	  if [ $$? -eq 1 ] ; then \
	    echo -e "\n\n#\n# Set to yes to start pdnsd at boot time\n#\nSTART_PDNSD=yes" >> /etc/rc.config ; \
	  fi \
	fi



