# $Id: Makefile.am,v 1.2 2000/07/29 21:29:39 thomas Exp $
EXTRA_DIST = pdnsd

DISTRO = @distribution@

install-exec-local:
	if [ "$(DISTRO)" = "RedHat" ]; then \
	  CURDIR=`pwd`; \
	  $(mkinstalldirs) /etc/rc.d/init.d; \
	  $(INSTALL_SCRIPT) $(srcdir)/pdnsd /etc/rc.d/init.d/pdnsd; \
	  $(mkinstalldirs) /etc/rc.d/rc2.d; \
	  cd /etc/rc.d/rc2.d; \
	  ln -fs ../init.d/pdnsd K45pdnsd; ln -s ../init.d/pdnsd S12pdnsd; \
	  cd $$CURDIR ; \
	  $(mkinstalldirs) /etc/rc.d/rc3.d; \
	  cd /etc/rc.d/rc3.d; \
	  ln -fs ../init.d/pdnsd K45pdnsd; ln -s ../init.d/pdnsd S12pdnsd; \
	  cd $$CURDIR ; \
	fi

#	  $(mkinstalldirs) /etc/rc.d/rc4.d; \
#	  cd /etc/rc.d/rc4.d; \
#	  ln -fs ../init.d/pdnsd K45pdnsd; ln -s ../init.d/pdnsd S12pdnsd; \
#	  cd $$CURDIR ; \
#	  $(mkinstalldirs) /etc/rc.d/rc5.d; \
#	  cd /etc/rc.d/rc5.d; \
#	  ln -fs ../init.d/pdnsd K45pdnsd; ln -s ../init.d/pdnsd S12pdnsd; \
#	  cd $$CURDIR ; \
#	  $(mkinstalldirs) /etc/rc.d/rc6.d; \
#	  cd /etc/rc.d/rc6.d; \
#	  ln -fs ../init.d/pdnsd K45pdnsd; \
