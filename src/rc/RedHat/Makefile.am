# $Id: Makefile.am,v 1.6 2001/04/10 01:36:23 tmm Exp $
#EXTRA_DIST = pdnsd

DISTRO = @distribution@

install-exec-local:
	if [ "$(DISTRO)" = "RedHat" ] ; then \
	  CURDIR=`pwd`; \
	  $(mkinstalldirs) $(DESTDIR)/etc/rc.d/init.d; \
	  $(INSTALL_SCRIPT) $(srcdir)/pdnsd $(DESTDIR)/etc/rc.d/init.d/pdnsd; \
	  $(mkinstalldirs) $(DESTDIR)/etc/rc.d/rc2.d; \
	  cd $(DESTDIR)/etc/rc.d/rc2.d; \
	  ln -fs ../init.d/pdnsd K45pdnsd; ln -s ../init.d/pdnsd S12pdnsd; \
	  cd $$CURDIR ; \
	  $(mkinstalldirs) $(DESTDIR)/etc/rc.d/rc3.d; \
	  cd $(DESTDIR)/etc/rc.d/rc3.d; \
	  ln -fs ../init.d/pdnsd K45pdnsd; ln -s ../init.d/pdnsd S12pdnsd; \
	  $(mkinstalldirs) $(DESTDIR)/etc/rc.d/rc0.d; \
	  cd $(DESTDIR)/etc/rc.d/rc3.d; \
	  ln -fs ../init.d/pdnsd K45pdnsd; \
	  $(mkinstalldirs) $(DESTDIR)/etc/rc.d/rc6.d; \
	  cd $(DESTDIR)/etc/rc.d/rc3.d; \
	  ln -fs ../init.d/pdnsd K45pdnsd; \
	  cd $$CURDIR ; \
	fi

#	  $(mkinstalldirs) $(DESTDIR)/etc/rc.d/rc4.d; \
#	  cd $(DESTDIR)/etc/rc.d/rc4.d; \
#	  ln -fs ../init.d/pdnsd K45pdnsd; ln -s ../init.d/pdnsd S12pdnsd; \
#	  cd $$CURDIR ; \
#	  $(mkinstalldirs) $(DESTDIR)/etc/rc.d/rc5.d; \
#	  cd $(DESTDIR)/etc/rc.d/rc5.d; \
#	  ln -fs ../init.d/pdnsd K45pdnsd; ln -s ../init.d/pdnsd S12pdnsd; \
#	  cd $$CURDIR ; \
#	  $(mkinstalldirs) $(DESTDIR)/etc/rc.d/rc6.d; \
#	  cd $(DESTDIR)/etc/rc.d/rc6.d; \
#	  ln -fs ../init.d/pdnsd K45pdnsd; \

