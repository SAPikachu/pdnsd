# $Id: Makefile.am,v 1.1 2000/07/20 20:03:19 thomas Exp $
EXTRA_DIST = pdnsd

DISTRO = @distribution@

install-exec-local:
	if [ "$(DISTRO)" = "SuSE" ]; then \
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
	  $(mkinstalldirs) $(DESTDIR)/sbin/init.d/rc4.d; \
	  cd $(DESTDIR)/sbin/init.d/rc4.d; \
	  ln -fs ../pdnsd K34pdnsd; ln -s ../pdnsd S11pdnsd; \
	  cd $$CURDIR ; \
	  $(mkinstalldirs) $(DESTDIR)/sbin/init.d/rc5.d; \
	  cd $(DESTDIR)/sbin/init.d/rc5.d; \
	  ln -fs ../pdnsd K34pdnsd; ln -s ../pdnsd S11pdnsd; \
	  cd $$CURDIR ; \
	  $(mkinstalldirs) $(DESTDIR)/sbin/init.d/rc6.d; \
	  cd $(DESTDIR)/sbin/init.d/rc6.d; \
	  ln -fs ../pdnsd K34pdnsd; \
	fi
