# $Id: Makefile.am,v 1.7 2001/05/17 14:14:30 tmm Exp $
#EXTRA_DIST = pdnsd

DISTRO = @distribution@

SPECBUILD = @specbuild@

# no need to create links. 'chkconfig' will take care of this.
# In the spec case, chkconfig is called during rpm install
install-exec-local:
	if [ "$(DISTRO)" = "RedHat" ] ; then \
	  $(mkinstalldirs) $(DESTDIR)/etc/rc.d/init.d; \
	  $(INSTALL_SCRIPT) $(srcdir)/pdnsd $(DESTDIR)/etc/rc.d/init.d/pdnsd; \
	    if [ "$(SPECBUILD)" = "yes" ] ; then \
	      /sbin/chkconfig --add pdnsd \
	    fi \
	fi

#	  $(mkinstalldirs) $(DESTDIR)/etc/rc.d/rc2.d; \
#	  cd $(DESTDIR)/etc/rc.d/rc2.d; \
#	  ln -fs ../init.d/pdnsd K45pdnsd; ln -s ../init.d/pdnsd S12pdnsd; \
#	  cd $$CURDIR ; \
#	  $(mkinstalldirs) $(DESTDIR)/etc/rc.d/rc3.d; \
#	  cd $(DESTDIR)/etc/rc.d/rc3.d; \
#	  ln -fs ../init.d/pdnsd K45pdnsd; ln -s ../init.d/pdnsd S12pdnsd; \
#	  $(mkinstalldirs) $(DESTDIR)/etc/rc.d/rc0.d; \
#	  cd $(DESTDIR)/etc/rc.d/rc3.d; \
#	  ln -fs ../init.d/pdnsd K45pdnsd; \
#	  $(mkinstalldirs) $(DESTDIR)/etc/rc.d/rc6.d; \
#	  cd $(DESTDIR)/etc/rc.d/rc6.d; \
#	  ln -fs ../init.d/pdnsd K45pdnsd; \
#	  $(mkinstalldirs) $(DESTDIR)/etc/rc.d/rc4.d; \
#	  cd $(DESTDIR)/etc/rc.d/rc4.d; \
#	  ln -fs ../init.d/pdnsd K45pdnsd; ln -s ../init.d/pdnsd S12pdnsd; \
#	  cd $$CURDIR ; \
#	  $(mkinstalldirs) $(DESTDIR)/etc/rc.d/rc5.d; \
#	  cd $(DESTDIR)/etc/rc.d/rc5.d; \
#	  ln -fs ../init.d/pdnsd K45pdnsd; ln -s ../init.d/pdnsd S12pdnsd; \
#	  cd $$CURDIR ; \
