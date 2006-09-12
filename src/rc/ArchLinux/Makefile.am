
#EXTRA_DIST = pdnsd

DISTRO = @distribution@

install-exec-local:
	if [ "$(DISTRO)" = "ArchLinux" ] ; then				\
	  $(mkinstalldirs) $(DESTDIR)/etc/rc.d;				\
	  $(INSTALL_SCRIPT) $(srcdir)/pdnsd $(DESTDIR)/etc/rc.d/pdnsd;	\
	fi



