# $Id: Makefile.am,v 1.3 2000/11/15 17:27:09 thomas Exp $

sbin_PROGRAMS = pdnsd-ctl

pdnsd_ctl_SOURCES = pdnsd-ctl.c
pdnsd_ctl_LDADD =  rr_types.o
pdnsd_ctl_DEPENDENCIES = rr_types.o

# These are Symlinks we want to have in the package
#EXTRA_DIST = rr_types.h

rr_types.o: %.o: ../%.c
	$(COMPILE) -c $<
