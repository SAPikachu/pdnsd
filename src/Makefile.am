# $Id: Makefile.am,v 1.10 2000/11/15 17:27:02 thomas Exp $

YFLAGS=$(yflags)

sbin_PROGRAMS = pdnsd

pdnsd_SOURCES = conf-parse.y conf-lex.l conff.c error.c thread.c helpers.c icmp.c status.c netdev.c servers.c dns_answer.c dns_query.c dns.c rr_types.c consts.c main.c consts.h dns_query.h helpers.h status.h conff.h dns.h rr_types.h error.h thread.h icmp.h netdev.h dns_answer.h ipvers.h servers.h conf-parse.h

pdnsd_LDADD = cacheing/$(cachedbm)/libcache.a

# These are Symlinks we want to have in the package
# EXTRA_DIST = config.h

## Try to do this last

SUBDIRS = cacheing pdnsd-ctl rc test

