# $Id: Makefile.am,v 1.12 2001/04/12 18:48:22 tmm Exp $

YFLAGS=$(yflags)

sbin_PROGRAMS = pdnsd

pdnsd_SOURCES = conf-parse.y conf-lex.l conff.c consts.c debug.c dns.c dns_answer.c dns_query.c error.c helpers.c \
	icmp.c list.c main.c netdev.c rr_types.c status.c servers.c thread.c \
	conff.h conf-parse.h consts.h debug.h dns.h dns_answer.h dns_query.h error.h helpers.h icmp.h ipvers.h list.h \
	netdev.h rr_types.h servers.h status.h thread.h

pdnsd_LDADD = cacheing/$(cachedbm)/libcache.a

# These are Symlinks we want to have in the package
# EXTRA_DIST = config.h

## Try to do this last

SUBDIRS = cacheing pdnsd-ctl rc test

