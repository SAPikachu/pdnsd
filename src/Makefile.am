# $Id: Makefile.am,v 1.5 2000/10/08 12:16:08 thomas Exp $

YFLAGS=$(yflags)

sbin_PROGRAMS = pdnsd

pdnsd_SOURCES = conf-parse.y conf-lex.l conff.c error.c helpers.c icmp.c status.c netdev.c servers.c dns_answer.c dns_query.c dns.c main.c consts.h dns_query.h helpers.h status.h conff.h dns.h error.h icmp.h netdev.h dns_answer.h ipvers.h servers.h conf-parse.h

pdnsd_LDADD = cacheing/$(cachedbm)/libcache.a -lefence

## Try to do this last

SUBDIRS = cacheing pdnsd-ctl rc test
