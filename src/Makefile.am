# $Id: Makefile.am,v 1.13 2001/05/09 17:51:52 tmm Exp $

sbin_PROGRAMS = pdnsd

pdnsd_SOURCES = conf-parser.c conff.c consts.c debug.c dns.c dns_answer.c dns_query.c error.c helpers.c \
	icmp.c list.c main.c netdev.c rr_types.c status.c servers.c thread.c cache.c hash.c \
	conf-parser.h conf-keywords.h conff.h consts.h debug.h dns.h dns_answer.h dns_query.h error.h helpers.h icmp.h ipvers.h list.h \
	netdev.h rr_types.h servers.h status.h thread.h cache.h hash.h pdnsd_assert.h

## Try to do this last

SUBDIRS = pdnsd-ctl rc test

