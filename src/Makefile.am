# $Id: Makefile.am,v 1.1 2000/07/20 20:03:10 thomas Exp $

YFLAGS=@yflags@

sbin_PROGRAMS = pdnsd

pdnsd_SOURCES = conf-parse.y conf-lex.l conff.c hash.c error.c helpers.c cache.c icmp.c status.c netdev.c servers.c dns_answer.c dns_query.c dns.c main.c cache.h consts.h dns_query.h helpers.h status.h conff.h dns.h error.h icmp.h netdev.h config.h dns_answer.h hash.h ipvers.h servers.h conf-parse.h

## Try to do this last

SUBDIRS = rc test
