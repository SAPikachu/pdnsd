/* dns_query.h - Execute outgoing dns queries and write entries to cache
   Copyright (C) 2000, 2001 Thomas Moestl

   With modifications by Paul Rombouts, 2002, 2003, 2004.

This file is part of the pdnsd package.

pdnsd is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

pdnsd is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pdsnd; see the file COPYING.  If not, write to
the Free Software Foundation, 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

/* $Id: dns_query.h,v 1.6 2001/05/09 17:51:52 tmm Exp $ */

#ifndef DNS_QUERY_H
#define DNS_QUERY_H

#include <config.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifdef NO_POLL
#include <sys/time.h>
#else
#include <sys/poll.h>
#endif
#include "dns.h"
#include "cache.h"

extern int query_method;

/* --- structures and state constants for parallel query */
typedef struct {
	union {
#ifdef ENABLE_IPV4
		struct sockaddr_in  sin4;
#endif
#ifdef ENABLE_IPV6
		struct sockaddr_in6 sin6;
#endif
	}                   a;
	time_t              timeout;
	unsigned short      flags;
	short               nocache;
	short               state;
	short               qm;
	char                trusted;
        char                auth_serv;
	char                lean_query;
	char                needs_testing;
	unsigned char       *nsdomain;
	/* internal state for p_exec_query */
	int                 sock;
/*	dns_cent_t          nent;
	dns_cent_t          servent;*/
	unsigned short      transl;
	unsigned short      recvl;
#ifndef NO_TCP_QUERIES
	int                 iolen;  /* number of bytes written or read up to now */
#endif
	dns_hdr_t           *hdr;
	dns_hdr_t           *recvbuf;
	unsigned short      myrid;
	unsigned short      qt;
	int                 s_errno;
} query_stat_t;
typedef DYNAMIC_ARRAY(query_stat_t) *query_stat_array;

#define QS_INITIAL       0  /* This is the initial state. Set this before starting. */

#define QS_TCPINITIAL    1  /* Start a TCP query. */
#define QS_TCPWRITE      2  /* Waiting to write data. */
#define QS_TCPREAD       3  /* Waiting to read data. */

#define QS_UDPINITIAL    4  /* Start a UDP query */
#define QS_UDPRECEIVE    5  /* UDP query transmitted, waiting for response. */

#define QS_QUERY_CASES   case QS_TCPINITIAL: case QS_TCPWRITE: case QS_TCPREAD: case QS_UDPINITIAL: case QS_UDPRECEIVE
#define QS_DONE          8  /* done, resources freed, result is in stat_t */


/* Events to be polled/selected for */
#define QS_WRITE_CASES case QS_TCPWRITE
#define QS_READ_CASES  case QS_TCPREAD: case QS_UDPRECEIVE

/* --- parallel query */
int p_dns_cached_resolve(query_stat_array q, unsigned char *name, unsigned char *rrn , dns_cent_t **cached, int hops, int thint, time_t queryts);

#endif
