/* dns_query.h - Execute outgoing dns queries and write entries to cache
   Copyright (C) 2000 Thomas Moestl

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

/* $Id: dns_query.h,v 1.7 2000/07/10 12:08:52 thomas Exp $ */

#ifndef _DNS_QUERY_H_
#define _DNS_QUERY_H_

#include "config.h"
#include <sys/types.h>
#include <sys/socket.h>
#ifdef NO_POLL
#include <sys/time.h>
#else
#include <sys/poll.h>
#endif
#include "dns.h"
#include "cache.h"

#define PAR_QUERIES   2
#define PAR_GRAN     50

#define UDP_ONLY 1
#define TCP_ONLY 2
#define TCP_UDP  3

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
	} a;
	int                 s_offs;
	struct sockaddr     *sin;
	int                 sinl;
	long                timeout;
	int                 si;
	int                 flags;
	int                 nocache;
	int                 state;
	int                 nstate;
	int                 qm;
	char                trusted;
	unsigned char       nsdomain[256];
	/* internal state for p_exec_query */
	int                 sock;
/*	dns_cent_t          nent;
	dns_cent_t          servent;*/
	unsigned short      transl;
	unsigned short      recvl;
	dns_hdr_t           *hdr;
	long                rts;
	int                 myrid;
	dns_hdr_t           *recvbuf;
	int                 qt;
	char                lean_query;
#ifdef NO_POLL
	fd_set              writes;
	struct timeval      tv;
#else
	struct pollfd       polls;
#endif
} query_stat_t;

typedef struct {
	int           num;
	query_stat_t  *qs;
} query_serv_t;

#define QS_INITIAL       0  /* This is the initial state. Set this before starting. */
#define QS_QUERY         1
#define QS_DONE         11  /* done, resources freed, result is in stat_t */


#define QSN_TCPINITIAL   1  /* Start a TCP query. */
#define QSN_TCPALLOC     2  /* Resources allocated */
#define QSN_TCPCONNECT   3  /* Connected. */
#define QSN_TCPLWRITTEN  4  /* Query length has been transmitted. */
#define QSN_TCPQWRITTEN  5  /* Query transmitted. */
#define QSN_TCPLREAD     6  /* Answer length read */

#define QSN_UDPINITIAL  20  /* Start a UDP query */
#define QSN_UDPTRANSMIT 21  /* Start a UDP query */
#define QSN_UDPRECEIVE  22  /* Start a UDP query */

#define QSN_DONE        11

/* --- parallel query */
int p_dns_cached_resolve(query_serv_t *q, unsigned char *name, unsigned char *rrn , dns_cent_t **cached, int hops, int thint, time_t queryts);

#endif
