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
#ifndef _DNS_QUERY_H_
#define _DNS_QUERY_H_

#include <sys/types.h>
#include <sys/socket.h>
#ifdef NO_POLL
#include <sys/time.h>
#else
#include <sys/poll.h>
#endif
#include "dns.h"
#include "config.h"
#include "cache.h"

#define PAR_QUERIES   2
#define PAR_GRAN     50

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
	struct sockaddr     *sin;
	int                 sinl;
	long                timeout;
	int                 si;
	int                 flags;
	int                 nocache;
	int                 state;
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

#define QS_INITIAL    0  /* This is the initial state. Set this before starting. */
#define QS_ALLOC      1  /* Resources allocated */
#define QS_CONNECT    2  /* Connected. */
#define QS_LWRITTEN   3  /* Query length has been transmitted. */
#define QS_QWRITTEN   4  /* Query transmitted. */
#define QS_LREAD      5  /* Answer length read */
#define QS_REQUERY    6  /* Requery needed */
#define QS_LWRITTEN2  7  /* Non-RD case of 3 */
#define QS_QWRITTEN2  8  /* Non-RD case of 4 */
#define QS_LREAD2     9  /* Non-RD case of 5 */
#define QS_DONE      10  /* done, resources freed, result is in stat_t */

/* --- parallel query */
int p_dns_resolve(unsigned char *name, unsigned char *rrn , dns_cent_t **cached, int hops, int thint);
int p_dns_cached_resolve(query_serv_t *q, unsigned char *name, unsigned char *rrn , dns_cent_t **cached, int hops, int thint, unsigned long queryts);

#endif
