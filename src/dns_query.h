/* dns_query.h - Execute outgoing dns queries and write entries to cache

   Copyright (C) 2000, 2001 Thomas Moestl
   Copyright (C) 2002, 2003, 2004, 2006 Paul A. Rombouts

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

#include "cache.h"

typedef struct qhintnode_s qhintnode_t;

/* --- parallel query */
int r_dns_cached_resolve(unsigned char *name, int thint, dns_cent_t **cachedp,
			 int hops, qhintnode_t *qhlist, time_t queryts,
			 unsigned char *c_soa);
#define dns_cached_resolve(name,thint,cachedp,hops,queryts,c_soa) \
        r_dns_cached_resolve(name,thint,cachedp,hops,NULL,queryts,c_soa)

int query_uptest(pdnsd_a *addr, int port, time_t timeout, int rep);

#endif
