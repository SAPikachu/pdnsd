/* helpers.h - Various helper functions
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

/* $Id: helpers.h,v 1.3 2000/06/03 19:59:35 thomas Exp $ */

#ifndef _HELPERS_H_
#define _HELPERS_H_

#include "config.h"
#include "cache.h"

void pdnsd_exit(void);

void strtolower(unsigned char *a);
int isdchar (unsigned char c);

void rhn2str(unsigned char *rhn, unsigned char *str);
int  str2rhn(unsigned char *str, unsigned char *rhn);

int in_addr2ip(struct in_addr *ia, unsigned char *qname);

int follow_cname_chain(dns_cent_t *c, unsigned char *name, unsigned char *rrn);

int is_inaddr_any(pdnsd_a *a);
int str2pdnsd_a(char *addr, pdnsd_a *a);
char *pdnsd_a2str(pdnsd_a *a, char *str, int maxlen);

#if DEBUG>0
char *socka2str(struct sockaddr *a, char *str, int maxlen);
#endif

#endif
