/* helpers.h - Various helper functions
   Copyright (C) 2000, 2001 Thomas Moestl

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

/* $Id: helpers.h,v 1.6 2001/04/06 18:11:34 tmm Exp $ */

#ifndef HELPERS_H
#define HELPERS_H

#include "config.h"
#include <pthread.h>
#include "cacheing/cache.h"


#define SOFTLOCK_MAXTRIES 1000

int run_as(char *user);
void pdnsd_exit(void);
int softlock_mutex(pthread_mutex_t *mutex);

int isdchar (unsigned char c);

void rhn2str(unsigned char *rhn, unsigned char *str);
int  str2rhn(unsigned char *str, unsigned char *rhn);

int follow_cname_chain(dns_cent_t *c, unsigned char *name, unsigned char *rrn);

int is_inaddr_any(pdnsd_a *a);
int str2pdnsd_a(char *addr, pdnsd_a *a);
char *pdnsd_a2str(pdnsd_a *a, char *str, int maxlen);

#if DEBUG>0
char *socka2str(struct sockaddr *a, char *str, int maxlen);
#endif

void init_rng(void);
void free_rng(void);
unsigned short get_rand16(void);

void fsprintf(int fd, char *format, ...);

int stricomp(char *a, char *b);

#endif
