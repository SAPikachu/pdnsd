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

/* $Id: helpers.h,v 1.11 2001/06/02 20:12:45 tmm Exp $ */

#ifndef HELPERS_H
#define HELPERS_H

#include <config.h>
#include <pthread.h>
#include "cache.h"

/* format string checking for printf-like functions */
#ifdef __GNUC__
#define printfunc(fmt, firstva) __attribute__((__format__(__printf__, fmt, firstva)))
#else
#define printfunc(fmt, firstva)
#endif

#define SOFTLOCK_MAXTRIES 1000

int run_as(char *user);
void pdnsd_exit(void);
int softlock_mutex(pthread_mutex_t *mutex);

int isdchar (unsigned char c);

void rhn2str(unsigned char *rhn, unsigned char *str);
int  str2rhn(unsigned char *str, unsigned char *rhn);
int rhnlen(unsigned char *rhn);
int rhncpy(unsigned char *dst, unsigned char *src);

int follow_cname_chain(dns_cent_t *c, unsigned char *name, unsigned char *rrn);

int is_inaddr_any(pdnsd_a *a);
int str2pdnsd_a(char *addr, pdnsd_a *a);
char *pdnsd_a2str(pdnsd_a *a, char *str, int maxlen);

#if DEBUG>0
char *socka2str(struct sockaddr *a, char *str, int maxlen);
#endif

int init_rng(void);
void free_rng(void);
unsigned short get_rand16(void);

void fsprintf(int fd, char *format, ...) printfunc(2, 3);

int stricomp(char *a, char *b);

/* Bah. I want strlcpy. */
int strncp(char *dst, char *src, int dstsz);

#endif
