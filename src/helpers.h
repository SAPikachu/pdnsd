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
#include <unistd.h>
#include "cache.h"
#include "pdnsd_assert.h"

#define SOFTLOCK_MAXTRIES 1000

int run_as(char *user);
void pdnsd_exit(void);
int softlock_mutex(pthread_mutex_t *mutex);

inline static int isdchar (unsigned char c)
{
  return ((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-'
#ifdef UNDERSCORE
	  || c=='_'
#endif
	  );
}

void rhn2str(unsigned char *rhn, unsigned char *str);
int  str2rhn(unsigned char *str, unsigned char *rhn);
int rhnlen(unsigned char *rhn);
int rhncpy(unsigned char *dst, unsigned char *src);

int follow_cname_chain(dns_cent_t *c, unsigned char *name, unsigned char *rrn);

inline static int is_inaddr_any(pdnsd_a *a)
{
  return
#ifdef ENABLE_IPV4
# ifdef ENABLE_IPV6
    run_ipv4? a->ipv4.s_addr==INADDR_ANY:
# else
    a->ipv4.s_addr==INADDR_ANY
# endif
#endif
#ifdef ENABLE_IPV6
    IN6_IS_ADDR_UNSPECIFIED(&a->ipv6)
#endif
    ;
}

inline static int same_inaddr(pdnsd_a *a, pdnsd_a *b)
{
  return
#ifdef ENABLE_IPV4
# ifdef ENABLE_IPV6
    run_ipv4? a->ipv4.s_addr==b->ipv4.s_addr:
# else
    a->ipv4.s_addr==b->ipv4.s_addr
# endif
#endif
#ifdef ENABLE_IPV6
    IN6_ARE_ADDR_EQUAL(&a->ipv6,&b->ipv6)
#endif
    ;
}

int str2pdnsd_a(char *addr, pdnsd_a *a);
char *pdnsd_a2str(pdnsd_a *a, char *str, int maxlen);

#if DEBUG>0
char *socka2str(struct sockaddr *a, char *str, int maxlen);
#endif

int init_rng(void);
void free_rng(void);
unsigned short get_rand16(void);

int fsprintf(int fd, const char *format, ...) printfunc(2, 3);

/* Added by Paul Rombouts */
inline static int write_all(int fd,const void *data,int n)
{
  int written=0;

  while(written<n) {
      int m=write(fd,(const void*)(((const char*)data)+written),n-written);

      if(m<0)
	return m;

      written+=m;
    }

  return written;
}


inline static int stricomp(const char *a, const char *b)
{
  return !strcasecmp(a,b);
}

/* Bah. I want strlcpy. */
inline static int strncp(char *dst, const char *src, int dstsz)
{
  char *p=stpncpy(dst,src,dstsz);
  if(p<dst+dstsz) return 1;
  *(p-1)='\0';
  return 0;
}

#endif
