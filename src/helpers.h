/* helpers.h - Various helper functions

   Copyright (C) 2000, 2001 Thomas Moestl
   Copyright (C) 2002, 2003, 2004 Paul A. Rombouts

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
#include <string.h>
#include <ctype.h>
#include "cache.h"
#include "pdnsd_assert.h"

#define SOFTLOCK_MAXTRIES 1000

int run_as(const char *user);
void pdnsd_exit(void);
int softlock_mutex(pthread_mutex_t *mutex);

#if 0
inline static int isdchar (unsigned char c)
{
  return ((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-'
#ifdef UNDERSCORE
	  || c=='_'
#endif
	  );
}
#endif

const unsigned char *rhn2str(const unsigned char *rhn, unsigned char *str, int size);
int  str2rhn(const unsigned char *str, unsigned char *rhn);
const char *parsestr2rhn(const unsigned char *str, int len, unsigned char *rhn);

/* Note added by Paul Rombouts:
   Compared to the definition used by Thomas Moestl (strlen(rhn)+1), the following definition of rhnlen
   may yield a different result in certain error situations (when a domain name segment contains null byte).
*/
inline static unsigned int rhnlen(const unsigned char *rhn)
{
	unsigned int i=0,lb;

	while((lb=rhn[i]))
		i+=lb+1;
	return i+1;
}

/* Skip k segments in a name in length-byte string notation. */
inline static unsigned char *skipsegs(unsigned char *nm, unsigned k)
{
	unsigned lb;
	for(;k;--k) {
		lb= *nm;
		if(!lb) return nm;
		nm += lb+1;
	}
	return nm;
}

/* Skip a name in length-byte string notation and return a pointer to the
   position right after the terminating null byte.
*/
inline static unsigned char *skiprhn(unsigned char *rhn)
{
	unsigned lb;

	while((lb= *rhn))
		rhn += lb+1;
	return rhn+1;
}

/* count the number of name segments of a name in length-byte string notation. */
inline static unsigned int rhnsegcnt(const unsigned char *rhn)
{
	unsigned int res=0,lb;

	while((lb= *rhn)) {
		++res;
		rhn += lb+1;
	}
	return res;
}

unsigned int rhncpy(unsigned char *dst, const unsigned char *src);

int follow_cname_chain(dns_cent_t *c, unsigned char *name);

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

int str2pdnsd_a(const char *addr, pdnsd_a *a);
const char *pdnsd_a2str(pdnsd_a *a, char *buf, int maxlen);

int init_rng(void);
#ifdef RANDOM_DEVICE
extern FILE *rand_file;
/* Because this is usually empty, it is now defined as a macro to save overhead.*/
#define free_rng() {if (rand_file) fclose(rand_file);}
#else
#define free_rng()
#endif

unsigned short get_rand16(void);

int fsprintf(int fd, const char *format, ...) printfunc(2, 3);
#if defined(__GNUC__) && (__GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 95))
# define fsprintf_or_return(args...) {int _retval; if((_retval=fsprintf(args))<0) return _retval;}
#else
/* ANSI style variadic macro. */
# define fsprintf_or_return(...) {int _retval; if((_retval=fsprintf(__VA_ARGS__))<0) return _retval;}
#endif

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

void hexdump(const void *data, int dlen, char *buf, int buflen);
int escapestr(char *in, int ilen, char *str, int size);

#if 0
inline static int stricomp(const char *a, const char *b)
{
  return !strcasecmp(a,b);
}
#endif

/* compare two names in length byte - string format */
inline static int rhnicmp(const unsigned char *a, const unsigned char *b)
{
	int i=0;
	unsigned char lb;
	for(;;) {
		lb=a[i];
		if(lb!=b[i]) return 0;
		if(!lb) break;
		++i;
		do {
			if(tolower(a[i])!=tolower(b[i])) return 0;
			++i;
		} while(--lb);
	}
	return 1;
}

/* Bah. I want strlcpy. */
inline static int strncp(char *dst, const char *src, size_t dstsz)
{
#ifdef HAVE_STRLCPY
	return (strlcpy(dst,src,dstsz)<dstsz);
#else
#ifdef HAVE_STPNCPY
	char *p=stpncpy(dst,src,dstsz);
	if(p<dst+dstsz) return 1;
	*(p-1)='\0';
	return 0;
#else
	strncpy(dst,src,dstsz);
	if(strlen(src)<dstsz) return 1;
	dst[dstsz-1]='\0';
	return 0;
#endif
#endif
}

#ifndef HAVE_STRDUP
inline static char *strdup(const char *s)
{
	size_t sz=strlen(s)+1;
	char *cp=malloc(sz);
	if(cp)
		memcpy(cp,s,sz);
	return cp;
}
#endif

#ifndef HAVE_STRNDUP
/* This version may allocate a buffer that is unnecessarily large,
   but I'm always going to use it with n<strlen(s)
*/
inline static char *strndup(const char *s, size_t n)
{
	char *cp;
	cp=malloc(n+1);
	if(cp) {
		memcpy(cp,s,n);
		cp[n]='\0';
	}
	return cp;
}
#endif

#ifndef HAVE_STPCPY
inline static char *stpcpy (char *dest, const char *src)
{
  register char *d = dest;
  register const char *s = src;

  while ((*d++ = *s++) != '\0');

  return d - 1;
}
#endif

#ifndef HAVE_MEMPCPY
inline static void *mempcpy(void *dest, const void *src, size_t len)
{
  memcpy(dest,src,len);
  return ((char *)dest)+len;
}
#endif

#ifndef HAVE_GETLINE
int getline(char **lineptr, size_t *n, FILE *stream);
#endif

#ifndef HAVE_ASPRINTF
int asprintf (char **lineptr, const char *format, ...);
#endif

#ifndef HAVE_VASPRINTF
int vasprintf (char **lineptr, const char *format, va_list va);
#endif

#ifndef HAVE_INET_NTOP
const char *inet_ntop(int af, const void *src, char *dst, size_t size);
#endif

#define strlitlen(strlit) (sizeof(strlit)-1)

#endif /* HELPERS_H */
