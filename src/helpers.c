/* helpers.c - Various helper functions
   Copyright (C) 2000, 2001 Thomas Moestl

   With modifications by Paul Rombouts, 2002, 2003.

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

#include <config.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include "ipvers.h"
#include "thread.h"
#include "error.h"
#include "helpers.h"
#include "cache.h"
#include "conff.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: helpers.c,v 1.33 2002/01/03 13:33:06 tmm Exp $";
#endif

/*
 * This is to exit pdnsd from any thread.
 */
void pdnsd_exit()
{
	pthread_kill(main_thread,SIGTERM);
	pthread_exit(NULL);
}

/*
 * Try to grab a mutex. If we can't, fail. This will loop until we get the 
 * mutex or fail. This is only used in debugging code or at exit, otherwise
 * we might run into lock contention problems.
 */
int softlock_mutex(pthread_mutex_t *mutex)
{
	int tr=0;
	while(pthread_mutex_trylock(mutex)) {
		if (++tr>=SOFTLOCK_MAXTRIES)
			return 0;
		usleep_r(10000);
	}
	return 1;
}

/*
 * setuid() and setgid() for a specified user
 */
int run_as(char *user)
{
	struct passwd *pwd;

	if (user[0]!='\0') {
		if (!(pwd=getpwnam(user))) {
			return 0;
		}
		/* setgid first, because we may not allowed to do it anymore after setuid */
		if (setgid(pwd->pw_gid)!=0) {
			return 0;
		}
		if (initgroups(user, pwd->pw_gid)!=0) {
			return 0;
		}
		if (setuid(pwd->pw_uid)!=0) {
			return 0;
		}
	}
	return 1;
}

/*
 * returns whether c is allowed in IN domain names
 */
/* int isdchar (unsigned char c)
{
	if ((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-'
#ifdef UNDERSCORE
	    || c=='_'
#endif
	   )
		return 1;
	return 0;
} */

/*
 * Convert a string given in dotted notation to the transport format (length byte prepended
 * domain name parts, ended by a null length sequence)
 * The memory areas referenced by str and rhn may not overlap.
 * The buffer rhn points to is assumed to be 256 bytes in size.
 */
int str2rhn(const unsigned char *str, unsigned char *rhn)
{
	int n=0,i,j;

	for(i=0;;) {
		int jlim,lb;
		jlim=i+63;
		if(jlim>254) jlim=254; /* 254 because the termination 0 has to follow */
		for(j=i; isdchar(str[j]); ++j) {
			if(j>=jlim) return 0;
			rhn[j+1]=str[j];
		}
		if(!str[j]) break;
		if(str[j]!='.') return 0;
		lb=j-i;
		if (lb>0) {
			rhn[i]=(unsigned char)lb;
			++n;
			i = j+1;
		}
		else
			return 0;
				
	}

	rhn[i]=0;
	if (j>i || n==0)
		return 0;
	return 1;
}

/*
  parsestr2rhn is essentially the same as str2rhn, except that it doesn't look beyond
  the first len chars in the input string. It also tolerates strings
  not ending in a dot and returns a message in case of an error.
 */
const char *parsestr2rhn(const unsigned char *str, int len, unsigned char *rhn)
{
	int n=0,i=0,j;

	do {
		int jlim,lb;
		jlim=i+63;
		if(jlim>254) jlim=254;
		for(j=i; j<len && str[j] && str[j]!='.'; ++j) {
			if(!isdchar(str[j]))
				return "Illegal character in domain name";
			if(j>=jlim)
				return "Domain name element too long";
			rhn[j+1]=str[j];
		}

		lb=j-i;
		if (lb>0) {
			rhn[i]=(unsigned char)lb;
			++n;
			i = j+1;
		}
		else if(j<len && str[j])
			return "Empty name element in domain name";
		else
			break;
	} while(j<len && str[j]);

	rhn[i]=0;
	if(n==0)
		return "Empty or root domain name not allowed";
	return NULL;
}

/*
 * Take a host name as used in the dns transfer protocol (a length byte, followed by the
 * first part of the name, ..., followed by a 0 length byte), and return a string (in str,
 * length is the same as rhn) in the usual dotted notation. Length checking is done 
 * elsewhere (in decompress_name), this takes names from the cache which are validated.
 * The buffer str points to is assumed to be 256 bytes in size.
 */
void rhn2str(const unsigned char *rhn, unsigned char *str)
{
	unsigned char lb;

	lb=rhn[0];
	if (!lb) {
		strcpy(str,".");
	}
	else {
		int i=0;
		do {
			PDNSD_ASSERT(i+lb < 255,
				     "rhn2str: string length overflow");
			for (;lb;--lb) {
				str[i]=rhn[i+1];
				i++;
			}
			str[i]='.';
			i++;
			lb=rhn[i];
		} while(lb);
		str[i]='\0';
	}
}

/* Return the length of a rhn. The definition has in fact been moved to helpers.h as an inline function.
   Note added by Paul Rombouts:
   Compared to the definition used by Thomas Moestl (strlen(rhn)+1), the following definition of rhnlen
   may yield a different result in certain error situations (when a domain name segment contains null byte).
*/
/* unsigned int rhnlen(const unsigned char *rhn)
{
	unsigned int i=0;
	unsigned char lb;

	while((lb=rhn[i]))
		i+=lb+1;
	return i+1;
}
*/

/*
 * Non-validating rhn copy (use with checked or generated data only).
 * Returns number of characters copied. The buffer dst points to is assumed to be 256 (or
 * at any rate large enough) bytes in size.
 * The answer assembly code uses this; it is guaranteed to not clobber anything
 * after the name.
 */
unsigned int rhncpy(unsigned char *dst, const unsigned char *src)
{
	unsigned int len = rhnlen(src);

	PDNSD_ASSERT(len<=256,"rhncpy: src too long!");
	memcpy(dst,src,len>256?256:len);
	return len;
}


/* take a name and its rrn (buffer must be 256 bytes), and return the name indicated by the cnames
 * in the record. */
int follow_cname_chain(dns_cent_t *c, unsigned char *name, unsigned char *rrn)
{
	rr_set_t *rrset=c->rr[T_CNAME-T_MIN];
	rr_bucket_t *rr;
	if (!rrset || !(rr=rrset->rrs))
		return 0;
	PDNSD_ASSERT(rr->rdlen <= 256, "follow_cname_chain: record too long");
	memcpy(rrn,rr+1,rr->rdlen);
	rhn2str(rrn,name);
	return 1;
}

int str2pdnsd_a(const char *addr, pdnsd_a *a)
{
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		return inet_aton(addr,&a->ipv4);
	}
#endif
#ifdef ENABLE_IPV6
	ELSE_IPV6 {
		/* Try to map an IPv4 address to IPv6 */
		struct in_addr a4;
		if(inet_aton(addr,&a4)) {
			a->ipv6=ipv4_6_prefix;
			((uint32_t *)(&a->ipv6))[3]=a4.s_addr;
			return 1;
		}
		return inet_pton(AF_INET6,addr,&a->ipv6)>0;
	}
#endif
	/* return 0; */
}

/* definition moved to helpers.h */
/* int is_inaddr_any(pdnsd_a *a)
{
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		return a->ipv4.s_addr==INADDR_ANY;
	}
#endif
#ifdef ENABLE_IPV6
	ELSE_IPV6 {
		return IN6_IS_ADDR_UNSPECIFIED(&a->ipv6);
	}
#endif
} */

/*
 * This is used for user output only, so it does not matter when an error occurs
 */
const char *pdnsd_a2str(pdnsd_a *a, char *buf, int maxlen)
{
	const char *res;
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		if (!(res=inet_ntop(AF_INET,&a->ipv4,buf,maxlen))) {
			log_error("inet_ntop: %s", strerror(errno));
		}
	}
#endif
#ifdef ENABLE_IPV6
	ELSE_IPV6 {
		if (!(res=inet_ntop(AF_INET6,&a->ipv6,buf,maxlen))) {
			log_error("inet_ntop: %s", strerror(errno));
		}
	}
#endif
	return res?res:"?.?.?.?";
}


/* Appropriately set our random device */
#ifdef R_DEFAULT
# if TARGET == TARGET_BSD && !defined(__NetBSD__)
#  define R_ARC4RANDOM 1
# else
#  define R_RANDOM 1
# endif
#endif

#ifdef RANDOM_DEVICE
FILE *rand_file;
#endif

#ifdef R_RANDOM
void init_crandom()
{
	struct timeval tv;
	struct timezone tz;

	gettimeofday(&tv,&tz);
	srandom(tv.tv_sec^tv.tv_usec); /* not as guessable as time() */
}
#endif

/* initialize the PRNG */
int init_rng()
{
#ifdef RANDOM_DEVICE
	if (!(rand_file=fopen(RANDOM_DEVICE,"r"))) {
		log_error("Could not open %s.",RANDOM_DEVICE);
		return 0;
	}
#endif
#ifdef R_RANDOM
	init_crandom();
#endif
	return 1;
}

/* The following function is now actually defined as a macro in helpers.h */
/* void free_rng()
{
#ifdef RANDOM_DEVICE
	if (rand_file)
		fclose(rand_file);
#endif
} */

/* generate a (more or less) random number. */
unsigned short get_rand16()
{
#ifdef RANDOM_DEVICE
	unsigned short rv;

	if (rand_file) {
		if (fread(&rv,sizeof(rv),1, rand_file)!=1) {
			log_error("Error while reading from random device: %s", strerror(errno));
			pdnsd_exit();
		}
		return rv;
	} else
		return random()&0xffff;
#endif
#ifdef R_RANDOM
	return random()&0xffff;
#endif
#ifdef R_ARC4RANDOM
	return arc4random()&0xffff;
#endif
}

/* the following function has been rewritten by Paul Rombouts */
int fsprintf(int fd, const char *format, ...)
{
	int n;
	va_list va;

	{
		char buf[256];

		va_start(va,format);
		n=vsnprintf(buf,sizeof(buf),format,va);
		va_end(va);

		if(n<sizeof(buf)) {
			if(n>0) n=write_all(fd,buf,n);
			return n;
		}
	}
	/* retry with a right sized buffer, needs glibc 2.1 or higher to work */
	{
		char buf[n+1];

		va_start(va,format);
		n=vsnprintf(buf,sizeof(buf),format,va);
		va_end(va);

		n=write_all(fd,buf,n);
	}
	return n;
}

/*
 * This is not like strcmp, but will return 1 on match or 0 if the
 * strings are different.
 */
/* int stricomp(char *a, char *b)
{
	int i;
	if (strlen(a) != strlen(b)) 
		return 0;
	for (i=0;i<strlen(a);i++) {
		if (tolower(a[i])!=tolower(b[i]))
			return 0;
	}
	return 1;
} */

/* Bah. I want strlcpy */
/*int strncp(char *dst, char *src, int dstsz)
{
	char o;
	
	strncpy(dst,src,dstsz);
	o=dst[dstsz-1];
	dst[dstsz-1]='\0';
	if (strlen(dst) >= dstsz-1 && o!='\0')
		return 0;
	return 1;
} */

#ifndef HAVE_GETLINE
/* Note by Paul Rombouts: I know that getline is a GNU extension and is not really portable,
   but the alternative standard functions have some real problems.
   The following substitute does not have exactly the same semantics as the GNU getline,
   but it should be good enough, as long as the stream doesn't contain any null chars.
   This version is actually based on fgets_realloc() that I found in the WWWOFFLE source.
*/

#define BUFSIZE 256
int getline(char **lineptr, size_t *n, FILE *stream)
{
	char *line=*lineptr;
	size_t sz=*n,i;

	if(!line || sz<BUFSIZE) {
		sz=BUFSIZE;
		line = realloc(line,sz);
		if(!line) return -1;
		*lineptr=line;
		*n=sz;
	}

	for (i=0;;) {
		char *lni;

		if(!(lni=fgets(line+i,sz-i,stream))) {
			if(i && feof(stream))
				break;
			else
				return -1;
		}
			
		i += strlen(lni);

		if(i<sz-1 || line[i-1]=='\n')
			break;

		sz += BUFSIZE;
		line = realloc(line,sz);
		if(!line) return -1;
		*lineptr=line;
		*n=sz;
	}

	return i;
}
#undef BUFSIZE
#endif

#ifndef HAVE_ASPRINTF
int asprintf (char **lineptr, const char *format, ...)
{
	int sz=128,n;
	char *line=malloc(sz);
	va_list va;

	if(!line) return -1;

	va_start(va,format);
	n=vsnprintf(line,sz,format,va);
	va_end(va);

	if(n>=sz) {
		/* retry with a right sized buffer, needs glibc 2.1 or higher to work */
		sz=n+1;
		{
			char *tmp=realloc(line,sz);
			if(!tmp) {
				free(line);
				return -1;
			}
			line=tmp;
		}

		va_start(va,format);
		n=vsnprintf(line,sz,format,va);
		va_end(va);
	}

	if(n>=0)
		*lineptr=line;
	else
		free(line);
	return n;
}
#endif
