/* helpers.c - Various helper functions
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
	while (1)  {
		if (pthread_mutex_trylock(mutex)==0)
			return 1;
		if (tr++>SOFTLOCK_MAXTRIES)
			return 0;
		usleep_r(10000);
	}
	return 0;
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
 * Convert a string given in dotted notation to the transport format (lenght byte prepended
 * domain name parts, ended by a null length sequence)
 */
int str2rhn(unsigned char *str, unsigned char *rhn)
{
	int i=0;
	int cnt=0;
	unsigned char buf[64];
	int lb;
	int tcnt=0;
	
	do {
		lb=0;
		if (lb + cnt >= 255)
			return 0;
		while(isdchar(str[lb+cnt])) {
			if (lb>62)
				return 0;
			buf[lb]=str[lb+cnt];
			lb++;
			if (lb + cnt >= 255)
				return 0;
		}
		if (str[lb+cnt]=='\0') {
			if (lb==0) {
				if (i==0)
					return 0;
				rhn[tcnt]='\0';
				return 1;
			}
			return 0;
		} else if (str[lb+cnt]=='.') {
			i++;
			if (lb+tcnt+1>255) /* 255 because the termination 0 has to follow */
				return 0;
			rhn[tcnt]=(unsigned char)lb;
			tcnt++;
			memcpy(rhn+tcnt,buf,lb);
			tcnt+=lb;
			cnt+=lb+1;
		} else
			return 0;
				
	} while (1);
}

/*
 * Take a host name as used in the dns transfer protocol (a length byte, followed by the
 * first part of the name, ..., followed by a 0 lenght byte), and return a string (in str,
 * length is the same as rhn) in the usual dotted notation. Length checking is done 
 * elsewhere (in decompress_name), this takes names from the cache which are validated.
 * The buffer str points to is assumed to be 256 bytes in size.
 */
void rhn2str(unsigned char *rhn, unsigned char *str)
{
	unsigned char lb;
	int i;
	int cnt=1;

	str[0]='\0';
	lb=rhn[0];
	if (!lb) {
		strcpy((char *)str,".");
		return;
	}
 	while (lb) {
		for (i=0;i<lb;i++) {
			PDNSD_ASSERT(cnt < 255,
			    "rhn2str: string length overflow");
			str[cnt-1]=rhn[cnt];
			cnt++;
		}
		PDNSD_ASSERT(cnt <= 255,
		    "rhn2str: string length overflow");
		str[cnt-1]='.';
		str[cnt]='\0';
		lb=rhn[cnt];
		cnt++;
		if (cnt>255)
			break;
	}
}

/* Return the length of a rhn. This is for better abstraction and could be a macro */
/* int rhnlen(unsigned char *rhn)
{
	return strlen((char *)rhn)+1;
} */

/*
 * Non-validating rhn copy (use with checked or generated data only).
 * Returns number of characters copied. The buffer dst points to is assumed to be 256 (or
 * at any rate large enough) bytes in size.
 * The answer assembly code uses this; it is guaranteed to not clobber anything
 * after the name.
 */
int rhncpy(unsigned char *dst, unsigned char *src)
{
	int len;

	len = rhnlen(src);
	PDNSD_ASSERT(len<=256,"rhncpy: src too long!");
	memcpy((char *)dst,(char *)src,len>256?256:len);
	return len;
}


/* take a name and its rrn (buffer must be 256 bytes), and return the name indicated by the cnames
 * in the record. */
int follow_cname_chain(dns_cent_t *c, unsigned char *name, unsigned char *rrn)
{
	rr_bucket_t *rr;
	if (!(c->rr[T_CNAME-T_MIN] && c->rr[T_CNAME-T_MIN]->rrs))
		return 0;
	rr=c->rr[T_CNAME-T_MIN]->rrs;
	PDNSD_ASSERT(rr->rdlen <= 256, "follow_cname_chain: record too long");
	memcpy(rrn,rr+1,rr->rdlen);
	rhn2str(rrn,name);
	return 1;
}

int str2pdnsd_a(char *addr, pdnsd_a *a)
{
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		return inet_aton(addr,&a->ipv4);
	}
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6) {
		return inet_pton(AF_INET6,addr,&a->ipv6)==1;
	}
#endif
	return 0;
}

/* int is_inaddr_any(pdnsd_a *a)
{
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		return a->ipv4.s_addr==INADDR_ANY;
	}
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6) {
		return IN6_IS_ADDR_UNSPECIFIED(&a->ipv6);
	}
#endif
	return 0;
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
	if (run_ipv6) {
		if (!(res=inet_ntop(AF_INET6,&a->ipv6,buf,maxlen))) {
			log_error("inet_ntop: %s", strerror(errno));
		}
	}
#endif
	return res?res:"?.?.?.?";
}


#if DEBUG>0
/* This is a function only needed by dns_query.c in debug mode. */

const char *socka2str(struct sockaddr *a, char *buf, int maxlen)
{
	const char *res;
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		if (!(res=inet_ntop(AF_INET,&((struct sockaddr_in *)a)->sin_addr,buf,maxlen))) {
			log_error("inet_ntop: %s", strerror(errno));
		}
	}
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6) {
		if (!(res=inet_ntop(AF_INET6,&((struct sockaddr_in6 *)a)->sin6_addr,buf,maxlen))) {
			log_error("inet_ntop: %s", strerror(errno));
		}
	}
#endif
	return res?res:"?.?.?.?";
}

#endif

/* Appropriately set our random device */
#ifdef R_DEFAULT
# if TARGET == TARGET_BSD && !defined(__NetBSD__)
#  define R_ARC4RANDOM 1
# else
#  define R_RANDOM 1
# endif
#endif

#ifdef RANDOM_DEVICE
static FILE *rand_file;
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
		log_error("Could not open %s.");
		return 0;
	}
#endif
#ifdef R_RANDOM
	init_crandom();
#endif
	return 1;
}

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
