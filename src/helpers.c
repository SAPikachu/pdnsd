/* helpers.c - Various helper functions
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
#include "config.h"
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
#include "cacheing/cache.h"
#include "conff.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: helpers.c,v 1.9 2000/11/11 14:24:48 thomas Exp $";
#endif

/*
 * This is to exit pdnsd from any thread.
 */
void pdnsd_exit()
{
	pthread_kill(main_thread,SIGTERM);
}

/*
 * Try to grab a mutex. If we can't, fail
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
int isdchar (unsigned char c)
{
	if ((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-')
		return 1;
	return 0;
}

/*
 * Convert a string given in dotted notation to the transport format (lenght byte prepended
 * domain name parts, ended by a null length sequence)
 */
int str2rhn(unsigned char *str, unsigned char *rhn)
{
	int i=0;
	int cnt=0;
	unsigned char buf[64];
	unsigned char b2[2];
	int lb;
	int tcnt=0;
	b2[0]=b2[1]='\0';
	
	do {
		lb=0;
		buf[0]='\0';
		while(isdchar(str[lb+cnt])) {
			if (lb>62)
				return 0;
			b2[0]=tolower(str[lb+cnt]);
			strcat((char *)buf,(char *)b2);
			lb++;
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
			if (lb+tcnt+1>254) /* 254 because the termination 0 has to follow */
				return 0;
			rhn[tcnt]=(unsigned char)lb;
			tcnt++;
			strcpy((char *)&rhn[tcnt],(char *)buf);
			tcnt+=strlen((char *)buf);
			cnt+=lb+1;
		} else
			return 0;
				
	} while (1);
}

/*
 * Take a host name as used in the dns transfer protocol (a length byte, followed by the
 * first part of the name, ..., followed by a 0 lenght byte), and return a string (in str,
 * length is the same as rhn) in the usual dotted notation. Length checking is done 
 * elsewhere (in decompress_name).
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
			str[cnt-1]=tolower(rhn[cnt]);
			cnt++;
		}
		str[cnt-1]='.';
		str[cnt]='\0';
		lb=rhn[cnt];
		cnt++;
		if (cnt>255)
			break;
	}
}

/* take a name and its rrn (buffer must be 256 bytes), and return the name indicated by the cnames
 * in the record. */
int follow_cname_chain(dns_cent_t *c, unsigned char *name, unsigned char *rrn)
{
	rr_bucket_t *rr;
	if (!(c->rr[T_CNAME-T_MIN] && c->rr[T_CNAME-T_MIN]->rrs))
		return 0;
	rr=c->rr[T_CNAME-T_MIN]->rrs;
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
		return inet_pton(AF_INET6,addr,&a->ipv6);
	}
#endif
	return 0;
}

int is_inaddr_any(pdnsd_a *a)
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
}

char *pdnsd_a2str(pdnsd_a *a, char *str, int maxlen)
{
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		strncpy(str,inet_ntoa(a->ipv4),maxlen);
		str[maxlen-1]='\0';
	}
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6) {
		inet_ntop(AF_INET6,&a->ipv6,str,maxlen);
	}
#endif
	return str;
}


#ifdef DEBUG
/* This is a function only needed by dns_query.c in debug mode. */

char *socka2str(struct sockaddr *a, char *str, int maxlen)
{
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		strncpy(str,inet_ntoa(((struct sockaddr_in *)a)->sin_addr),maxlen);
		str[maxlen-1]='\0';
	}
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6) {
		inet_ntop(AF_INET6,&((struct sockaddr_in6 *)a)->sin6_addr,str,maxlen);
	}
#endif
	return str;
}

#endif

#ifdef RANDOM_DEVICE
static FILE *rand_file;
#endif

/* initialize the RNG */
void init_rng()
{
	struct timeval tv;
	struct timezone tz;
#ifdef RANDOM_DEVICE
	if (!(rand_file=fopen(RANDOM_DEVICE,"r"))) {
		log_warn("Could not open %s. Will use the internal random() function, which might be less secure.");
#endif
		gettimeofday(&tv,&tz);
		srandom(tv.tv_sec^tv.tv_usec); /* not as guessable as time() */
#ifdef RANDOM_DEVICE
	}
#endif
}

void free_rng()
{
#ifdef RANDOM_DEVICE
	if (rand_file)
		fclose(rand_file);
#endif
}

/* generate a (more or less) random number. */
unsigned short get_rand16()
{
#ifdef RANDOM_DEVICE
	unsigned short rv;

	if (rand_file) {
		fread(&rv,sizeof(unsigned short),1, rand_file);
		return rv;
	} else {
#endif
		return random()&0xffff;
#ifdef RANDOM_DEVICE
	}
#endif
}

void fsprintf(int fd, char *format, ...)
{
	char buf[1024];

	va_list va;
	va_start(va,format);
	vsnprintf(buf,1023,format,va);
	write(fd,buf,strlen(buf));

	va_end(va);
}

/*
 * This is not like strcmp, but will return 1 on match or 0 if the
 * strings are different.
 */
int stricomp(char *a, char *b)
{
	int i;
	if (strlen(a) != strlen(b)) 
		return 0;
	for (i=0;i<strlen(a);i++) {
		if (tolower(a[i])!=tolower(b[i]))
			return 0;
	}
	return 1;
}
