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
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "ipvers.h"
#include "error.h"
#include "helpers.h"
#include "cache.h"
#include "conff.h"

/*
 * This is to exit pdnsd from any thread.
 */
void pdnsd_exit()
{
	pthread_kill(main_thread,SIGTERM);
}

/*
 * This is to exit pdnsd from any thread.
 */
void pdnsd_exit()
{
	pthread_kill(main_thread,SIGTERM);
}

/*
 * Takes a string and returns it in lower case using tolower(). Since in
 * dns names there are no special characters allowed anyway, this is sufficient
 */
void strtolower(unsigned char *a)
{
	unsigned int i;
	for (i=0;i<strlen((char *)a);i++) {
		a[i]=tolower(a[i]);
	}
}

/*
 * returns whether c allowed in IN domain names
 */
int isdchar (unsigned char c)
{
	if ((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-')
		return 1;
	return 0;
}

/*
 * Take a host name as used in the dns transfer protocol (a length byte, followed by the
 * first part of the name, ..., followed by a 0 lenght byte), and return a string (in str,
 * length is the same as rhn) in the usual dotted notation.
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
			b2[0]=str[lb+cnt];
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
			if (lb+tcnt+1>255)
				return 0;
			rhn[tcnt]=(unsigned char)lb;
			tcnt++;
			strcpy((char *)&rhn[tcnt],(char *)buf);
			tcnt+=strlen((char *)buf);
			cnt+=lb+1;
		} else
			return 0;
				
	} while (1);
/*	strcat(str,".");*/
}

void rhn2str(unsigned char *rhn, unsigned char *str)
{
	unsigned char lb;
	int i;
	int cnt=1;
	str[0]='\0';
	lb=rhn[0];
	while (lb) {
		for (i=0;i<lb;i++) {
			str[cnt-1]=tolower(rhn[cnt]);
			cnt++;
		}
		str[cnt-1]='.';
		str[cnt]='\0';
		lb=rhn[cnt];
		cnt++;
		if (cnt>254)
			break;
	}
/*	strcat(str,".");*/
}

/*
 * Extract an ip from a domain name for ip-to-hostname resolving (in the .in-addr.arpa. domain).
 * Example: 1.0.0.127.in-addr.arpa. -> 127.0.0.1
 */
int in_addr2ip(struct in_addr *ia, unsigned char *qname)
{
	unsigned char tmp[15];
	int i,n,fd;
	unsigned int d[4];
	unsigned char *pt=qname;
	d[0]=d[1]=d[2]=d[3]=0;
		
	for (i=0;i<4;i++) {
		fd=1;
		n=0;
		while (isdigit(*pt)) {
			fd=0;
			tmp[n]=*pt;
			pt++;
			n++;
		}
		if (fd)
			return 0;
		if (*pt!='.')
			return 0;
		pt++;
		tmp[n]='\0';
		sscanf((char *)tmp,"%u",&d[i]);
		if (d[i]>255)
			return 0;
		if (!isdigit(*pt))
			break;
	}
	if (i<4) {
		for (n=3-i;n>0;n--) {
			d[n+3-i]=d[n];
		}
		for (n=0;n<3-i;n++) {
			d[n]=0xff;
		}
	}
	snprintf((char *)tmp,15,"%u.%u.%u.%u",d[3],d[2],d[1],d[0]);
	inet_aton((char *)tmp,ia); 
	return 1;
}

/* take a name and its rrn (buffer must be 256 bytes, and return the name indicated by the cnames
 * in the record. */
int follow_cname_chain(dns_cent_t *c, unsigned char *name, unsigned char *rrn)
{
	rr_bucket_t *rr;
	if (!(rr=c->rr[T_CNAME-T_MIN]))
		return 0;
	memcpy(rrn,rr+1,rr->rdlen);
	rhn2str(rrn,name);
	return 1;
}

unsigned long get_rr_ttlf(dns_cent_t *c, int tp, short *flags)
{
	time_t ttl=0;
	time_t res;
	int i;
	short tf;
	unsigned char brrn[256], bname[256];
	rr_bucket_t *rrb;

	if (tp>=QT_MIN) {
		switch (tp) {
		case QT_ALL:
			*flags=0;
			for (i=T_MIN;i<=T_MAX;i++) {
				res=get_rr_ttlf(c,i,&tf);
				*flags|=tf;
				if (res>ttl)
					ttl=res;
			}
			break;
		case QT_MAILA:
			*flags=0;
			res=get_rr_ttlf(c,T_MD,&tf);
			*flags|=tf;
			if (res>ttl)
				ttl=res;
			res=get_rr_ttlf(c,T_MF,&tf);
			*flags|=tf;
			if (res>ttl)
				ttl=res;
			break;
		case QT_MAILB:
			*flags=0;
			res=get_rr_ttlf(c,T_MB,&tf);
			*flags|=tf;
			if (res>ttl)
				ttl=res;
			res=get_rr_ttlf(c,T_MG,&tf);
			*flags|=tf;
			if (res>ttl)
				ttl=res;
			res=get_rr_ttlf(c,T_MR,&tf);
			*flags|=tf;
			if (res>ttl)
				ttl=res;
			break;
		}
		return ttl;
	}

	follow_cname_chain(c,bname,brrn);
	*flags=0;
	rrb=c->rr[tp-T_MIN];
	while (rrb) {
		if (!ttl)
			ttl=1;  /* indicate that we actually found a record */
		if (rrb->ts+rrb->ttl>ttl)
			ttl=rrb->ts+rrb->ttl;
		*flags|=rrb->flags; /*combine the flags*/
		rrb=rrb->next;
	}
	return ttl;
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
