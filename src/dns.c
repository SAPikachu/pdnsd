/* dns.c - Declarations for dns handling and generic dns functions
   Copyright (C) 2000, 2001 Thomas Moestl

   With modifications by Paul Rombouts, 2002, 2003, 2004.

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
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "error.h"
#include "helpers.h"
#include "dns.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: dns.c,v 1.31 2002/01/03 17:47:20 tmm Exp $";
#endif

/* Decompress a name record, taking the whole message as msg, returning its results in tgt (max. 255 chars),
 * taking sz as the remaining msg size (it is returned decremented by the name length, ready for further use) and
 * a source pointer (it is returned pointing to the location after the name). msgsize is the size of the whole message,
 * len is the total name length.
 * msg and msgsz are needed for decompression (see rfc1035). The returned data is decompressed, but still in the
 * rr name form (length byte - string of that length, terminated by a 0 lenght byte).
 * If uscore is NULL, an underscore will be treated as illegal (except when UNDERSCORE is defined). Otherwise,
 * *uscore will be set to 0 if the name contained no underscores, and to 1 otherwise.
 *
 * Returned is a dns return code, with one exception: RC_TRUNC, as defined in dns.h, indicates that the message is
 * truncated at the name (which needs a special return code, as it might or might not be fatal).
 */
int decompress_name(unsigned char *msg, unsigned char *tgt, unsigned char **src, long *sz, long msgsz, int *len, int *uscore)
{
	unsigned char lb;
	int jumped=0;
	long offs;
	unsigned char *lptr;
	int i;
	int hops=0;
	int tpos=0;
	long osz=*sz;

	if (!*sz)
		return RC_TRUNC;
	if (uscore!=NULL)
		*uscore=0;
	lptr=*src;
	while (1) {
		if (lptr-msg>=msgsz)
			return RC_FORMAT;
		if (!jumped)
			if (*sz<=0)
				return RC_FORMAT;
		if (tpos>255)
			return RC_FORMAT;
		if (!jumped)
			(*sz)--;
		lb=*lptr;
		lptr++;

		do {
 			if (lb>63 && lb<192)     /* The two highest bits must be either 00 or 11 */
				return RC_FORMAT;
			if (lb>=192) {
				if (lptr-msg>=msgsz)
					return RC_FORMAT;
				if (!jumped) {
					if ((*sz)<1)
						return RC_TRUNC;
					(*sz)--;
					jumped=1;

				}
				offs=(((unsigned short)lb&0x3f)<<8)|(*lptr);
				if (offs>=msgsz) 
					return RC_FORMAT;
				lptr=msg+offs;
				hops++;
				if (hops>255)
					return RC_FORMAT;
				lb=*lptr;
				lptr++;
			}
		} while (lb>63);
 		tgt[tpos]=lb;
		tpos++;
		if (lb==0) {
			break;
		}
		for (i=0;i<lb;i++) {
			if (lptr-msg>=msgsz)
				return RC_FORMAT;
			if (!jumped) {
				if (*sz<=0)
					return RC_TRUNC;
			}
			if (tpos>=255)
				return RC_FORMAT;
			if (!isdchar(*lptr) && (uscore==NULL || *lptr!='_'))
				return RC_FORMAT;
			if (*lptr=='_' && uscore!=NULL)
				*uscore=1;
			tgt[tpos]=*lptr;
			lptr++;
			tpos++;
			if (!jumped) {
				(*sz)--;
			}
		}
	}
	*src+=osz-*sz;
	if(len) *len=tpos;
	return RC_OK;
}

/* Compare the names (in length byte-string notation) back-to-forth and return the longest match.
   The comparison is done at name granularity.
   The return value is the length of the match in name elements.
   *os (*od) is set to the offset in the domain name ms (md) of the match.
 */
int domain_match(const unsigned char *ms, const unsigned char *md, int *os, int *od)
{
	int i,j,k,n,ns=0,nd=0,offs,offd;
	unsigned char lb,ls[128],ld[128];

	/* first collect all length bytes */
	i=0;
	while((lb=ms[i])) {
		PDNSD_ASSERT(ns<128, "domain_match: too many name segments");
		ls[ns++]=lb;
		i += lb+1;
	}

	j=0;
	while((lb=md[j])) {
		PDNSD_ASSERT(nd<128, "domain_match: too many name segments");
		ld[nd++]=lb;
		j += lb+1;
	}

	n=ns;  if(n>nd) n=nd;

	for(k=1; offs=i,offd=j,k<=n; ++k) {
		lb=ls[ns-k];
		if(lb!=ld[nd-k]) goto mismatch;
		for(;lb;--lb)
			if(tolower(ms[--i]) != tolower(md[--j])) goto mismatch;
		--i; --j;
	}
 mismatch:

	if(os) *os=offs;
	if(od) *od=offd;
	return k-1;
}

/* compress the domain name in in and put the result (of maximum length of strlen(in)) and
 * fill cb with compression information for further strings.*cb may be NULL initially. 
 * offs is the offset the generated string will be placed in the packet.
 * retval: 0 - error, otherwise length
 * When done, just free() cb (if it is NULL, free will behave correctly).
 * It is guaranteed (and insured by assertions) that the output is smaller or equal in
 * size to the input.
 */
int compress_name(unsigned char *in, unsigned char *out, int offs, compel_array *cb)
{
	int i;
	int add=1;
	int longest=0,lrem=0,coffs=0;
	int rl=0;
	int ilen = rhnlen(in);

	PDNSD_ASSERT(ilen<=256, "compress_name: name too long");

	/* part 1: compression */
	for (i=0;i<DA_NEL(*cb);i++) {
		int rv,rem,to;
		if ((rv=domain_match(in, DA_INDEX(*cb,i).s, &rem,&to))>longest) {
			/*
			 * This has some not obvious implications that should be noted: If a 
			 * domain name as saved in the list has been compressed, we only can
			 * index the non-compressed part. We rely here that the first occurence
			 * can't be compressed. So we take the first occurence of a given length.
			 * This works perfectly, but watch it if you change something.
			 */
			longest=rv;
			lrem=rem;
			coffs=DA_INDEX(*cb,i).index+to;
		}
	}
	if (longest>0) {
		PDNSD_ASSERT(lrem+2 <= ilen, "compress_name: length increased");
		memcpy(out, in,lrem);
		out[lrem]=0xc0|((coffs&0x3f00)>>8);
		out[lrem+1]=coffs&0xff;
		rl=lrem+2;
		add= lrem!=0;
	}
	else {
		memcpy(out,in,ilen);
		rl=ilen;
	}

	/* part 2: addition to the cache structure */
	if (add) {
		if (!(*cb=DA_GROW1(*cb)))
			return 0;
		DA_LAST(*cb).index=offs;
		memcpy(DA_LAST(*cb).s,in,ilen);
	}
	return rl;
}


typedef	struct {
	struct in_addr ipv4;
#ifdef ENABLE_IPV6
	struct in6_addr ipv6;
#endif
} pdnsd_ca;

/*
 * Add records for a host as read from a hosts-style file.
 * Returns 1 on success, 0 in an out of memory condition, and -1 when there was a problem with
 * the record data.
 */
static int add_host(unsigned char *pn, unsigned char *rns, unsigned char *b3, pdnsd_ca *a, int a_sz, time_t ttl, int flags, int tp, int reverse)
{
	dns_cent_t ce;

	if (!init_cent(&ce, pn, flags, time(NULL), 0  DBG0))
		return 0;
#ifdef ENABLE_IPV4
	if (tp==T_A) {
		if (!add_cent_rr(&ce,ttl,0,CF_LOCAL,a_sz,&a->ipv4,tp  DBG0))
			goto free_cent_return0;
	}
#endif
#if defined(DNS_NEW_RRS) && defined(ENABLE_IPV6)
	if (tp==T_AAAA) {
		if (!add_cent_rr(&ce,ttl,0,CF_LOCAL,a_sz,&a->ipv6,tp  DBG0))
			goto free_cent_return0;
	}
#endif
	if (!add_cent_rr(&ce,ttl,0,CF_LOCAL,rhnlen(rns),rns,T_NS  DBG0))
		goto free_cent_return0;
	add_cache(&ce);
	free_cent(&ce  DBG0);
	if (reverse) {
		unsigned char b2[256],rhn[256];
#ifdef ENABLE_IPV4
		if (tp==T_A) {
# if TARGET==TARGET_BSD
			snprintf(b2,256,"%li.%li.%li.%li.in-addr.arpa.",ntohl(a->ipv4.s_addr)&0xffl,(ntohl(a->ipv4.s_addr)>>8)&0xffl,
				 (ntohl(a->ipv4.s_addr)>>16)&0xffl, (ntohl(a->ipv4.s_addr)>>24)&0xffl);
# else
			snprintf(b2,256,"%i.%i.%i.%i.in-addr.arpa.",ntohl(a->ipv4.s_addr)&0xff,(ntohl(a->ipv4.s_addr)>>8)&0xff,
				 (ntohl(a->ipv4.s_addr)>>16)&0xff, (ntohl(a->ipv4.s_addr)>>24)&0xff);
# endif
		}
		else
#endif
#if defined(DNS_NEW_RRS) && defined(ENABLE_IPV6)
		if (tp==T_AAAA) {
			unsigned char b4[7];
			int i;
			b2[0]='\0';
			for (i=15;i>=0;i--) {
				snprintf(b4, sizeof(b4),"%x.%x.",((unsigned char *)&a->ipv6)[i]&&0xf,(((unsigned char *)&a->ipv6)[i]&&0xf0)>>4);
				strncat(b2,b4,sizeof(b2)-strlen(b2)-1);
			}
			strncat(b2,"ip6.int.",sizeof(b2)-strlen(b2)-1);
		}
		else
#endif
			return -1;
		if (!str2rhn(b2,rhn))
			return -1;
		if (!init_cent(&ce, b2, flags, time(NULL), 0  DBG0))
			return 0;
		if (!add_cent_rr(&ce,ttl,0,CF_LOCAL,rhnlen(b3),b3,T_PTR  DBG0))
			goto free_cent_return0;
		if (!add_cent_rr(&ce,ttl,0,CF_LOCAL,rhnlen(rns),rns,T_NS  DBG0))
			goto free_cent_return0;
		add_cache(&ce);
		free_cent(&ce  DBG0);
	}
	return 1;

 free_cent_return0:
	free_cent(&ce  DBG0);
	return 0;
}

/*
 * Read a file in /etc/hosts-format and add generate rrs for it.
 * Errors are largely ignored so that we can skip entries we do not understand
 * (but others possibly do).
 */
int read_hosts(char *fn, unsigned char *rns, time_t ttl, int flags, int aliases, char **errstr)
{
	int rv=0;
	FILE *f;
	char *buf;
	size_t buflen=256;

	if (!(f=fopen(fn,"r"))) {
		if(asprintf(errstr, "Failed to source %s: %s", fn, strerror(errno))<0) *errstr=NULL;
		return 0;
	}
	buf=malloc(buflen);
	if(!buf) {
		*errstr=NULL;
		goto fclose_return;
	}
	while(getline(&buf,&buflen,f)>=0) {
		int last=0,len;
		unsigned char b2[256],b3[256];
		unsigned char *p,*pn,*pi;
		int tp,sz;
		pdnsd_ca a;

		p=strchr(buf,'#');
		if(p) *p=0;
		p=buf;
		for(;;) {
			if(!*p) goto nextline;
			if(!isspace(*p)) break;
			++p;
		}
		pi=p;
		do {
			if(!*++p) goto nextline;
		} while(!isspace(*p));
		*p=0;
		do {
			if(!*++p) goto nextline;
		} while (isspace(*p));
		pn=p;
		for(;;) {
			++p;
			if(!*p) {last=1; break;}
			if(isspace(*p)) {*p=0; break;}
		}
		len=p-pn;
		if(len>255) continue;
		strcpy(b2,pn);
		if(b2[len-1]!='.') {
			b2[len]='.';
			if(++len>255) continue;
			b2[len]=0;
		}
		if (!str2rhn(b2,b3))
			continue;
		if (inet_aton(pi,&a.ipv4)) {
			tp=T_A;
			sz=sizeof(struct in_addr);
		} else {
#if defined(DNS_NEW_RRS) && defined(ENABLE_IPV6) /* We don't read them otherwise, as the C library may not be able to to that.*/
			if (inet_pton(AF_INET6,pi,&a.ipv6)>0) {
				tp=T_AAAA;
				sz=sizeof(struct in6_addr);
			} else
				continue;
#else
			continue;
#endif
		}
		{
			int res=add_host(b2, rns, b3, &a, sz, ttl, flags, tp,1);
			if(res==0) {
				*errstr= NULL;
				goto cleanup_return;
			}
			else if(res<0)
				continue;
		}
		if(aliases) {
			while(!last) {
				do {
					if(!*++p) goto nextline;
				} while (isspace(*p));
				pn=p;
				for(;;) {
					++p;
					if(!*p) {last=1; break;}
					if(isspace(*p)) {*p=0; break;}
				}
				len=p-pn;
				if(len>255) break;
				strcpy(b2,pn);
				if(b2[len-1]!='.') {
					b2[len]='.';
					if(++len>255) break;
					b2[len]=0;
				}
				if (!str2rhn(b2,b3))
					break;
				if (add_host(b2, rns, b3, &a, sz, ttl, flags, tp,0) == 0) {
					*errstr= NULL;
					goto cleanup_return;
				}
			}
		}
	nextline:;
	}
	if (feof(f))
		rv=1;
	else if(asprintf(errstr, "Failed to source %s: %s", fn, strerror(errno))<0) *errstr=NULL;
 cleanup_return:
	free(buf);
 fclose_return:
	fclose(f);
	return rv;
}


#if DEBUG>0
/*
 * Const decoders for debugging display
 */
char *c_names[C_NUM] = {"IN","CS","CH","HS"};
char *qt_names[QT_NUM]={"IXFR","AXFR","MAILA","MAILB","*"};

char *get_cname(int id)
{
	if (id>=C_MIN && id<=C_MAX)
		return c_names[id-C_MIN];
	if (id==QC_ALL)
		return "*";
	return "[unknown]";
}

char *get_tname(int id)
{
	if (id>=T_MIN && id<=T_MAX)
		return rr_info[id-T_MIN].name;
        else if (id>=QT_MIN && id<=QT_MAX)
		return qt_names[id-QT_MIN];
	return "[unknown]";
}

char *e_names[RC_REFUSED+1]={"no error","query format error","server failed","unknown domain","not supported","query refused"};

char *get_ename(int id)
{
	if (id<0 || id>RC_REFUSED)
		return "[unknown]";
	return e_names[id];
}


#endif
