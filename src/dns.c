/* dns.c - Declarations for dns handling and generic dns functions

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
 * rr name form (length byte - string of that length, terminated by a 0 length byte).
 *
 * Returned is a dns return code, with one exception: RC_TRUNC, as defined in dns.h, indicates that the message is
 * truncated at the name (which needs a special return code, as it might or might not be fatal).
 */
int decompress_name(unsigned char *msg, long msgsz, unsigned char **src, long *sz, unsigned char *tgt, int *len)
{
	unsigned char lb;
	unsigned offs;
	unsigned char *lptr;
	int hops=0;
	int tpos=0;
	long osz=*sz;

	lptr=*src;
	for(;;) {
		if (*sz<=0)
			return RC_TRUNC;
		if (lptr-msg>=msgsz)
			return RC_FORMAT;
		(*sz)--;
		lb=*lptr++;

		if(lb>0x3f) {
 			if (lb<0xc0)     /* The two highest bits must be either 00 or 11 */
				return RC_FORMAT;
			if (*sz<=0)
				return RC_TRUNC;
			if (lptr-msg>=msgsz)
				return RC_FORMAT;
			(*sz)--;
			offs=(((unsigned int)lb&0x3f)<<8)|(*lptr);
			if (offs>=msgsz) 
				return RC_FORMAT;
			lptr=msg+offs;
			goto jumped;
		}
 		tgt[tpos++]=lb;
		if (lb==0)
			break;

		if (tpos+lb>255) /* terminating null byte has to follow */
			return RC_FORMAT;
		do {
			if (*sz<=0)
				return RC_TRUNC;
			if (lptr-msg>=msgsz)
				return RC_FORMAT;
			/* if (!*lptr || *lptr=='.')
				return RC_FORMAT; */
			(*sz)--;
			tgt[tpos++]=*lptr++;
		} while(--lb);
	}
	goto return_OK;

 jumped:
	++hops;
	for(;;) {
		lb=*lptr++;

		while(lb>0x3f) {
 			if (lb<0xc0)     /* The two highest bits must be either 00 or 11 */
				return RC_FORMAT;
			if (lptr-msg>=msgsz)
				return RC_FORMAT;
			if (++hops>255)
				return RC_FORMAT;
			offs=(((unsigned int)lb&0x3f)<<8)|(*lptr);
			if (offs>=msgsz) 
				return RC_FORMAT;
			lptr=msg+offs;
			lb=*lptr++;
		}
 		tgt[tpos++]=lb;
		if (lb==0)
			break;

		if (lptr+lb-msg>=msgsz || tpos+lb>255) /* terminating null byte has to follow */
			return RC_FORMAT;
		do {
			/* if (!*lptr || *lptr=='.')
				return RC_FORMAT; */
			tgt[tpos++]=*lptr++;
		} while(--lb);
	}
 return_OK:
	*src+=osz-*sz;
	if(len) *len=tpos;
	return RC_OK;
}

#if 0
/* Compare two names (ordinary C-strings) back-to-forth and return the longest match.
   The comparison is done at name granularity.
   The return value is the length of the match in name elements.
   *os (*od) is set to the offset in the domain name ms (md) of the match.
 */
int domain_name_match(const unsigned char *ms, const unsigned char *md, int *os, int *od)
{
	int i,j,k=0,offs,offd;

	offs=i=strlen(ms); offd=j=strlen(md);
	if(i && ms[i-1]=='.') --offs;
	if(j && md[j-1]=='.') --offd;

	if(i==0 || (i==1 && *ms=='.') || j==0 || (j==1 && *md=='.'))
		/* Special case: root domain */
		;
	else {
		--i; if(ms[i]=='.') --i;
		--j; if(md[j]=='.') --j;
		while(tolower(ms[i]) == tolower(md[j])) {
			if(ms[i]=='.') {
				++k;
				offs=i+1; offd=j+1;
			}
			if(i==0 || j==0) {
				if((i==0 || ms[i-1]=='.') && (j==0 || md[j-1]=='.')) {
					++k;
					offs=i; offd=j;
				}
				break;
			}
			--i; --j;
		}	
	}
	if(os) *os=offs;
	if(od) *od=offd;
	return k;
}
#endif

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
		i += ((unsigned)lb)+1;
	}

	j=0;
	while((lb=md[j])) {
		PDNSD_ASSERT(nd<128, "domain_match: too many name segments");
		ld[nd++]=lb;
		j += ((unsigned)lb)+1;
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
int compress_name(unsigned char *in, unsigned char *out, int offs, dlist *cb)
{
	compel_t *ci;
	int add=1;
	int longest=0,lrem=0,coffs=0;
	int rl=0;
	unsigned ilen = rhnlen(in);

	PDNSD_ASSERT(ilen<=256, "compress_name: name too long");

	/* part 1: compression */
	for (ci=dlist_first(*cb); ci; ci=dlist_next(ci)) {
		int rv,rem,to;
		if ((rv=domain_match(in, ci->s, &rem,&to))>longest) {
			/*
			 * This has some not obvious implications that should be noted: If a 
			 * domain name as saved in the list has been compressed, we only can
			 * index the non-compressed part. We rely here that the first occurence
			 * can't be compressed. So we take the first occurence of a given length.
			 * This works perfectly, but watch it if you change something.
			 */
			longest=rv;
			lrem=rem;
			coffs= ci->index + to;
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
		if (!(*cb=dlist_grow(*cb,sizeof(compel_t)+ilen)))
			return 0;
		ci=dlist_last(*cb);
		ci->index=offs;
		memcpy(ci->s,in,ilen);
	}
	return rl;
}

/* Convert a numeric IP address into a domain name representation
   (C string) suitable for PTR records.
   buf is assumed to be at least 256 bytes in size.
*/
int a2ptrstr(pdnsd_ca *a, int tp, unsigned char *buf)
{
	if(tp==T_A) {
		unsigned char *p=(unsigned char *)&a->ipv4.s_addr;
		int n=snprintf(buf,256,"%i.%i.%i.%i.in-addr.arpa.",p[3],p[2],p[1],p[0]);
		if(n<0 || n>=256)
			return 0;
	}
	else 
#if defined(DNS_NEW_RRS) && defined(ENABLE_IPV6)
	if(tp==T_AAAA) {
		unsigned char *p=(unsigned char *)&a->ipv6;
		int i,offs=0;
		for (i=15;i>=0;--i) {
			unsigned char bt=p[i];
			int n=snprintf(buf+offs, 256-offs,"%x.%x.",bt&0xf,(bt>>4)&0xf);
			if(n<0) return 0;
			offs+=n;
			if(offs>=256) return 0;
		}
		if(!strncp(buf+offs,"ip6.int.",256-offs))
			return 0;
	}
	else
#endif
		return 0;
	return 1;
}

/*
 * Add records for a host as read from a hosts-style file.
 * Returns 1 on success, 0 in an out of memory condition, and -1 when there was a problem with
 * the record data.
 */
static int add_host(unsigned char *pn, unsigned char *rns, pdnsd_ca *a, int tp, int a_sz, time_t ttl, unsigned flags, int reverse)
{
	dns_cent_t ce;

	if (!init_cent(&ce, pn, 0, 0, flags  DBG0))
		return 0;
	if (!add_cent_rr(&ce,tp,ttl,0,CF_LOCAL,a_sz,a  DBG0))
		goto free_cent_return0;
	if (!add_cent_rr(&ce,T_NS,ttl,0,CF_LOCAL,rhnlen(rns),rns  DBG0))
		goto free_cent_return0;
	add_cache(&ce);
	free_cent(&ce  DBG0);
	if (reverse) {
		unsigned char b2[256],rhn[256];
		if(!a2ptrstr(a,tp,b2))
			return -1;
		if (!str2rhn(b2,rhn))
			return -1;
		if (!init_cent(&ce, rhn, 0, 0, flags  DBG0))
			return 0;
		if (!add_cent_rr(&ce,T_PTR,ttl,0,CF_LOCAL,rhnlen(pn),pn  DBG0))
			goto free_cent_return0;
		if (!add_cent_rr(&ce,T_NS,ttl,0,CF_LOCAL,rhnlen(rns),rns  DBG0))
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
int read_hosts(const char *fn, unsigned char *rns, time_t ttl, unsigned flags, int aliases, char **errstr)
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
		int len;
		unsigned char *p,*pn,*pi;
		unsigned char rhn[256];
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
		do {
			++p;
		} while(*p && !isspace(*p));
		len=p-pn;
		if (parsestr2rhn(pn,len,rhn)!=NULL)
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
#endif
			continue;
		}
		{
			int res=add_host(rhn, rns, &a, tp,sz, ttl, flags, 1);
			if(res==0) {
				*errstr= NULL;
				goto cleanup_return;
			}
			else if(res<0)
				continue;
		}
		if(aliases) {
			for(;;) {
				for(;;) {
					if(!*p) goto nextline;
					if(!isspace(*p)) break;
					++p;
				}
				pn=p;
				do {
					++p;
				} while(*p && !isspace(*p));
				len=p-pn;
				if (parsestr2rhn(pn,len,rhn)!=NULL)
					break;
				if (add_host(rhn, rns, &a, tp,sz, ttl, flags, 0) == 0) {
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
char *qt_names[QT_NUM]={"IXFR","AXFR","MAILB","MAILA","*"};

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
