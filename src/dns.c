/* dns.c - Declarations for dns handling and generic dns functions
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

#include "config.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "helpers.h"
#include "dns.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: dns.c,v 1.21 2001/04/30 17:02:00 tmm Exp $";
#endif

/* Decompress a name record, taking the whole message as msg, returning its results in tgt (max. 255 chars),
 * taking sz as the remaining msg size (it is returned decremented by the name length, ready for further use) and
 * a source pointer (it is returned pointing to the location after the name). msgsize is the size of the whole message,
 * len is the total name lentgh.
 * msg and msgsz are needed for decompression (see rfc1035). The returned data is decompressed, but still in the
 * rr name form (length byte - string of that length, terminated by a 0 lenght byte).
 *
 * Returned is a dns return code, with one exception: RC_TRUNC, as defined in dns.h, indicates that the message is
 * truncated at the name (which needs a special return code, as it might or might not be fatal).
 */
int decompress_name(unsigned char *msg, unsigned char *tgt, unsigned char **src, long *sz, long msgsz, int *len)
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
			if (!isdchar(*lptr))
				return RC_FORMAT;
			tgt[tpos]=*lptr;
			lptr++;
			tpos++;
			if (!jumped) {
				(*sz)--;
			}
		}
	}
	*src+=osz-*sz;
	*len=tpos;
	return RC_OK;
}

/* Compare the names back-to-forth and return the longest match. The comparison is done at 
 * name granularity. The return value is the length of the match in name elements.
 * The unmatched part of ms is returned in rest (may be empty). o is set to the offset in the
 * domain name md (in length byte-string notation) of the match.
 * rest must point to a buffer of at least 256 bytes.
 */
int domain_match(int *o, unsigned char *ms, unsigned char *md, unsigned char *rest)
{
	unsigned char sbuf[257],dbuf[257];
	int offs, slen, dlen, cnt, nc;

	sbuf[0]='.';          /* Prefix the names with '.' : This is done for the special case that */
	dbuf[0]='.';          /* the domains match exactly, or one is a complete subdomain of another */
	rhn2str(ms,sbuf+1); /* Change to dotted notation since processing starts from behind, */
	rhn2str(md,dbuf+1); /* and so it's much easier that way. */
	/* If this is the root domain, we have two dots. bad. so this special case test: */
	if (strcmp((char *)&sbuf[1],".")==0) {
		*o=0;
		rest[0]='\0';
		return 0;
	}
	if (strlen((char *)sbuf)<2 || strlen((char *)dbuf)<2)
		return 0;
	slen=strlen((char *)sbuf)-2;
	dlen=strlen((char *)dbuf)-2;
	nc=cnt=0;
	offs=-1;
	while (cnt<=slen && cnt<=dlen) {
		if (tolower(sbuf[slen-cnt])!=tolower(dbuf[dlen-cnt]))
			break;
		if (sbuf[slen-cnt]=='.') {
			/* one complete name part matched. Set the offset */
			nc++;
			offs=cnt;
		}
		cnt++;
	}
	*o=dlen-offs;
	memset(rest,'\0',256);
	if (slen-offs>0) 
		memcpy(rest,ms,slen-offs);
	return nc;
}

/* compress the domain name in in and put the result (of maximum length of strlen(in)) and
 * fill cb with compression information for further strings.*cb may be NULL initially. 
 * offs is the offset the generated string will be placed in the packet.
 * retval: 0 - error, otherwise length
 * When done, just free() cb (if it is NULL, free will behave correctly).
 */
int compress_name(unsigned char *in, unsigned char *out, int offs, darray *cb)
{
#if 0
	/* Delete this debug code when done */
	unsigned char buf1[256],buf2[256];
#endif
	int i;
	int add=1;
	int coffs=-1;
	int rv,rl,to;
	int longest=0;
	unsigned char rest[256];
	unsigned char brest[256];
	rl=0;
	/* part 1: compression */
	if (*cb) {
		for (i=0;i<da_nel(*cb);i++) {
			if ((rv=domain_match(&to, in, DA_INDEX(*cb,i,compel_t)->s,rest))>longest) {
				/*
				 * This has some not obvious implications that should be noted: If a 
				 * domain name as saved in the list has been compressed, we only can
				 * index the non-compressed part. We rely here that the first occurence
				 * can't be compressed. So we take the first occurence of a given length.
				 * This works perfectly, but watch it if you change something.
				 */
				rhncpy(brest,rest);
				longest=rv;
				coffs=DA_INDEX(*cb,i, compel_t)->index+to;
			} 
		}
		if (coffs>-1) {
			rl=rhncpy(out, brest)-1; /* omit the length byte, because it needs to be frobbed */
			out[rl]=192|((coffs&0x3f00)>>8);
			out[rl+1]=coffs&0xff;
			rl+=2;
#if 0
			rhn2str(in,buf1);
			rhn2str(brest,buf2);
			printf("Compressed %s to %s and reference to %i.\n",buf1,buf2,coffs);
#endif
			add=strlen((char *)brest)!=0;
		} else {
#if 0
			rhn2str(in,buf1);
			printf("%s not compressed.\n",buf1);
#endif
			rl=rhncpy(out,in);
		}
	} else {
#if 0
		rhn2str(in,buf1);
		printf("%s not compressed.\n",buf1);
#endif
		rl=rhncpy(out,in);
	}

	/* part 2: addition to the cache structure */
	if (add) {
		if (!*cb) {
			if (!(*cb=DA_CREATE(compel_t)))
			    return 0;
		}
		if (!(*cb=da_grow(*cb, 1)))
			return 0;
		DA_LAST(*cb, compel_t)->index=offs;
		rhncpy(DA_LAST(*cb, compel_t)->s,in);
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
 * Add records for a host as read from a hosts-style file
 */
static int add_host(unsigned char *pn, unsigned char *rns, unsigned char *b3, pdnsd_ca *a, int a_sz, time_t ttl, int flags, int tp, int reverse)
{
	dns_cent_t ce;
	unsigned char b2[256],rhn[256];
#if defined(DNS_NEW_RRS) && defined(ENABLE_IPV6)
	unsigned char b4[5];
	int i;
#endif

	if (!init_cent(&ce, pn, flags, time(NULL), 0, 0))
		return 0;
#ifdef ENABLE_IPV4
	if (tp==T_A) {
		if (!add_cent_rr(&ce,ttl,0,CF_LOCAL,a_sz,&a->ipv4,tp,0)) {
 			free_cent(ce,0);
			return 0;
		}
	}
#endif
#if defined(DNS_NEW_RRS) && defined(ENABLE_IPV6)
	if (tp==T_AAAA) {
		if (!add_cent_rr(&ce,ttl,0,CF_LOCAL,a_sz,&a->ipv6,tp,0)) {
 			free_cent(ce,0);
			return 0;
		}
	}
#endif
	if (!add_cent_rr(&ce,ttl,0,CF_LOCAL,rhnlen(rns),rns,T_NS,0)) {
		free_cent(ce,0);
		return 0;
	}
	add_cache(ce);
	free_cent(ce,0);
	if (reverse) {
#ifdef ENABLE_IPV4
		if (tp==T_A) 
# if TARGET==TARGET_BSD
			snprintf((char *)b2,256,"%li.%li.%li.%li.in-addr.arpa.",ntohl(a->ipv4.s_addr)&0xffl,(ntohl(a->ipv4.s_addr)>>8)&0xffl,
				 (ntohl(a->ipv4.s_addr)>>16)&0xffl, (ntohl(a->ipv4.s_addr)>>24)&0xffl);
# else
			snprintf((char *)b2,256,"%i.%i.%i.%i.in-addr.arpa.",ntohl(a->ipv4.s_addr)&0xff,(ntohl(a->ipv4.s_addr)>>8)&0xff,
				 (ntohl(a->ipv4.s_addr)>>16)&0xff, (ntohl(a->ipv4.s_addr)>>24)&0xff);
# endif
#endif
#if defined(DNS_NEW_RRS) && defined(ENABLE_IPV6)
		if (tp==T_AAAA) {
			b2[0]='\0';
			for (i=15;i>=0;i--) {
				sprintf((char *)b4,"%x.%x.",((unsigned char *)&a->ipv6)[i]&&0xf,(((unsigned char *)&a->ipv6)[i]&&0xf0)>>4);
				strcat((char *)b2,(char *)b4);
			}
			strcat((char *)b2,"ip6.int.");
		}
#endif
		if (!str2rhn(b2,rhn))
			return 0;
		if (!init_cent(&ce, b2, flags, time(NULL), 0, 0))
			return 0;
		if (!add_cent_rr(&ce,ttl,0,CF_LOCAL,rhnlen(b3),b3,T_PTR,0)) {
 			free_cent(ce,0);
			return 0;
		}
		if (!add_cent_rr(&ce,ttl,0,CF_LOCAL,rhnlen(rns),rns,T_NS,0)) {
 			free_cent(ce,0);
			return 0;
		}
		add_cache(ce);
		free_cent(ce,0);
	}
	return 1;
}

/*
 * Read a file in /etc/hosts-format and add generate rrs for it.
 */
int read_hosts(char *fn, unsigned char *rns, time_t ttl, int flags, int aliases, char *errbuf, int errsize)
{
	FILE *f;
	unsigned char buf[1025];
	unsigned char b2[257],b3[256];
	unsigned char *p,*pn,*pi;
	struct in_addr ina4;
	int tp;
	int sz;
	pdnsd_ca a;

	buf[1023]='\0';
	if (!(f=fopen(fn,"r"))) {
		snprintf(errbuf, errsize, "Failed to source %s: %s\n", fn, strerror(errno));
		return 0;
	}
	while (!feof(f)) {
		if (fgets((char *)buf,1023,f)==NULL) {
			if (feof(f))
				break;
			snprintf(errbuf, errsize, "Failed to source %s: %s\n", fn, strerror(errno));
			fclose(f);
			return 0;
		}
		buf[1023]='\0';
/*		printf("read: %s\n", buf);*/
		p=buf;
		while (*p) {
			if (*p=='#') {
				*p='\0';
				break;
			}
			p++;
		}
		pi=buf;
		while (*pi==' ' || *pi=='\t') pi++;
		if (!*pi)
			continue;
		pn=pi;
		while (*pn=='.' || *pn==':' || isxdigit(*pn)) pn++;  /* this includes IPv6 (':') */
		if (!*pn)
			continue;
		*pn='\0';
		pn++;
		while (*pn==' ' || *pn=='\t') pn++;
		if (!*pn)
			continue;
		p=pn;
		while (isdchar(*p) || *p=='.') p++;
		*p='\0';
		memset(b2,'\0',257);
		strncpy((char *)b2,(char *)pn,255);
		if (b2[strlen((char *)b2)-1]!='.' && strlen((char *)b2)<256) {
			b2[strlen((char *)b2)]='.';
		}
/*		printf("i: %s, n: %s--\n",pi,pn);*/
		if (!str2rhn(b2,b3))
			continue;
		if (inet_aton((char *)pi,&ina4)) {
			a.ipv4=ina4;
			tp=T_A;
			sz=sizeof(struct in_addr);
		} else {
#if defined(DNS_NEW_RRS) && defined(ENABLE_IPV6) /* We don't read them otherwise, as the C library may not be able to to that.*/
			if (inet_pton(AF_INET6,(char *)pi,&a.ipv6)) {
				tp=T_AAAA;
				sz=sizeof(struct in6_addr);
			} else
				continue;
#else
			continue;
#endif
		}
		if (!add_host(b2, rns, b3, &a, sz, ttl, flags, tp,1))
			continue;
		while (aliases) {
			pn=p+1;
			while (*pn==' ' || *pn=='\t') pn++;
			if (!*pn)
				break;
			p=pn;
			while (isdchar(*p) || *p=='.') p++;
			*p='\0';
			memset(b2,'\0',257);
			strncpy((char *)b2,(char *)pn,255);
			if (b2[strlen((char *)b2)-1]!='.' && strlen((char *)b2)<256) {
				b2[strlen((char *)b2)]='.';
			}
			if (!str2rhn(b2,b3))
				break;
			add_host(b2, rns, b3, &a, sz, ttl, flags, tp,0);
		}
	}
	fclose(f);
	return 1;
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
		return rr_info[id-T_MIN];
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
