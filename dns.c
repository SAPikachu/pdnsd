/* dns.c - Declarations for dns handling and generic dns functions
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
#include <ctype.h>
#include <stdlib.h>
#include "helpers.h"
#include "dns.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: dns.c,v 1.6 2000/06/26 11:41:57 thomas Exp $";
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
		if (tpos>=255)
			return RC_FORMAT;
		if (!jumped)
			(*sz)--;
		lb=*lptr;
		lptr++;

		do {
 			if (lb>63 && lb<192)     /* The two highest bits must be either 00 or 11 */
				return RC_FORMAT;
			if (lb>=192) {
				if (lptr-msg>=msgsz-1)
					return RC_FORMAT;
				if (!jumped) {
					if ((*sz)<1)
						return RC_TRUNC;
					(*sz)--;
					jumped=1;

				}
				offs=(((unsigned short)lb&0x3f)<<8)|(*lptr);
				if (offs>=msgsz-1) 
					return RC_FORMAT;
				lptr=msg+offs;
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
			if (jumped) {
				if (*sz<=0)
					return RC_TRUNC;
			}
			if (tpos>=255)
				return RC_FORMAT;
			tgt[tpos]=tolower(*lptr);
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
	rhn2str(ms,&sbuf[1]); /* Change to dotted notation since processing starts from behind, */
	rhn2str(md,&dbuf[1]); /* and so it's much easier that way. */
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
int compress_name(unsigned char *in, unsigned char *out, int offs, compbuf_t **cb)
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
		for (i=0;i<(*cb)->num;i++) {
			if ((rv=domain_match(&to, in, (&((*cb)->first_el))[i].s,rest))>longest) {
				/*
				 * This has some not obvious implications that should be noted: If a 
				 * domain name as saved in the list has been compressed, we only can
				 * index the non-compressed part. We rely here that the first occurence
				 * can't be compressed. So we take the first occurence of a given length.
				 * This works perfectly, but watch it if you change something.
				 */
				memcpy(brest,rest,256);
				longest=rv;
				coffs=(&((*cb)->first_el))[i].index+to;
			} 
		}
		if (coffs>-1) {
			strcpy((char *)out,(char *)brest);
			rl=strlen((char *)brest);
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
			strcpy((char *)out,(char *)in);
			rl=strlen((char *)out)+1;
		}
	} else {
#if 0
		rhn2str(in,buf1);
		printf("%s not compressed.\n",buf1);
#endif
		strcpy((char *)out,(char *)in);
		rl=strlen((char *)out)+1;
	}

	/* part 2: addition to the cache structure */
	if (add) {
		if (!*cb) {
			if (!(*cb=calloc(sizeof(compbuf_t),1)))
				return 0;
			(*cb)->num=1;
		} else {
			(*cb)->num++;
			if (!(*cb=(compbuf_t *)realloc(*cb,sizeof(int)+sizeof(compel_t)*(*cb)->num)))
				return 0;
		}
		(&((*cb)->first_el))[(*cb)->num-1].index=offs;
		strcpy((char *)(&((*cb)->first_el))[(*cb)->num-1].s,(char *)in);
	}
	return rl;
}

#if DEBUG>0
/*
 * Const decoders for debugging display
 */
char *c_names[C_NUM] = {"IN","CS","CH","HS"};
#ifdef DNS_NEW_RRS
char *t_names[T_NUM] = {"A","NS","MD","MF","CNAME","SOA","MB","MG","MR","NULL","WKS","PTR","HINFO","MINFO","MX","TXT","RP","AFSDB","X25",
                        "ISDN","RT","NSAP","NSAP-PTR","SIG","KEY","PX","GPOS","AAAA (IPv6 A)","LOC","NXT","EID","NIMLOC","SRV","ATMA",
                        "NAPTR","KX"};
#else
char *t_names[T_NUM] = {"A","NS","MD","MF","CNAME","SOA","MB","MG","MR","NULL","WKS","PTR","HINFO","MINFO","MX","TXT"};
#endif
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
		return t_names[id-T_MIN];
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
