/* dns_answer.c - Receive and process incoming dns queries.
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

/*
 * STANDARD CONFORMITY
 * 
 * There are several standard conformity issues noted in the comments.
 * Some additional comments:
 *
 * I always set RA but I ignore RD largely (in everything but CNAME recursion), 
 * not because it is not supported, but because I _always_ do a recursive 
 * resolve in order to be able to cache the results.
 */

#include <config.h>
#include "ipvers.h"
#include <pthread.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <sys/param.h>
#include <netdb.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include "thread.h"
#include "list.h"
#include "dns.h"
#include "dns_answer.h"
#include "dns_query.h"
#include "helpers.h"
#include "cache.h"
#include "error.h"
#include "debug.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: dns_answer.c,v 1.58 2002/01/04 14:53:06 tmm Exp $";
#endif

/*
 * This is for error handling to prevent spewing the log files.
 * Maximums of different message types are set.
 * Races do not really matter here, so no locks.
 */
#define TCP_MAX_ERRS 5
#define UDP_MAX_ERRS 5
#define MEM_MAX_ERRS 5
#define MISC_MAX_ERRS 5
volatile int da_tcp_errs=0;
volatile int da_udp_errs=0;
volatile int da_mem_errs=0;
volatile int da_misc_errs=0;
pthread_t tcps;
pthread_t udps;
volatile int procs=0;   /* active query processes */
volatile int qprocs=0;  /* queued query processes */
volatile int thrid_cnt=0;
pthread_mutex_t proc_lock = PTHREAD_MUTEX_INITIALIZER;

#ifdef SOCKET_LOCKING
pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

volatile int tcp_up=1;
volatile int udp_up=1;

typedef struct {
	union {
#ifdef ENABLE_IPV4
		struct sockaddr_in  sin4;
#endif
#ifdef ENABLE_IPV6
		struct sockaddr_in6 sin6;
#endif
	}                  addr;

	union {
#if TARGET==TARGET_LINUX
# ifdef ENABLE_IPV4
		struct in_pktinfo   pi4;
# endif
#else
# ifdef ENABLE_IPV4
		struct in_addr      ai4;
# endif

#endif
#ifdef ENABLE_IPV6
		struct in6_pktinfo  pi6;
#endif
	}                  pi;

	int                sock;
	int                proto;
	long               len;
	unsigned char      buf[512];
} udp_buf_t;

typedef struct {
	unsigned char  query[256];
	unsigned short qtype;
	unsigned short qclass;
} dns_queryel_t;
typedef DYNAMIC_ARRAY(dns_queryel_t) *dns_queryel_array;

#define S_ANSWER     1
#define S_AUTHORITY  2
#define S_ADDITIONAL 3

typedef struct {
	unsigned short tp;
	unsigned char nm[256];
	unsigned char data[256];
} sva_t; 
typedef DYNAMIC_ARRAY(sva_t) *sva_array;

/*
 * Mark an additional record as added to avoid double records. Supply either name or rhn (set the other to 0)
 */
int sva_add(sva_array *sva, unsigned char *name, unsigned char *rhn, int tp, rr_bucket_t *b)
{
	sva_t *st;

	PDNSD_ASSERT(b->rdlen<=256,"Unexpected type to sva_add");
	if (sva) {
		if (*sva==NULL) {
			if ((*sva=DA_CREATE(sva_t))==NULL) {
				return 0;
			}
		}
		if ((*sva=DA_GROW1(*sva,sva_t))==NULL) {
			return 0;
		}
		st=&DA_LAST(*sva);
		st->tp=tp;
		if (!name)
			rhn2str(rhn,st->nm);
		else {
			strncpy((char *)st->nm,(char *)name,sizeof(st->nm));
			st->nm[sizeof(st->nm)-1]='\0';
		}
		memcpy(st->data,b+1,b->rdlen);
	}
	return 1;
}

/*
 * Add an rr from a rr_bucket_t (as in cache) into a dns message in ans. Ans is grown
 * to fit, sz is the old size of the packet (it is modified so at the end of the procedure
 * it is the new size), type is the rr type and ltime is the time in seconds the record is
 * old.
 * cb is the buffer used for message compression. *cb should be NULL if you call add_to_response
 * the first time. It gets filled with a pointer to compression information that can be
 * reused in subsequent calls to add_to_response.
 * sect is the section (S_ANSWER, S_AUTHORITY or S_ADDITIONAL) in which the record 
 * belongs logically. Note that you still have to add the rrs in the right order (answer rrs first,
 * then authority and last additional).
 */
static int add_rr(dns_hdr_t **ans, long *sz, rr_bucket_t *rr, unsigned short type, char section, compel_array *cb, char udp, time_t queryts,
    unsigned char *rrn, time_t ts, time_t ttl, unsigned short flags)
{
	time_t tleft;
	unsigned char nbuf[256];
	int nlen,ilen,blen,osz;
	rr_hdr_t rrh;
	unsigned char *rrht;
	dns_hdr_t *nans;
#ifdef DNS_NEW_RRS
	int j,k,wlen;
#endif

	osz=*sz;
	if (!(nlen=compress_name(rrn,nbuf,*sz,cb))) {
		pdnsd_free(*ans);
		return 0;
	}

	/* This buffer is over-allocated usually due to compression. Never mind, just a few bytes,
	 * and the buffer is freed soon*/
	nans=(dns_hdr_t *)pdnsd_realloc(*ans,*sz+sizeof(rr_hdr_t)+nlen+rr->rdlen+2);
	if (!nans) {
		pdnsd_free(*ans);
		return 0;
	}
	*ans=nans;
	memcpy((unsigned char *)(*ans)+*sz,nbuf,nlen); 
	*sz+=nlen;
	rrht=((unsigned char *)(*ans))+(*sz);
	rrh.type=htons(type);
	rrh.class=htons(C_IN);
	if (flags&CF_LOCAL)
		rrh.ttl=htonl(ttl);
	else {
		tleft=queryts-ts;
		rrh.ttl=htonl(tleft>ttl?0:ttl-tleft);
	}
	rrh.rdlength=0;
	*sz+=sizeof(rr_hdr_t);
	
	switch (type) {
	case T_CNAME:
	case T_MB:
	case T_MD:
	case T_MF:
	case T_MG:
	case T_MR:
	case T_NS:
	case T_PTR:
		if (!(rrh.rdlength=compress_name(((unsigned char *)(rr+1)), ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			pdnsd_free(*ans);
			return 0;
		}
		*sz+=rrh.rdlength;
		break;
	case T_MINFO:
#ifdef DNS_NEW_RRS
	case T_RP:
#endif
		if (!(rrh.rdlength=compress_name(((unsigned char *)(rr+1)), ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			pdnsd_free(*ans);
			return 0;
		}
		*sz+=rrh.rdlength;
		ilen=rhnlen((unsigned char *)(rr+1));
		PDNSD_ASSERT(rrh.rdlength <= ilen, "T_MINFO/T_RP: got longer");
		if (!(blen=compress_name(((unsigned char *)(rr+1))+ilen, ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			pdnsd_free(*ans);
			return 0;
		}
		rrh.rdlength+=blen;
		*sz+=blen;
		break;
	case T_MX:
#ifdef DNS_NEW_RRS
	case T_AFSDB:
	case T_RT:
	case T_KX:
#endif
		PDNSD_ASSERT(rr->rdlen > 2, "T_MX/T_AFSDB/...: rr botch");
		memcpy(((unsigned char *)(*ans))+(*sz),(unsigned char *)(rr+1),2);
		*sz+=2;
		if (!(blen=compress_name(((unsigned char *)(rr+1))+2, ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			pdnsd_free(*ans);
			return 0;
		}
		rrh.rdlength=2+blen;
		*sz+=blen;
		break;
	case T_SOA:
		if (!(rrh.rdlength=compress_name(((unsigned char *)(rr+1)), ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			pdnsd_free(*ans);
			return 0;
		}
		*sz+=rrh.rdlength;
		ilen=rhnlen((unsigned char *)(rr+1));
		PDNSD_ASSERT(rrh.rdlength <= ilen, "T_SOA: got longer");
		if (!(blen=compress_name(((unsigned char *)(rr+1))+ilen, ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			pdnsd_free(*ans);
			return 0;
		}
		rrh.rdlength+=blen;
		*sz+=blen;
		ilen+=rhnlen(((unsigned char *)(rr+1))+ilen);
		PDNSD_ASSERT(rrh.rdlength <= ilen, "T_SOA: got longer");
		memcpy(((unsigned char *)(*ans))+(*sz),((unsigned char *)(rr+1))+ilen,sizeof(soa_r_t));
		*sz+=sizeof(soa_r_t);
		rrh.rdlength+=sizeof(soa_r_t);
		break;
#ifdef DNS_NEW_RRS
	case T_PX:
		PDNSD_ASSERT(rr->rdlen > 2, "T_PX: rr botch");
		memcpy(((unsigned char *)(*ans))+(*sz),(unsigned char *)(rr+1),2);
		*sz+=2;
		ilen=2;
		if (!(blen=compress_name(((unsigned char *)(rr+1))+ilen, ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			pdnsd_free(*ans);
			return 0;
		}
		rrh.rdlength=2+blen;
		*sz+=blen;
		ilen+=rhnlen(((unsigned char *)(rr+1))+ilen);
		PDNSD_ASSERT(rrh.rdlength <= ilen, "T_PX: got longer");
		if (!(blen=compress_name(((unsigned char *)(rr+1))+ilen, ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			pdnsd_free(*ans);
			return 0;
		}
		rrh.rdlength+=blen;
		*sz+=blen;
		break;
	case T_SRV:
		PDNSD_ASSERT(rr->rdlen > 6, "T_SRV: rr botch");
		memcpy(((unsigned char *)(*ans))+(*sz),(unsigned char *)(rr+1),6);
		*sz+=6;
		if (!(blen=compress_name(((unsigned char *)(rr+1))+6, ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			pdnsd_free(*ans);
			return 0;
		}
		rrh.rdlength=6+blen;
		*sz+=blen;
		break;
	case T_NXT:
		if (!(blen=compress_name(((unsigned char *)(rr+1)), ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			pdnsd_free(*ans);
			return 0;
		}
		rrh.rdlength=blen;
		*sz+=blen;
		ilen=rhnlen((unsigned char *)(rr+1));
		PDNSD_ASSERT(rrh.rdlength <= ilen, "T_NXT: got longer");
		PDNSD_ASSERT(rr->rdlen >= ilen, "T_NXT: rr botch");
		wlen=rr->rdlen < ilen ? 0 : (rr->rdlen - ilen);
		memcpy(((unsigned char *)(*ans))+(*sz),((unsigned char *)(rr+1))+ilen,wlen);
		*sz+=wlen;
		rrh.rdlength+=wlen;
		break;
	case T_NAPTR:
		PDNSD_ASSERT(rr->rdlen > 5, "T_NAPTR: rr botch");
		memcpy(((unsigned char *)(*ans))+(*sz),(unsigned char *)(rr+1),4);
		*sz+=4;
		ilen=4;
		for (j=0;j<3;j++) {
			k=*(((unsigned char *)(rr+1))+ilen);
			PDNSD_ASSERT(k + 1 + ilen < rr->rdlen, "T_NAPTR: rr botch 2");
			memcpy(((unsigned char *)(*ans))+(*sz),((unsigned char *)(rr+1))+ilen,k+1);
			(*sz)+=k+1;
			ilen+=k+1;
		}
		if (!(blen=compress_name(((unsigned char *)(rr+1))+ilen, ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			pdnsd_free(*ans);
			return 0;
		}
		rrh.rdlength=ilen+blen;
		*sz+=blen;
		break;
#endif
	default:
		rrh.rdlength=rr->rdlen;
		memcpy(((unsigned char *)(*ans))+(*sz),((unsigned char *)(rr+1)),rr->rdlen);
		*sz+=rr->rdlen;
	}

	if (udp && (*sz)>512 && section==S_ADDITIONAL) /* only add the record if we do not increase the length over 512 */
		*sz=osz;                               /* in additionals for udp answer*/
	else {
		rrh.rdlength=htons(rrh.rdlength);
		memcpy(rrht,&rrh,sizeof(rrh));
		switch (section) {
		case S_ANSWER:
			(*ans)->ancount=htons(ntohs((*ans)->ancount)+1);
			break;
		case S_AUTHORITY:
			(*ans)->nscount=htons(ntohs((*ans)->nscount)+1);
			break;
		case S_ADDITIONAL:
			(*ans)->arcount=htons(ntohs((*ans)->arcount)+1);
			break;
		}
	}

	return 1;
}

typedef struct rre_s {
	int	       tp;
	unsigned char  tnm[256]; /* Name for the domain a record refers to */
	/* rr, nm, ts, ttl, flags only have meanings if tp==RRETP_AUTH */
	int    	       sz;
	unsigned char  nm[256];  /* Name of the domain the record is for (if needed) */
	time_t         ts;
	time_t         ttl;
	unsigned short flags;
} rr_ext_t;
typedef DYNAMIC_ARRAY(rr_ext_t) *rr_ext_array;

/* types for the tp field */
#define RRETP_AUTH	1	/* For name server: add to authority, add address to additional. */
#define RRETP_ADD	2	/* For other records: add the address of buf to additional */

static int add_ar(void *tnm, int tsz, rr_ext_array *ar, unsigned char *nm, time_t ts, time_t ttl, int flags, int tp)
{
	rr_ext_t *re;

	PDNSD_ASSERT(tsz <= 256, "add_ar: tsz botch");
	if ((*ar=DA_GROW1(*ar,rr_ext_t))==NULL) {
		return 0;
	}
	re=&DA_LAST(*ar);
	rhncpy(re->nm,nm);
	re->ts=ts;
	re->ttl=ttl;
	re->flags=flags;
	re->tp=tp;
	re->sz=tsz;
	memcpy(re->tnm,tnm,tsz);
	return 1;
}

#define AR_NUM 5
int ar_recs[AR_NUM]={T_NS, T_MD, T_MF, T_MB, T_MX}; 
int ar_offs[AR_NUM]={0,0,0,0,2}; /* offsets from record data start to server name */

/* This adds an rrset, optionally randomizing the first element it adds.
 * if that is done, all rrs after the randomized one appear in order, starting from
 * that one and wrapping over if needed. */
static int add_rrset(dns_cent_t *cached, int tp, dns_hdr_t **ans, long *sz, compel_array *cb, char udp, time_t queryts, unsigned char *rrn, sva_array *sva,
    rr_ext_array *ar)
{
	rr_bucket_t *b;
	rr_bucket_t *first;
	int cnt,i;

	if (cached->rr[tp-T_MIN] && cached->rr[tp-T_MIN]->rrs) {
		b=cached->rr[tp-T_MIN]->rrs;
		if (global.rnd_recs) {
			/* in order to have equal chances for each records to be the first, we have to count first. */
			first=b;
			cnt=0;
			while (b) {
				b=b->next;
				cnt++;
			}
			/* We do not use the pdnsd random functions (these might use /dev/urandom if the user is paranoid,
			 * and we do not need any good PRNG here). */
			cnt=random()%cnt;
			while (cnt) {
				cnt--;
				first=first->next;
			}
			b=first;
		}
		while (b) {
			if (!add_rr(ans, sz, b, tp,S_ANSWER,cb,udp,queryts,rrn,cached->rr[tp-T_MIN]->ts,
				    cached->rr[tp-T_MIN]->ttl,cached->rr[tp-T_MIN]->flags)) 
				return 0;
			if (tp==T_NS || tp==T_A || tp==T_AAAA) {
				/* mark it as added */
				if (!sva_add(sva,NULL,rrn,tp,b)) {
					pdnsd_free(*ans);
					return 0;
				}
			}
			/* Mark for additional address records. XXX: this should be a more effective algorithm; at least the list is small */
			for (i=0;i<AR_NUM;i++) {
				if (ar_recs[i]==tp) {
					if (!add_ar(((unsigned char *)(b+1))+ar_offs[i], b->rdlen-ar_offs[i],ar, (unsigned char *)"",
					    0,0,0,RRETP_ADD)) {
						pdnsd_free(*ans);
						return 0;
					}
					break;
				}
			}
			b=b->next;
			if (global.rnd_recs && !b) {
				/* wraparound */
				b=cached->rr[tp-T_MIN]->rrs;
			}
			if (global.rnd_recs && b==first)
				break;
		}
	}
	return 1;
}

/*
 * Add the fitting elements of the cached record to the message in ans, where ans
 * is grown to fit, sz is the size of the packet and is modified to be the new size.
 * The query is in qe. 
 * cb is the buffer used for message compression. *cb should be NULL if you call add_to_response
 * the first time. It gets filled with a pointer to compression information that can be
 * reused in subsequent calls to add_to_response.
 */
static int add_to_response(dns_queryel_t qe, dns_hdr_t **ans, long *sz, dns_cent_t *cached, compel_array *cb, char udp, unsigned char *rrn, time_t queryts,
    sva_array *sva, rr_ext_array *ar)
{
	int i;
	/* first of all, add cnames. Well, actually, there should be at max one in the record. */
	if (qe.qtype!=T_CNAME)
		if (!add_rrset(cached,T_CNAME, ans, sz, cb, udp, queryts, rrn, sva, ar))
			return 0;

	/* We need no switch for qclass, since we already have filtered packets we cannot understand */
	if (qe.qtype==QT_AXFR || qe.qtype==QT_IXFR) {
		/* I do not know what to do in this case. Since we do not maintain zones (and since we are
		   no master server, so it is not our task), I just return an error message. If anyone
		   knows how to do this better, please notify me. 
		   Anyway, this feature is rarely used in client communication, and there is no need for
		   other name servers to ask pdnsd. Btw: many bind servers reject an ?XFR query for security
		   reasons. */
		return 0; 
	} else if (qe.qtype==QT_MAILB) {
		if (!add_rrset(cached,T_MB, ans, sz, cb, udp, queryts, rrn, sva, ar))
			return 0;
		if (!add_rrset(cached,T_MG, ans, sz, cb, udp, queryts, rrn, sva, ar))
			return 0;
		if (!add_rrset(cached,T_MR, ans, sz, cb, udp, queryts, rrn, sva, ar))
			return 0;
	} else if (qe.qtype==QT_MAILA) {
		if (!add_rrset(cached,T_MD, ans, sz, cb, udp, queryts, rrn, sva, ar))
			return 0;
		if (!add_rrset(cached,T_MF, ans, sz, cb, udp, queryts, rrn, sva, ar))
			return 0;
	} else if (qe.qtype==QT_ALL) {
		for (i=T_MIN;i<=T_MAX;i++) {
			if (i==T_CNAME)
				continue; /* cnames are added above without name filtering */
			if (!add_rrset(cached,i, ans, sz, cb, udp, queryts, rrn, sva, ar))
				return 0;
		}
	} else {
		/* Unsupported elements have been filtered.*/
		if (!add_rrset(cached, qe.qtype , ans, sz, cb, udp, queryts, rrn, sva, ar))
			return 0;
	}
#if 0
	if (!ntohs((*ans)->ancount)) {
		/* Add a SOA if we have one and no other records are present in the answer.
		 * This is to aid caches so that they have a ttl. */
		if (!add_rrset(cached, T_SOA , ans, sz, cb, udp, queryts, rrn, sva, ar))
			return 0;
	}
#endif
	return 1;
}

/*
 * Add an additional
 */
static int add_additional_rr(unsigned char *rhn, unsigned char *buf, sva_array *sva, dns_hdr_t **ans, long *rlen, char udp, time_t queryts, compel_array *cb,
    int tp, rr_bucket_t *rr, time_t ts, time_t ttl, int flags, int sect)
{
	int rc;
	int j;
	sva_t *st;

	if (!rr)
		return 1;

	/* Check if already added; no double additionals */
	rc=1;
	/* We do NOT look at the data field for addresses, because I feel one address is enough. */
	for (j=0;j<DA_NEL(*sva);j++) {
		st=&DA_INDEX(*sva,j);
		if (st->tp==tp && stricomp((char *)st->nm,(char *)buf) && 
		    (memcmp(st->data,(unsigned char *)(rr+1), rr->rdlen)==0)) {
			rc=0;
			break;
		}
	}
	if (rc) {
		/* add_rr will do nothing when sz>512 bytes. */
		add_rr(ans, rlen, rr, tp, sect, cb, udp,queryts,rhn,
		       ts,ttl,flags); 
		/* mark it as added */
		if (!sva_add(sva,buf,NULL,tp,rr)) {
			pdnsd_free(*ans);
			return 0;
		}
	}
	return 1;
}

/*
 * The code below actually handles A and AAAA additionals.
 */
static int add_additional_a(unsigned char *rhn, sva_array *sva, dns_hdr_t **ans, long *rlen, char udp, time_t queryts, compel_array *cb) 
{
	unsigned char buf[256]; /* this is buffer space for the ns record */
	dns_cent_t *ae;
	int retval = 1;

	rhn2str(rhn,buf);
	if ((ae=lookup_cache(buf))) {
		if (ae->rr[T_A-T_MIN])
		    if (!add_additional_rr(rhn, buf, sva, ans, rlen, udp, queryts, cb, T_A, ae->rr[T_A-T_MIN]->rrs,
					   ae->rr[T_A-T_MIN]->ts,ae->rr[T_A-T_MIN]->ttl,ae->rr[T_A-T_MIN]->flags,S_ADDITIONAL))
			    retval = 0;
#ifdef DNS_NEW_RRS
		if (ae->rr[T_AAAA-T_MIN])
			if (!add_additional_rr(rhn, buf, sva, ans, rlen, udp, queryts, cb, T_AAAA, ae->rr[T_AAAA-T_MIN]->rrs,
					       ae->rr[T_AAAA-T_MIN]->ts,ae->rr[T_AAAA-T_MIN]->ttl,ae->rr[T_AAAA-T_MIN]->flags,S_ADDITIONAL))
			    retval = 0;
#endif
		free_cent(*ae,1);
		pdnsd_free(ae);
	}
	return retval;
}

/*
 * Compose an answer message for the decoded query in q, hdr is the header of the dns requestm
 * rlen is set to be the answer lenght.
 */
static unsigned char *compose_answer(dns_queryel_array q, dns_hdr_t *hdr, long *rlen, char udp) 
{
	char aa=1;
	unsigned char buf[256],bufr[256],oname[256];
	sva_array sva=NULL;
	int i,rc,hops,cont,cnc=0;
	time_t queryts=time(NULL);
	rr_bucket_t *rr;
	rr_ext_array ar;
	rr_ext_t *rre;
	compel_array cb=NULL;
	dns_hdr_t *ans, *nans;
	dns_queryel_t *qe;
	dns_cent_t *cached;
	std_query_t temp_q;

	ar=NULL;
	ans=(dns_hdr_t *)pdnsd_calloc(sizeof(dns_hdr_t),1);
	if (!ans)
		return NULL;
	ans->id=hdr->id;
	ans->qr=QR_RESP;
	ans->opcode=OP_QUERY;
	ans->aa=0;
	ans->tc=0; /* If tc is needed, it is set when the response is sent in udp_answer_thread. */
	ans->rd=hdr->rd;
	ans->ra=1;
	ans->z1=0;
	ans->au=0;
	ans->z2=0;
	ans->rcode=RC_OK;
	ans->qdcount=htons(DA_NEL(q));
	ans->ancount=0; /* this is first filled in and will be modified */
	ans->nscount=0;
	ans->arcount=0;

	*rlen=sizeof(dns_hdr_t);
	/* first, add the query to the response */
	for (i=0;i<DA_NEL(q);i++) {
		qe=&DA_INDEX(q,i);
		if (!(nans=(dns_hdr_t *)pdnsd_realloc(ans,*rlen+rhnlen(qe->query)+4))) {
			pdnsd_free(ans);
			return NULL;
		}
		ans=nans;
		*rlen+=rhncpy(((unsigned char *)ans)+*rlen,qe->query);
		temp_q.qtype=htons(qe->qtype);
		temp_q.qclass=htons(qe->qclass);
		memcpy(((unsigned char *)ans)+*rlen,&temp_q,sizeof(temp_q));
		*rlen+=4;
	}

	/* Barf if we get a query we cannot answer */
	for (i=0;i<DA_NEL(q);i++) {
		qe=&DA_INDEX(q,i);
		if ((qe->qtype<T_MIN || qe->qtype>T_MAX) &&
		    (qe->qtype!=QT_MAILA && qe->qtype!=QT_MAILB && qe->qtype!=QT_ALL)) {
			ans->rcode=RC_NOTSUPP;
			return (unsigned char *)ans;
		}
		if (qe->qclass!=C_IN && qe->qclass!=QC_ALL) {
			ans->rcode=RC_NOTSUPP;
			return (unsigned char *)ans;
		}
	}
	
	if ((ar=DA_CREATE(rr_ext_t))==NULL) {
		pdnsd_free(ans);
		return NULL;
	}
	/* second, the answer section */
	for (i=0;i<DA_NEL(q);i++) {
		qe=&DA_INDEX(q,i);
		rhncpy(bufr,qe->query);
		rhn2str(qe->query,buf);
		/* look if we have a cached copy. otherwise, perform a nameserver query. Same with timeout */
		hops=MAX_HOPS;
		do {
			cont=0;
			if ((rc=p_dns_cached_resolve(NULL,buf, bufr, &cached, MAX_HOPS,qe->qtype,queryts))!=RC_OK) {
				ans->rcode=rc;
				goto error_ar;
			}
			aa=0;
			strncpy((char *)oname,(char *)buf,sizeof(oname));
			oname[sizeof(oname)-1]='\0';
			if (!add_to_response(*qe,&ans,rlen,cached,&cb,udp,bufr,queryts,&sva,&ar))
				goto error_cached;
			cnc=follow_cname_chain(cached,buf,bufr);
			hops--;
			/* If there is only a cname and rd is set, add the cname to the response (add_to_response
			 * has already done this) and repeat the inquiry with the c name */
			if ((qe->qtype>=QT_MIN || !cached->rr[qe->qtype-T_MIN] || !cached->rr[qe->qtype-T_MIN]->rrs) && 
			     cnc>0 && hdr->rd!=0) {
				/* We did follow_cname_chain, so bufr and buf must contain the last cname in the chain.*/
				cont=1;
			}
			/* maintain a list for authority records: We will add every name server we got an authoritative
			 * answer from (and only those) to this list. This list will be appended to the record. This
			 * is at max one ns record per result. For extensibility, however, we support an arbitrary number
			 * of rrs (including 0) 
			 * We only do this for the last record in a cname chain, to prevent answer bloat. */
			if (!cont) {
				if (cached->rr[T_NS-T_MIN]) {
					rr=cached->rr[T_NS-T_MIN]->rrs;
					while (rr) {
						if (!add_ar(rr+1,rr->rdlen, &ar, bufr, cached->rr[T_NS-T_MIN]->ts, cached->rr[T_NS-T_MIN]->ttl,
						    cached->rr[T_NS-T_MIN]->flags,RRETP_AUTH)) {
							pdnsd_free(ans);
							goto error_cached;
						}
						rr=rr->next;
					}
				}
			}

			free_cent(*cached,1);
			pdnsd_free(cached);
		} while (cont && hops>=0);
	}

        /* Add the authority section */
	for (i=0;i<DA_NEL(ar);i++) {
		rre=&DA_INDEX(ar,i);
		if (rre->tp == RRETP_AUTH) {
			if ((rr=create_rr(rre->sz,rre->tnm,1))==NULL) {
				pdnsd_free(ans);
				goto error_ans;
			}
			rhn2str(rre->nm,buf);
			if (!add_additional_rr(rre->nm, buf, &sva, &ans, rlen, udp, queryts, &cb, T_NS, 
			    rr, rre->ts, rre->ttl, rre->flags,S_AUTHORITY)) {
				free_rr(*rr,1);
				pdnsd_free(rr);
				goto error_ans;
			}
			free_rr(*rr,1);
			pdnsd_free(rr);
		}
	}

	/* now add the name server addresses */
	for (i=0;i<DA_NEL(ar);i++) {
		rre=&DA_INDEX(ar,i);
		if (!add_additional_a(rre->tnm, &sva, &ans, rlen, udp, queryts, &cb))
			goto error_ans;
	}
	da_free(ar);
	
	if (cb)
		da_free(cb);
	if (sva)
		da_free(sva);
	if (aa)
		ans->aa=1;
	return (unsigned char *)ans;

	/* You may not like goto's, but here we avoid lots of code duplication. */
error_cached:
	free_cent(*cached,1);
	pdnsd_free(cached);
error_ans:
	ans=NULL; /* already freed if we get here */
error_ar:
	da_free(ar);
	if (cb)
		da_free(cb);
	if (sva)
		da_free(sva);
	return (unsigned char *)ans;
}	

/*
 * Decode the query (the query messgage is in data and rlen bytes long) into q
 * XXX: data needs to be aligned
 */
static int decode_query(unsigned char *data, long rlen, dns_queryel_array *q)
{
	int i,res,l,uscore;
	dns_hdr_t *hdr=(dns_hdr_t *)data; /* aligned, so no prob. */
	unsigned char *ptr=(unsigned char *)(hdr+1);
	long sz=rlen-sizeof(dns_hdr_t);
	dns_queryel_t *qe;
	
	if (ntohs(hdr->qdcount)==0) 
		return RC_FORMAT;
	
	if (!(*q=DA_CREATE(dns_queryel_t)))
		return RC_SERVFAIL;
	
	for (i=0;i<ntohs(hdr->qdcount);i++) {
		if (!(*q=DA_GROW1(*q,dns_queryel_t)))
			return RC_SERVFAIL;
		qe=&DA_LAST(*q);
		res=decompress_name(data,qe->query,&ptr,&sz,rlen,&l,&uscore);
		if (res==RC_TRUNC) {
			if (hdr->tc) {
				if (i==0) {
					da_free(*q);
					return RC_FORMAT; /*not even one complete query*/
				} else
					*q=DA_RESIZE(*q,dns_queryel_t,i);
				break;
			} else {
				da_free(*q);
				return RC_FORMAT;
			}
		} else if (res!=RC_OK) {
			da_free(*q);
			return res;
		}
		if (sz<4) {
			/* truncated in qname or qclass*/
			if (i==0) {
				da_free(*q);
				return RC_FORMAT; /*not even one complete query*/
			} else
				*q=DA_RESIZE(*q,dns_queryel_t,i);
			break;
		}
		/* Use memcpy to avoid unaligned access */
		memcpy(&qe->qtype,ptr,sizeof(qe->qtype));
		ptr+=2;
		memcpy(&qe->qclass,ptr,sizeof(qe->qclass));
		sz-=4;
		ptr+=2;
		qe->qtype=ntohs(qe->qtype);
		qe->qclass=ntohs(qe->qclass);
		/* Underscore only allowed for SRV records. */
		if (uscore && qe->qtype!=T_SRV) {
			da_free(*q);
			return RC_FORMAT;
		}
	}
	return RC_OK;
}

/* Make a dns error reply message
 * Id is the query id and still in network order.
 * op is the opcode to fill in, rescode - name says it all.
 */
static dns_hdr_t mk_error_reply(unsigned short id, unsigned short opcode,unsigned short rescode)
{
	dns_hdr_t rep;
	rep.id=id;
	rep.qr=QR_RESP;
	rep.opcode=opcode;
	rep.aa=0;
	rep.tc=0;
	rep.rd=0;
	rep.ra=1;
	rep.z1=0;
	rep.au=0;
	rep.z2=0;
	rep.rcode=rescode;
	rep.qdcount=0;
	rep.ancount=0;
	rep.nscount=0;
	rep.arcount=0;
	return rep;
}

/*
 * Analyze and answer the query in data. The answer is returned. rlen is at call the query length and at
 * return the length of the answer. You have to free the answer after sending it.
 */
static unsigned char *process_query(unsigned char *data, long *rlen, char udp)
{
#if DEBUG>0
	unsigned char buf[256];
#endif

	int res;
	dns_hdr_t *hdr;
	dns_queryel_array q;
	dns_hdr_t *resp=(dns_hdr_t *)pdnsd_calloc(sizeof(dns_hdr_t),1);
	dns_hdr_t *ans;
	

	DEBUG_MSG("Received query.\n");
	if (!resp) {
		if (da_mem_errs<MEM_MAX_ERRS) {
			da_mem_errs++;
			log_error("Out of memory in query processing.");
		}
		return NULL;
	}
	/*
	 * We will ignore all records that come with a query, except for the actual query records.
	 * We will send back the query in the response. We will reject all non-queries, and
	 * some not supported thingies. 
	 * If anyone notices behaviour that is not in standard conformance, please notify me!
	 */
	hdr=(dns_hdr_t *)data;
	if (*rlen<2) { 
		pdnsd_free(resp);
		DEBUG_MSG("Message too short.\n");
		return NULL; /* message too short: no id provided. */
	}
	if (*rlen<sizeof(dns_hdr_t)) {
		*rlen=sizeof(dns_hdr_t);
		*resp=mk_error_reply(hdr->id,*rlen>=3?hdr->opcode:OP_QUERY,RC_FORMAT);
		DEBUG_MSG("Message too short.\n");
		return (unsigned char *)resp;
	}
	if (hdr->qr==QR_RESP) {
		pdnsd_free(resp);
		DEBUG_MSG("Response, not query.\n");
		return NULL; /* RFC says: discard */
	}
	if (hdr->opcode!=OP_QUERY) {
		*rlen=sizeof(dns_hdr_t);
		*resp=mk_error_reply(hdr->id,hdr->opcode,RC_NOTSUPP);
		DEBUG_MSG("No query.\n");
		return (unsigned char *)resp;
	}
	if (hdr->z1!=0 || hdr->z2!=0) {
		*rlen=sizeof(dns_hdr_t);
		*resp=mk_error_reply(hdr->id,hdr->opcode,RC_FORMAT);
		DEBUG_MSG("Malformed query.\n");
		return (unsigned char *)resp;
	}
	if (hdr->rcode!=RC_OK) {
		pdnsd_free(resp);
		DEBUG_MSG("Bad rcode.\n");
		return NULL; /* discard (may cause error storms) */
	}

	res=decode_query(data,*rlen,&q);
	if (res) {
		*rlen=sizeof(dns_hdr_t);
		*resp=mk_error_reply(hdr->id,hdr->opcode,res);
		return (unsigned char *)resp;
	}

#if DEBUG>0
	if (debug_p) {
		dns_queryel_t *qe;

		DEBUG_MSG("Questions are:\n");
		for (res=0;res<DA_NEL(q);res++) {
			qe=&DA_INDEX(q,res);
			rhn2str(qe->query,buf);
			DEBUG_MSG("\tqc=%s (%i), qt=%s (%i), query=\"%s\"\n",get_cname(qe->qclass),qe->qclass,get_tname(qe->qtype),qe->qtype,buf);
		}
	}
#endif

	if (!(ans=(dns_hdr_t *)compose_answer(q, hdr, rlen, udp))) {
		/* An out of memory condition or similar could cause NULL output. Send failure notification */
		da_free(q);
		*rlen=sizeof(dns_hdr_t);
		*resp=mk_error_reply(hdr->id,hdr->opcode,RC_SERVFAIL);
		return (unsigned char *)resp;
	}
	pdnsd_free(resp);
	da_free(q);
	return (unsigned char *)ans;
}

/*
 * Called by *_answer_thread exit handler to clean up process count.
 */
void decrease_procs(void *dummy)
{
	(void)dummy;
	pthread_mutex_lock(&proc_lock);
	procs--;
	qprocs--;
	pthread_mutex_unlock(&proc_lock);
}


/*
 * A thread opened to answer a query transmitted via udp. Data is a pointer to the structure udp_buf_t that
 * contains the received data and various other parameters.
 * After the query is answered, the thread terminates
 * XXX: data must point to a correctly aligned buffer
 */
void *udp_answer_thread(void *data)
{
	struct msghdr msg;
	struct iovec v;
	struct cmsghdr *cmsg;
	char ctrl[512];
	long rlen=((udp_buf_t *)data)->len;
	/* XXX: process_query is assigned to this, this mallocs, so this points to aligned memory */
	unsigned char *resp;
	socklen_t sl;
	int tmp,i,thrid;
#ifdef ENABLE_IPV6
	char buf[ADDRSTR_MAXLEN];
#endif
	pthread_cleanup_push(decrease_procs, NULL);
	THREAD_SIGINIT;

	if (!global.strict_suid ) {
		if (!run_as(global.run_as)) {
			log_error("Could not change user and group id to those of run_as user %s",global.run_as);
			pdnsd_exit();
		}
	}

	do {
		pthread_mutex_lock(&proc_lock);
		i=procs;
		if (i <= global.proc_limit) {
			procs++;
			thrid=thrid_cnt++;
		}
		pthread_mutex_unlock(&proc_lock);
		if (i>global.proc_limit)
			usleep_r(50000);
	} while (i>global.proc_limit); 
		
	if (pthread_setspecific(thrid_key, &thrid) != 0) {
		log_error("pthread_setspecific failed.");
		pdnsd_exit();
	}

	if (!(resp=process_query(((udp_buf_t *)data)->buf,&rlen,1))) {
		/*
		 * A return value of NULL is a fatal error that prohibits even the sending of an error message.
		 * logging is already done. Just exit the thread now.
		 */
		pdnsd_free(data);
		pthread_exit(NULL);
	}
	if (rlen>512) {
		rlen=512;
		((dns_hdr_t *)resp)->tc=1; /*set truncated bit*/
	}
	DEBUG_MSG("Outbound msg len %li, tc=%i, rc=\"%s\"\n",rlen,((dns_hdr_t *)resp)->tc,get_ename(((dns_hdr_t *)resp)->rcode));

	v.iov_base=(char *)resp;
	v.iov_len=rlen;
	msg.msg_iov=&v;
	msg.msg_iovlen=1;
#if defined(SRC_ADDR_DISC)
	msg.msg_control=ctrl;
	msg.msg_controllen=512;
#else
	msg.msg_control=NULL;
	msg.msg_controllen=0;
#endif

#ifdef ENABLE_IPV4
	if (run_ipv4) {

		msg.msg_name=&((udp_buf_t *)data)->addr.sin4;
		msg.msg_namelen=sizeof(struct sockaddr_in);
# if defined(SRC_ADDR_DISC) 
#  if TARGET==TARGET_LINUX
		((udp_buf_t *)data)->pi.pi4.ipi_spec_dst=((udp_buf_t *)data)->pi.pi4.ipi_addr;
		cmsg=CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len=CMSG_LEN(sizeof(struct in_pktinfo));
		cmsg->cmsg_level=SOL_IP;
		cmsg->cmsg_type=IP_PKTINFO;
		memcpy(CMSG_DATA(cmsg),&((udp_buf_t *)data)->pi.pi4,sizeof(struct in_pktinfo));
		msg.msg_controllen=CMSG_SPACE(sizeof(struct in_pktinfo));
#  else
		cmsg=CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len=CMSG_LEN(sizeof(struct in_addr));
		cmsg->cmsg_level=IPPROTO_IP;
		cmsg->cmsg_type=IP_RECVDSTADDR;
		memcpy(CMSG_DATA(cmsg),&((udp_buf_t *)data)->pi.ai4,sizeof(struct in_addr));
		msg.msg_controllen=CMSG_SPACE(sizeof(struct in_addr));
#  endif
# endif		
		DEBUG_MSG("Answering to: %s", inet_ntoa(((udp_buf_t *)data)->addr.sin4.sin_addr));
# if defined(SRC_ADDR_DISC)
#  if TARGET==TARGET_LINUX
		DEBUG_MSGC(", source address: %s\n", inet_ntoa(((udp_buf_t *)data)->pi.pi4.ipi_spec_dst));
#  else
		DEBUG_MSGC(", source address: %s\n", inet_ntoa(((udp_buf_t *)data)->pi.ai4));
#  endif
# else
		DEBUG_MSGC("\n");
# endif
	}
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6) {

		msg.msg_name=&((udp_buf_t *)data)->addr.sin6;
		msg.msg_namelen=sizeof(struct sockaddr_in6);
# if defined(SRC_ADDR_DISC)
		cmsg=CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len=CMSG_LEN(sizeof(struct in6_pktinfo));
		cmsg->cmsg_level=SOL_IPV6;
		cmsg->cmsg_type=IPV6_PKTINFO;
		memcpy(CMSG_DATA(cmsg),&((udp_buf_t *)data)->pi.pi6,sizeof(struct in6_pktinfo));
		msg.msg_controllen=CMSG_SPACE(sizeof(struct in6_pktinfo));
# endif

		DEBUG_MSG("Answering to: %s", inet_ntop(AF_INET6,&((udp_buf_t *)data)->addr.sin6.sin6_addr,buf,ADDRSTR_MAXLEN));
# if defined(SRC_ADDR_DISC)
		DEBUG_MSGC(", source address: %s\n", inet_ntop(AF_INET6,&((udp_buf_t *)data)->pi.pi6.ipi6_addr,buf,ADDRSTR_MAXLEN));
# else
		DEBUG_MSGC("\n");
# endif
	}
#endif
	
	/* Lock the socket, and clear the error flag before dropping the lock */
#ifdef SOCKET_LOCKING
	pthread_mutex_lock(&s_lock);
#endif
	if (sendmsg(((udp_buf_t *)data)->sock,&msg,0)<0) {
#ifdef SOCKET_LOCKING
		pthread_mutex_unlock(&s_lock);
#endif
		if (da_udp_errs<UDP_MAX_ERRS) {
			da_udp_errs++;
			log_error("Error in udp send: %s",strerror(errno));
		}
	} else {
		sl=sizeof(tmp);
		getsockopt(((udp_buf_t *)data)->sock, SOL_SOCKET, SO_ERROR, &tmp, &sl);
#ifdef SOCKET_LOCKING
		pthread_mutex_unlock(&s_lock);
#endif
	}
	
	pdnsd_free(resp);
	pdnsd_free(data);
	pthread_cleanup_pop(1);
	return NULL;
}

int init_udp_socket()
{
	int sock;
	int so=1;
#ifdef ENABLE_IPV4
	struct sockaddr_in sin4;
#endif
#ifdef ENABLE_IPV6
	struct sockaddr_in6 sin6;
#endif
	struct sockaddr *sin;
	int sinl;
	struct protoent *pe=getprotobyname("udp");

	if (!pe) {
		log_error("Could not get udp protocol: %s",strerror(errno));
		return -1;
	}
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		if ((sock=socket(PF_INET,SOCK_DGRAM,pe->p_proto))==-1) {
			log_error("Could not open udp socket: %s",strerror(errno));
			return -1;
		}
		memset(&sin4,0,sizeof(sin4));
		sin4.sin_family=AF_INET;
		sin4.sin_port=htons(global.port);
		sin4.sin_addr=global.a.ipv4;
		SET_SOCKA_LEN4(sin4);
		sin=(struct sockaddr *)&sin4;
		sinl=sizeof(sin4);
	}
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6) {
		if ((sock=socket(PF_INET6,SOCK_DGRAM,pe->p_proto))==-1) {
			log_error("Could not open udp socket: %s",strerror(errno));
			return -1;
		}
		memset(&sin6,0,sizeof(sin6));
		sin6.sin6_family=AF_INET6;
		sin6.sin6_port=htons(global.port);
		sin6.sin6_flowinfo=IPV6_FLOWINFO;
		sin6.sin6_addr=global.a.ipv6;
		SET_SOCKA_LEN6(sin6);
		sin=(struct sockaddr *)&sin6;
		sinl=sizeof(sin6);
	}
#endif

#ifdef SRC_ADDR_DISC
# if (TARGET==TARGET_BSD)
	if (run_ipv4) {
#endif
		/* The following must be set on any case because it also applies for IPv4 packets sent to
		 * ipv6 addresses. */
# if  TARGET==TARGET_LINUX 
		if (setsockopt(sock,SOL_IP,IP_PKTINFO,&so,sizeof(so))!=0) {
# else
		if (setsockopt(sock,IPPROTO_IP,IP_RECVDSTADDR,&so,sizeof(so))!=0) {
# endif
			log_error("Could not set options on udp socket: %s",strerror(errno));
			close(sock);
			return -1;
		}
# if (TARGET==TARGET_BSD)
	}
#endif

# ifdef ENABLE_IPV6
	if (run_ipv6) {
		if (setsockopt(sock,SOL_IPV6,IPV6_PKTINFO,&so,sizeof(so))!=0) {
			log_error("Could not set options on udp socket: %s",strerror(errno));
			close(sock);
			return -1;
		}
	}
# endif
#endif
	if (bind(sock,sin,sinl)!=0) {
		log_error("Could not bind to udp socket: %s",strerror(errno));
		close(sock);
		return -1;
	}
	return sock;
}

/* 
 * Listen on the specified port for udp packets and answer them (each in a new thread to be nonblocking)
 * This was changed to support sending UDP packets with exactly the same source address as they were coming
 * to us, as required by rfc2181. Although this is a sensible requirement, it is slightly more difficult
 * and may introduce portability issues.
 */
void *udp_server_thread(void *dummy)
{
	int sock;
	long qlen;
#ifdef ENABLE_IPV4
	struct sockaddr_in sin4;
#endif
#ifdef ENABLE_IPV6
	struct sockaddr_in6 sin6;
#endif
	pthread_t pt;
	udp_buf_t *buf;
	struct msghdr msg;
	struct iovec v;
	struct cmsghdr *cmsg;
	char ctrl[512];
#if defined(ENABLE_IPV6) && (TARGET==TARGET_LINUX)
	struct in_pktinfo sip;
#endif
	(void)dummy; /* To inhibit "unused variable" warning */

	THREAD_SIGINIT;


	if (!global.strict_suid) {
		if (!run_as(global.run_as)) {
			log_error("Could not change user and group id to those of run_as user %s",global.run_as);
			pdnsd_exit();
		}
	}

	sock=udp_socket;
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		memset(&sin4,0,sizeof(sin4));
		sin4.sin_family=AF_INET;
		sin4.sin_port=htons(global.port);
		sin4.sin_addr=global.a.ipv4;
		SET_SOCKA_LEN4(sin4);
	}
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6) {
		memset(&sin6,0,sizeof(sin6));
		sin6.sin6_family=AF_INET6;
		sin6.sin6_port=htons(global.port);
		sin6.sin6_flowinfo=IPV6_FLOWINFO;
		sin6.sin6_addr=global.a.ipv6;
		SET_SOCKA_LEN6(sin6);
	}
#endif

	while (1) {
		if (!(buf=(udp_buf_t *)pdnsd_calloc(sizeof(udp_buf_t),1))) {
			if (da_mem_errs<MEM_MAX_ERRS) {
				da_mem_errs++;
				log_error("Out of memory in request handling.");
			}
			udp_up=0;
			if (!tcp_up)
				pdnsd_exit();
			return NULL;
		}
		
		buf->sock=sock;

		v.iov_base=(char *)buf->buf;
		v.iov_len=512;
		msg.msg_iov=&v;
		msg.msg_iovlen=1;
		msg.msg_control=ctrl;
		msg.msg_controllen=512;

#if defined(SRC_ADDR_DISC)
# ifdef ENABLE_IPV4
		if (run_ipv4) {
			msg.msg_name=&buf->addr.sin4;
			msg.msg_namelen=sizeof(struct sockaddr_in);
			if ((qlen=recvmsg(sock,&msg,0))>=0) {
				cmsg=CMSG_FIRSTHDR(&msg);
				while(cmsg) {
#  if TARGET==TARGET_LINUX
					if (cmsg->cmsg_level==SOL_IP && cmsg->cmsg_type==IP_PKTINFO) {
						memcpy(&buf->pi.pi4,CMSG_DATA(cmsg),sizeof(struct in_pktinfo));
						break;
					}
#  else
					if (cmsg->cmsg_level==IPPROTO_IP && cmsg->cmsg_type==IP_RECVDSTADDR) {
						memcpy(&buf->pi.ai4,CMSG_DATA(cmsg),sizeof(buf->pi.ai4));
						break;
					}
#  endif
					cmsg=CMSG_NXTHDR(&msg,cmsg);
				}
				if (!cmsg) {
					if (da_udp_errs<UDP_MAX_ERRS) {
						da_udp_errs++;
						log_error("Could not discover udp destination address");
					}
					pdnsd_free(buf);
					usleep_r(50000);
					continue;
				}
			} else if (errno!=EINTR) {
				if (da_udp_errs<UDP_MAX_ERRS) {
					da_udp_errs++;
					log_error("error in UDP recv: %s", strerror(errno));
				}
			}
		}
# endif
# ifdef ENABLE_IPV6
		if (run_ipv6) {
			msg.msg_name=&buf->addr.sin6;
			msg.msg_namelen=sizeof(struct sockaddr_in6);
			if ((qlen=recvmsg(sock,&msg,0))>=0) {
				cmsg=CMSG_FIRSTHDR(&msg);
				while(cmsg) {
					if (cmsg->cmsg_level==SOL_IPV6 && cmsg->cmsg_type==IPV6_PKTINFO) {
						memcpy(&buf->pi.pi6,CMSG_DATA(cmsg),sizeof(struct in6_pktinfo));
						break;
					}
					cmsg=CMSG_NXTHDR(&msg,cmsg);
				}
				if (!cmsg) {
				       /* We might have an IPv4 Packet incoming on our IPv6 port, so we also have to
				        * check for IPv4 sender addresses */
					cmsg=CMSG_FIRSTHDR(&msg);
					while(cmsg) {
#  if TARGET==TARGET_LINUX
						if (cmsg->cmsg_level==SOL_IP && cmsg->cmsg_type==IP_PKTINFO) {
							memcpy(&sip,CMSG_DATA(cmsg),sizeof(sip));
							IPV6_MAPIPV4(&sip.ipi_addr,&buf->pi.pi6.ipi6_addr);
							buf->pi.pi6.ipi6_ifindex=sip.ipi_ifindex;
							break;
						}
						/* FIXME: What about BSD? probably ok, but... */
#  endif
						cmsg=CMSG_NXTHDR(&msg,cmsg);
					}
					if (!cmsg) {
						if (da_udp_errs<UDP_MAX_ERRS) {
							da_udp_errs++;
							log_error("Could not discover udp destination address");
						}
						pdnsd_free(buf);
						usleep_r(50000);
						continue;
					}
				}
			} else if (errno!=EINTR) {
				if (da_udp_errs<UDP_MAX_ERRS) {
					da_udp_errs++;
					log_error("error in UDP recv: %s", strerror(errno));
				}
			}
		}
# endif
#else /* !SRC_ADDR_DISC */
# ifdef ENABLE_IPV4
		if (run_ipv4) {
			msg.msg_name=&buf->addr.sin4;
			msg.msg_namelen=sizeof(struct sockaddr_in);
			qlen=recvmsg(sock,&msg,0);
			if (qlen<0 && errno!=EINTR) {
				if (da_udp_errs<UDP_MAX_ERRS) {
					da_udp_errs++;
					log_error("error in UDP recv: %s", strerror(errno));
				}
			}		
		}
# endif
# ifdef ENABLE_IPV6
		if (run_ipv6) {
			msg.msg_name=&buf->addr.sin6;
			msg.msg_namelen=sizeof(struct sockaddr_in6);
			qlen=recvmsg(sock,&msg,0);
			if (qlen<0 && errno!=EINTR) {
				if (da_udp_errs<UDP_MAX_ERRS) {
					da_udp_errs++;
					log_error("error in UDP recv: %s", strerror(errno));
				}
			}
		}
# endif
#endif

		if (qlen<0) {
			pdnsd_free(buf);
			usleep_r(50000);
/*			if (errno==EINTR) {
			close(sock);
			return NULL;
			}*/
			continue;
		} else {
			pthread_mutex_lock(&proc_lock);
			if (qprocs<global.proc_limit+global.procq_limit) {
				pthread_attr_t attr;

				qprocs++;
				pthread_mutex_unlock(&proc_lock);
				buf->len=qlen;
				pthread_attr_init(&attr);
				pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
				pthread_create(&pt,&attr,udp_answer_thread,(void *)buf);
				pthread_attr_destroy(&attr);
			} else {
				pthread_mutex_unlock(&proc_lock);
				pdnsd_free(buf);
				usleep_r(50000);
			}
		}
	}
	close(sock);
	udp_socket=-1;
	return NULL;
}

#ifndef NO_TCP_SERVER
/*
 * Process a dns query via tcp. The argument is a pointer to the socket.
 */
void *tcp_answer_thread(void *csock)
{
	dns_hdr_t err;
	unsigned short rlen,olen;
	long nlen;
	/* XXX: This should be OK, the original must be (and is) aligned */
	int sock=*((int *)csock);
	unsigned char *buf;
	unsigned char *resp;
	int i, thrid;
#ifdef NO_POLL
	fd_set fds;
	struct timeval tv;
#else
	struct pollfd pfd;
#endif

	pthread_cleanup_push(decrease_procs, NULL);
	THREAD_SIGINIT;

	if (!global.strict_suid) {
		if (!run_as(global.run_as)) {
			log_error("Could not change user and group id to those of run_as user %s",global.run_as);
			pdnsd_exit();
		}
	}

	do {
		pthread_mutex_lock(&proc_lock);
		i=procs;
		if (i<=global.proc_limit) {
			procs++;
			thrid=thrid_cnt++;
		}
		pthread_mutex_unlock(&proc_lock);
		if (i>global.proc_limit)
			usleep_r(50000);
	} while (i>global.proc_limit);

	if (pthread_setspecific(thrid_key, &thrid) != 0) {
		log_error("pthread_setspecific failed.");
		pdnsd_exit();
	}

	pdnsd_free(csock);
	/* rfc1035 says we should process multiple queries in succession, so we are looping until
	 * the socket is closed by the other side or by tcp timeout. 
	 * This in fact makes DoSing easier. If that is your concern, you should disable pdnsd's
	 * TCP server.*/
	while (1) {
#ifdef NO_POLL
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		tv.tv_usec=0;
		tv.tv_sec=global.tcp_qtimeout;
		if (select(sock+1,&fds,NULL,NULL,&tv)<1) {
			close(sock);
			pthread_exit(NULL);
		}
#else
		pfd.fd=sock;
		pfd.events=POLLIN;
		if (poll(&pfd,1,global.tcp_qtimeout*1000)<1) {
			close(sock);
			pthread_exit(NULL);
		}
#endif
		if (read(sock,&rlen,sizeof(rlen))!=sizeof(rlen)) {
			/*
			 * If the socket timed or was closed before we even received the 
			 * query length, we cannot return an error. So exit silently.
			 */
			close(sock);
			pthread_exit(NULL);
		}
		rlen=ntohs(rlen);
		if (rlen == 0) {
			log_error("TCP zero size query received.\n");
			pthread_exit(NULL);
		}
		buf=(unsigned char *)pdnsd_calloc(sizeof(unsigned char),rlen);
		if (!buf) {
			if (da_mem_errs<MEM_MAX_ERRS) {
				da_mem_errs++;
				log_error("Out of memory in request handling.");
			}
			close (sock);
			pthread_exit(NULL);
		}

#ifdef NO_POLL
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		tv.tv_usec=0;
		tv.tv_sec=global.tcp_qtimeout;
		if (select(sock+1,&fds,NULL,NULL,&tv)<1) {
			close(sock);
			pdnsd_free(buf);
			pthread_exit(NULL);
		}
#else
		pfd.fd=sock;
		pfd.events=POLLIN;
		if (poll(&pfd,1,global.tcp_qtimeout*1000)<1) {
			close(sock);
			pdnsd_free(buf);
			pthread_exit(NULL);
		}
#endif
		if ((olen=read(sock,buf,rlen))<rlen) {
			/*
			 * If the promised length was not sent, we should return an error message,
			 * but if read fails that way, it is unlikely that it will arrive. Nevertheless...
			 */
			if (olen<=2) {
				/*
				 * If we did not get the id, we cannot set a valid reply.
				 */
				pdnsd_free(buf);
				close(sock);
				pthread_exit(NULL);
			} else {
				memcpy(&err,buf,sizeof(err)>olen?olen:sizeof(err));
				err=mk_error_reply(err.id,olen>=3?err.opcode:OP_QUERY,RC_FORMAT);
				rlen=htons(sizeof(err));
				if (write_all(sock,&rlen,sizeof(rlen))!=sizeof(rlen)) {
					pdnsd_free(buf);
					close(sock);
					pthread_exit(NULL);
				}
				write_all(sock,&err,sizeof(err)); /* error anyway. */
				pdnsd_free(buf);
				close(sock);
				pthread_exit(NULL);
			}
		} else {
			nlen=rlen;
			if (!(resp=process_query(buf,&nlen,0))) {
			       /*
				* A return value of NULL is a fatal error that prohibits even the sending of an error message.
				* logging is already done. Just exit the thread now.
				*/
				pdnsd_free(buf);
				close(sock);
				pthread_exit(NULL);
			}
			pdnsd_free(buf);
			rlen=htons(nlen);
			if (write_all(sock,&rlen,sizeof(rlen))!=sizeof(rlen)) {
				pdnsd_free(resp);
				close(sock);
				pthread_exit(NULL);
			}
			if (write_all(sock,resp,ntohs(rlen))!=ntohs(rlen)) {
				pdnsd_free(resp);
				close(sock);
				pthread_exit(NULL);
			}
			pdnsd_free(resp);
		}
#ifndef TCP_SUBSEQ
		/* Do not allow multiple queries in one sequence.*/
		close(sock);
		break;
#endif
	}
	pthread_cleanup_pop(1);
	return NULL;
}

int init_tcp_socket()
{
	int sock;
#ifdef ENABLE_IPV4
	struct sockaddr_in sin4;
#endif
#ifdef ENABLE_IPV6
	struct sockaddr_in6 sin6;
#endif
	struct sockaddr *sin;
	int sinl;
	struct protoent *pe=getprotobyname("tcp");

	if (!pe) {
		log_error("Could not get tcp protocol: %s",strerror(errno));
		return -1;
	}
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		if ((sock=socket(PF_INET,SOCK_STREAM,pe->p_proto))==-1) {
			log_error("Could not open tcp socket: %s",strerror(errno));
			return -1;
		}
		memset(&sin4,0,sizeof(sin4));
		sin4.sin_family=AF_INET;
		sin4.sin_port=htons(global.port);
		sin4.sin_addr=global.a.ipv4;
		SET_SOCKA_LEN4(sin4);
		sin=(struct sockaddr *)&sin4;
		sinl=sizeof(sin4);
	}
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6) {
		if ((sock=socket(PF_INET6,SOCK_STREAM,pe->p_proto))==-1) {
			log_error("Could not open tcp socket: %s",strerror(errno));
			return -1;
		}
		memset(&sin6,0,sizeof(sin6));
		sin6.sin6_family=AF_INET6;
		sin6.sin6_port=htons(global.port);
		sin6.sin6_flowinfo=IPV6_FLOWINFO;
		sin6.sin6_addr=global.a.ipv6;
		SET_SOCKA_LEN6(sin6);
		sin=(struct sockaddr *)&sin6;
		sinl=sizeof(sin6);
	}
#endif
	if (bind(sock,sin,sinl)) {
		log_error("Could not bind tcp socket: %s",strerror(errno));
		close(sock);
		return -1;
	}
	return sock;
}

/*
 * Listen on the specified port for tcp connects and answer them (each in a new thread to be nonblocking)
 */
void *tcp_server_thread(void *p)
{
	int sock;
	pthread_t pt;
	int *csock;
	int first=1;

	(void)p; /* To inhibit "unused variable" warning */

	THREAD_SIGINIT;

	if (!global.strict_suid) {
		if (!run_as(global.run_as)) {
			log_error("Could not change user and group id to those of run_as user %s",global.run_as);
			pdnsd_exit();
		}
	}

	sock=tcp_socket;
	
	if (listen(sock,5)) {
		if (da_tcp_errs<TCP_MAX_ERRS) {
			da_tcp_errs++;
			log_error("Could not listen on tcp socket: %s",strerror(errno));
		}
		tcp_up=0;
		if (!udp_up)
			pdnsd_exit();
		return NULL;
	}
	
	while (1) {
		if (!(csock=(int *)pdnsd_calloc(sizeof(int),1))) {
			if (da_mem_errs<MEM_MAX_ERRS) {
				da_mem_errs++;
				log_error("Out of memory in request handling.");
			}
			tcp_up=0;
			if (!udp_up)
				pdnsd_exit();
			return NULL;
		}
		if ((*csock=accept(sock,NULL,0))==-1) {
			pdnsd_free(csock);
			if (errno!=EINTR && first) {
				first=0; /* special handling, not da_tcp_errs*/
				log_error("tcp accept failed: %s",strerror(errno));
			}
			if (errno==EINTR) {
				close(sock);
				tcp_socket=-1;
				return NULL;
			}
			usleep_r(50000);
		} else {
			/*
			 * With creating a new thread, we follow recommendations
			 * in rfc1035 not to block
			 */
			pthread_mutex_lock(&proc_lock);
			if (qprocs<global.proc_limit+global.procq_limit) {
				pthread_attr_t attr;

				qprocs++;
				pthread_mutex_unlock(&proc_lock);
				pthread_attr_init(&attr);
				pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
				pthread_create(&pt,&attr,tcp_answer_thread,(void *)csock);
				pthread_attr_destroy(&attr);
			} else {
				pthread_mutex_unlock(&proc_lock);
				close(*csock);
				pdnsd_free(csock);
				usleep_r(50000);
			}
		}
	}
	close(sock);
	tcp_socket=-1;
	return NULL;
}
#endif

/*
 * Starts the tcp server thread and the udp server thread. Both threads
 * are not terminated, so only a signal can interrupt the server.
 */
void start_dns_servers()
{
	
#ifndef NO_TCP_SERVER       
	if (tcp_socket!=-1) {
		pthread_attr_t attrt;
		pthread_attr_init(&attrt);
		pthread_attr_setdetachstate(&attrt,PTHREAD_CREATE_DETACHED);
		if (pthread_create(&tcps,&attrt,tcp_server_thread,NULL)) {
			log_error("Could not create tcp server thread. Exiting.");
			pdnsd_exit();
		} else
			log_info(2,"tcp server thread started.");
		pthread_attr_destroy(&attrt);
	}		
#endif

	if (udp_socket!=-1) {
		pthread_attr_t attru;
		pthread_attr_init(&attru);
		pthread_attr_setdetachstate(&attru,PTHREAD_CREATE_DETACHED);
		if (pthread_create(&udps,&attru,udp_server_thread,NULL)) {
			log_error("Could not create tcp server thread. Exiting.");
			pdnsd_exit();
		} else
			log_info(2,"udp server thread started.");
		pthread_attr_destroy(&attru);
	}
}
