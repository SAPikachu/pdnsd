/* dns_answer.c - Receive and process incoming dns queries.

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
static char rcsid[]="$Id: dns_answer.c,v 1.60 2002/08/07 08:55:33 tmm Exp $";
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
volatile unsigned long da_tcp_errs=0;
volatile unsigned long da_udp_errs=0;
volatile unsigned long da_mem_errs=0;
volatile unsigned long da_misc_errs=0;
pthread_t tcps;
pthread_t udps;
volatile int procs=0;   /* active query processes */
volatile int qprocs=0;  /* queued query processes */
volatile int thrid_cnt=0;
pthread_mutex_t proc_lock = PTHREAD_MUTEX_INITIALIZER;

#ifdef SOCKET_LOCKING
pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

typedef union {
#ifdef ENABLE_IPV4
# if (TARGET==TARGET_LINUX)
	struct in_pktinfo   pi4;
# else
	struct in_addr      ai4;
# endif
#endif
#ifdef ENABLE_IPV6
	struct in6_pktinfo  pi6;
#endif
} pkt_info_t;

#define udp_buf_len 512

typedef struct {
	union {
#ifdef ENABLE_IPV4
		struct sockaddr_in  sin4;
#endif
#ifdef ENABLE_IPV6
		struct sockaddr_in6 sin6;
#endif
	}                  addr;

	pkt_info_t         pi;

	int                sock;
	int                proto;
	long               len;
	unsigned char      buf[udp_buf_len];
} udp_buf_t;

typedef struct {
	unsigned short qtype;
	unsigned short qclass;
	unsigned char  query[0];
} dns_queryel_t;


#define S_ANSWER     1
#define S_AUTHORITY  2
#define S_ADDITIONAL 3

typedef struct {
	unsigned short tp,dlen;
	unsigned char nm[0];
	/* unsigned char data[0]; */
} sva_t; 


/*
 * Mark an additional record as added to avoid double records.
 */
static int sva_add(dlist *sva, const unsigned char *rhn, unsigned short tp, unsigned short dlen, void* data)
{
	if (sva) {
		size_t rlen=rhnlen(rhn);
		sva_t *st;
		if (!(*sva=dlist_grow(*sva,sizeof(sva_t)+rlen+dlen))) {
			return 0;
		}
		st=dlist_last(*sva);
		st->tp=tp;
		st->dlen=dlen;
		memcpy(mempcpy(st->nm,rhn,rlen),data,dlen);
	}
	return 1;
}

inline static time_t ans_ttl(time_t ttl, time_t ts, time_t queryts, unsigned flags)
{
	if (!(flags&CF_LOCAL)) {
		time_t tpassed=queryts-ts;
		if(tpassed<0) tpassed=0;
		ttl -= tpassed;
		if(ttl<0) ttl=0;
	}
	return ttl;
}

/*
 * Add data from a rr_bucket_t (as in cache) into a dns message in ans. Ans is grown
 * to fit, sz is the old size of the packet (it is modified so at the end of the procedure
 * it is the new size), type is the rr type and ltime is the time in seconds the record is
 * old.
 * cb is the buffer used for message compression. *cb should be NULL when you call compress_name
 * or add_to_response the first time.
 * It gets filled with a pointer to compression information that can be reused in subsequent calls
 * to add_to_response.
 * sect is the section (S_ANSWER, S_AUTHORITY or S_ADDITIONAL) in which the record 
 * belongs logically. Note that you still have to add the rrs in the right order (answer rrs first,
 * then authority and last additional).
 */
static int add_rr(dns_hdr_t **ans, long *sz, unsigned short type, int dlen, void *data, char section, dlist *cb,
		  char udp, unsigned char *rrn, time_t ttl)
{
	int ilen,blen,osz,rdlen;
	unsigned char *rrht;

	osz=*sz;
	{
		int nlen;
		unsigned char nbuf[256];

		if (!(nlen=compress_name(rrn,nbuf,*sz,cb)))
			goto failed;

		/* This buffer is over-allocated usually due to compression. Never mind, just a few bytes,
		 * and the buffer is freed soon*/
		{
			dns_hdr_t *nans=(dns_hdr_t *)pdnsd_realloc(*ans,*sz+nlen+sizeof(rr_hdr_t)+dlen+2);
			if (!nans)
				goto failed;
			*ans=nans;
		}
		memcpy((unsigned char *)(*ans)+*sz,nbuf,nlen);
		*sz+=nlen;
	}

	/* the rr header will be filled in later. Just reserve some space for it. */
	rrht=((unsigned char *)(*ans))+(*sz);
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
		if (!(rdlen=compress_name(((unsigned char *)data), ((unsigned char *)(*ans))+(*sz),*sz,cb)))
			goto failed;
		*sz+=rdlen;
		break;
	case T_MINFO:
#ifdef DNS_NEW_RRS
	case T_RP:
#endif
		if (!(rdlen=compress_name(((unsigned char *)data), ((unsigned char *)(*ans))+(*sz),*sz,cb)))
			goto failed;
		*sz+=rdlen;
		ilen=rhnlen((unsigned char *)data);
		PDNSD_ASSERT(rdlen <= ilen, "T_MINFO/T_RP: got longer");
		if (!(blen=compress_name(((unsigned char *)data)+ilen, ((unsigned char *)(*ans))+(*sz),*sz,cb)))
			goto failed;
		rdlen+=blen;
		*sz+=blen;
		break;
	case T_MX:
#ifdef DNS_NEW_RRS
	case T_AFSDB:
	case T_RT:
	case T_KX:
#endif
		PDNSD_ASSERT(dlen > 2, "T_MX/T_AFSDB/...: rr botch");
		memcpy(((unsigned char *)(*ans))+(*sz),(unsigned char *)data,2);
		*sz+=2;
		if (!(blen=compress_name(((unsigned char *)data)+2, ((unsigned char *)(*ans))+(*sz),*sz,cb)))
			goto failed;
		rdlen=2+blen;
		*sz+=blen;
		break;
	case T_SOA:
		if (!(rdlen=compress_name(((unsigned char *)data), ((unsigned char *)(*ans))+(*sz),*sz,cb)))
			goto failed;
		*sz+=rdlen;
		ilen=rhnlen((unsigned char *)data);
		PDNSD_ASSERT(rdlen <= ilen, "T_SOA: got longer");
		if (!(blen=compress_name(((unsigned char *)data)+ilen, ((unsigned char *)(*ans))+(*sz),*sz,cb)))
			goto failed;
		rdlen+=blen;
		*sz+=blen;
		ilen+=rhnlen(((unsigned char *)data)+ilen);
		PDNSD_ASSERT(rdlen <= ilen, "T_SOA: got longer");
		memcpy(((unsigned char *)(*ans))+(*sz),((unsigned char *)data)+ilen,20);
		*sz+=20;
		rdlen+=20;
		break;
#ifdef DNS_NEW_RRS
	case T_PX:
		PDNSD_ASSERT(dlen > 2, "T_PX: rr botch");
		memcpy(((unsigned char *)(*ans))+(*sz),(unsigned char *)data,2);
		*sz+=2;
		ilen=2;
		if (!(blen=compress_name(((unsigned char *)data)+ilen, ((unsigned char *)(*ans))+(*sz),*sz,cb)))
			goto failed;
		rdlen=2+blen;
		*sz+=blen;
		ilen+=rhnlen(((unsigned char *)data)+ilen);
		PDNSD_ASSERT(rdlen <= ilen, "T_PX: got longer");
		if (!(blen=compress_name(((unsigned char *)data)+ilen, ((unsigned char *)(*ans))+(*sz),*sz,cb)))
			goto failed;
		rdlen+=blen;
		*sz+=blen;
		break;
	case T_SRV:
		PDNSD_ASSERT(dlen > 6, "T_SRV: rr botch");
		memcpy(((unsigned char *)(*ans))+(*sz),(unsigned char *)data,6);
		*sz+=6;
		if (!(blen=compress_name(((unsigned char *)data)+6, ((unsigned char *)(*ans))+(*sz),*sz,cb)))
			goto failed;
		rdlen=6+blen;
		*sz+=blen;
		break;
	case T_NXT:
		if (!(blen=compress_name(((unsigned char *)data), ((unsigned char *)(*ans))+(*sz),*sz,cb)))
			goto failed;
		rdlen=blen;
		*sz+=blen;
		ilen=rhnlen((unsigned char *)data);
		PDNSD_ASSERT(rdlen <= ilen, "T_NXT: got longer");
		PDNSD_ASSERT(dlen >= ilen, "T_NXT: rr botch");
		{
			int wlen=dlen < ilen ? 0 : (dlen - ilen);
			memcpy(((unsigned char *)(*ans))+(*sz),((unsigned char *)data)+ilen,wlen);
			*sz+=wlen;
			rdlen+=wlen;
		}
		break;
	case T_NAPTR:
		PDNSD_ASSERT(dlen > 4, "T_NAPTR: rr botch");
		ilen=4;
		{
			int j;
			for (j=0;j<3;j++) {
				ilen += ((int)*(((unsigned char *)data)+ilen)) + 1;
				PDNSD_ASSERT(dlen > ilen, "T_NAPTR: rr botch 2");
			}
		}
		memcpy(((unsigned char *)(*ans))+(*sz),((unsigned char *)data),ilen);
		(*sz)+=ilen;

		if (!(blen=compress_name(((unsigned char *)data)+ilen, ((unsigned char *)(*ans))+(*sz),*sz,cb)))
			goto failed;
		rdlen=ilen+blen;
		*sz+=blen;
		break;
#endif
	default:
		rdlen=dlen;
		memcpy(((unsigned char *)(*ans))+(*sz),((unsigned char *)data),dlen);
		*sz+=dlen;
	}

	if (udp && (*sz)>512 && section==S_ADDITIONAL) /* only add the record if we do not increase the length over 512 */
		*sz=osz;                               /* in additionals for udp answer*/
	else {
		PUTINT16(type,rrht);
		PUTINT16(C_IN,rrht);
		PUTINT32(ttl,rrht);
		PUTINT16(rdlen,rrht);

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

 failed:
	pdnsd_free(*ans); *ans=NULL;
	return 0;
}

typedef struct rre_s {
	unsigned short tp;
	unsigned short tsz;
	unsigned char  tnm[0];		/* Name for the domain a record refers to */
	/* unsigned char  nm[0]; */	/* Name of the domain the record is for (if tp==T_NS or T_SOA) */
	/* time_t         ttl; */	/* ttl of the record in the answer (if tp==T_NS or T_SOA) */
} rr_ext_t;


/* types for the tp field */
/* #define RRETP_NS	T_NS */		/* For name server: add to authority, add address to additional. */
/* #define RRETP_SOA	T_SOA */	/* For SOA record: add to authority. */
#define RRETP_ADD	0		/* For other records: add the address of buf to additional */

static int add_ar(dlist *ar,unsigned short tp, unsigned short tsz,void *tnm,unsigned char *nm, time_t ttl)
{
	rr_ext_t *re;
	unsigned char *p;
	size_t nmsz=0,size=sizeof(rr_ext_t)+tsz;
	if(tp==T_NS || tp==T_SOA) {
		nmsz=rhnlen(nm);
		size += nmsz + sizeof(time_t);
	}
	if (!(*ar=dlist_grow(*ar,size)))
		return 0;
	re=dlist_last(*ar);
	re->tp=tp;
	re->tsz=tsz;
	p=mempcpy(re->tnm,tnm,tsz);
	if(tp==T_NS || tp==T_SOA) {
		p=mempcpy(p,nm,nmsz);
		memcpy(p,&ttl,sizeof(time_t));
	}
	return 1;
}

#define AR_NUM 5
static const int ar_recs[AR_NUM]={T_NS, T_MD, T_MF, T_MB, T_MX}; 
static const int ar_offs[AR_NUM]={0,0,0,0,2}; /* offsets from record data start to server name */

/* This adds an rrset, optionally randomizing the first element it adds.
 * if that is done, all rrs after the randomized one appear in order, starting from
 * that one and wrapping over if needed. */
static int add_rrset(unsigned tp, dns_hdr_t **ans, long *sz, dns_cent_t *cached, dlist *cb,
		     char udp, unsigned char *rrn, time_t queryts, dlist *sva, dlist *ar)
{
	rr_bucket_t *b;
	rr_bucket_t *first=NULL; /* Initialized to inhibit compiler warning */
	int cnt,i;
	rr_set_t *crrset=cached->rr[tp-T_MIN];

	if (crrset && crrset->rrs) {
		int rnd_recs=global.rnd_recs;
		b=crrset->rrs;
		if (rnd_recs) {
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
			if (!add_rr(ans, sz, tp,b->rdlen,b+1, S_ANSWER,cb,udp,rrn,
				    ans_ttl(crrset->ttl,crrset->ts,queryts,crrset->flags))) 
				return 0;
			if (tp==T_NS || tp==T_A || tp==T_AAAA) {
				/* mark it as added */
				if (!sva_add(sva,rrn,tp,b->rdlen,b+1))
					goto failed;
			}
			/* Mark for additional address records. XXX: this should be a more effective algorithm; at least the list is small */
			for (i=0;i<AR_NUM;i++) {
				if (ar_recs[i]==tp) {
					if (!add_ar(ar, RRETP_ADD,b->rdlen-ar_offs[i],((unsigned char *)(b+1))+ar_offs[i],
						    "", 0))
						goto failed;
					break;
				}
			}
			b=b->next;
			if (rnd_recs) {
				if(!b) b=crrset->rrs; /* wraparound */
				if(b==first)	break;
			}
		}
	}
	return 1;

 failed:
	pdnsd_free(*ans); *ans=NULL;
	return 0;
}

/*
 * Add the fitting elements of the cached record to the message in ans, where ans
 * is grown to fit, sz is the size of the packet and is modified to be the new size.
 * The query is in qe. 
 * cb is the buffer used for message compression. *cb should be NULL if you call add_to_response
 * the first time. It gets filled with a pointer to compression information that can be
 * reused in subsequent calls to add_to_response.
 */
static int add_to_response(unsigned qtype, dns_hdr_t **ans, long *sz, dns_cent_t *cached, dlist *cb,
			   char udp, unsigned char *rrn, time_t queryts, dlist *sva, dlist *ar)
{
	/* first of all, add cnames. Well, actually, there should be at max one in the record. */
	if (qtype!=T_CNAME && qtype!=QT_ALL)
		if (!add_rrset(T_CNAME, ans, sz, cached, cb, udp, rrn, queryts, sva, ar))
			return 0;

	/* We need no switch for qclass, since we already have filtered packets we cannot understand */
	if (qtype==QT_AXFR || qtype==QT_IXFR) {
		/* I do not know what to do in this case. Since we do not maintain zones (and since we are
		   no master server, so it is not our task), I just return an error message. If anyone
		   knows how to do this better, please notify me. 
		   Anyway, this feature is rarely used in client communication, and there is no need for
		   other name servers to ask pdnsd. Btw: many bind servers reject an ?XFR query for security
		   reasons. */
		pdnsd_free(*ans); *ans=NULL;
		return 0; 
	} else if (qtype==QT_MAILB) {
		if (!add_rrset(T_MB, ans, sz, cached, cb, udp, rrn, queryts, sva, ar))
			return 0;
		if (!add_rrset(T_MG, ans, sz, cached, cb, udp, rrn, queryts, sva, ar))
			return 0;
		if (!add_rrset(T_MR, ans, sz, cached, cb, udp, rrn, queryts, sva, ar))
			return 0;
	} else if (qtype==QT_MAILA) {
		if (!add_rrset(T_MD, ans, sz, cached, cb, udp, rrn, queryts, sva, ar))
			return 0;
		if (!add_rrset(T_MF, ans, sz, cached, cb, udp, rrn, queryts, sva, ar))
			return 0;
	} else if (qtype==QT_ALL) {
		unsigned i;
		for (i=T_MIN;i<=T_MAX;i++) {
			if (!add_rrset(i, ans, sz, cached, cb, udp, rrn, queryts, sva, ar))
				return 0;
		}
	} else {
		/* Unsupported elements have been filtered.*/
		if (!add_rrset(qtype, ans, sz, cached, cb, udp, rrn, queryts, sva, ar))
			return 0;
	}
#if 0
	if (!ntohs((*ans)->ancount)) {
		/* Add a SOA if we have one and no other records are present in the answer.
		 * This is to aid caches so that they have a ttl. */
		if (!add_rrset(T_SOA , ans, sz, cached, cb, udp, rrn, queryts, sva, ar))
			return 0;
	}
#endif
	return 1;
}

/*
 * Add an additional
 */
static int add_additional_rr(unsigned char *rhn, dlist *sva, dns_hdr_t **ans,
			     long *rlen, char udp, dlist *cb, unsigned tp,
			     unsigned dlen,void *data, time_t ttl, int sect)
{
	sva_t *st;

	/* Check if already added; no double additionals */
	/* We do NOT look at the data field for addresses, because I feel one address is enough. */
	for (st=dlist_first(*sva); st; st=dlist_next(st)) {
		if (st->tp==tp && rhnicmp(st->nm,rhn) && st->dlen==dlen &&
		    (memcmp(skiprhn(st->nm),data, dlen)==0))
		{
			return 1;
		}
	}
	/* add_rr will do nothing when sz>512 bytes. */
	if(!add_rr(ans, rlen, tp, dlen,data, sect, cb, udp, rhn, ttl))
		return 0;
	/* mark it as added */
	if (!sva_add(sva,rhn,tp,dlen,data)) {
		pdnsd_free(*ans); *ans=NULL;
		return 0;
	}
	return 1;
}

/*
 * The code below actually handles A and AAAA additionals.
 */
static int add_additional_a(unsigned char *rhn, dlist *sva, dns_hdr_t **ans, long *rlen, char udp, time_t queryts, dlist *cb) 
{
	dns_cent_t *ae;
	int retval = 1;

	if ((ae=lookup_cache(rhn,NULL))) {
		rr_set_t *rrset; rr_bucket_t *rr;
		rrset=ae->rr[T_A-T_MIN];
		if (rrset && (rr=rrset->rrs))
		  
			if (!add_additional_rr(rhn, sva, ans, rlen, udp, cb, T_A, rr->rdlen,rr+1,
					       ans_ttl(rrset->ttl,rrset->ts,queryts,rrset->flags),S_ADDITIONAL))
				retval = 0;

#ifdef DNS_NEW_RRS
		if(retval) {
			rrset=ae->rr[T_AAAA-T_MIN];
			if (rrset && (rr=rrset->rrs))
				if (!add_additional_rr(rhn, sva, ans, rlen, udp, cb, T_AAAA, rr->rdlen,rr+1,
						       ans_ttl(rrset->ttl,rrset->ts,queryts,rrset->flags),S_ADDITIONAL))
					retval = 0;
		}
#endif
		free_cent(ae  DBG1);
		pdnsd_free(ae);
	}
	return retval;
}

/*
 * Compose an answer message for the decoded query in q, hdr is the header of the dns request
 * rlen is set to be the answer length.
 */
static unsigned char *compose_answer(dlist q, dns_hdr_t *hdr, long *rlen, char udp) 
{
	short aa=1;
	dlist sva=NULL;
	dlist ar=NULL;
	dlist cb=NULL;
	time_t queryts=time(NULL);
	dns_queryel_t *qe;
	dns_hdr_t *ans;
	dns_cent_t *cached;

	ans=(dns_hdr_t *)pdnsd_malloc(sizeof(dns_hdr_t));
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
	ans->qdcount=0; /* this is first filled in and will be modified */
	ans->ancount=0;
	ans->nscount=0;
	ans->arcount=0;

	*rlen=sizeof(dns_hdr_t);
	/* first, add the query to the response */
	for (qe=dlist_first(q); qe; qe=dlist_next(qe)) {
		int qclen;
		dns_hdr_t *nans=(dns_hdr_t *)pdnsd_realloc(ans,*rlen+rhnlen(qe->query)+4);
		if (!nans)
			goto error_ans;
		ans=nans;
		{
			unsigned char *p = ((unsigned char *)ans) + *rlen;
			/* the first name occurrence will not be compressed,
			   but the offset needs to be stored for future compressions */
			if (!(qclen=compress_name(qe->query,p,*rlen,&cb)))
				goto error_ans;
			p += qclen;
			PUTINT16(qe->qtype,p);
			PUTINT16(qe->qclass,p);
		}
		*rlen += qclen+4;
		ans->qdcount=htons(ntohs(ans->qdcount)+1);
	}

	/* Barf if we get a query we cannot answer */
	for (qe=dlist_first(q); qe; qe=dlist_next(qe)) {
		if (((qe->qtype<T_MIN || qe->qtype>T_MAX) &&
		     (qe->qtype!=QT_MAILB && qe->qtype!=QT_MAILA && qe->qtype!=QT_ALL)) ||
		    (qe->qclass!=C_IN && qe->qclass!=QC_ALL))
		{
			ans->rcode=RC_NOTSUPP;
			return (unsigned char *)ans;
		}
	}
	
	/* second, the answer section */
	for (qe=dlist_first(q); qe; qe=dlist_next(qe)) {
		int hops;
		unsigned char qname[256];

		rhncpy(qname,qe->query);
		/* look if we have a cached copy. otherwise, perform a nameserver query. Same with timeout */
		hops=MAX_HOPS;
		do {
			int rc;
			unsigned char c_soa=cundef;
			if ((rc=dns_cached_resolve(qname, &cached, MAX_HOPS,qe->qtype,queryts,&c_soa))!=RC_OK) {
				ans->rcode=rc;
				if(rc==RC_NAMEERR && c_soa!=cundef) {
					/* Try to add a SOA record to the authority section. */
					unsigned scnt=rhnsegcnt(qname);
					if(c_soa<scnt && (cached=lookup_cache(skipsegs(qname,scnt-c_soa),NULL))) {
						rr_set_t *rrset=cached->rr[T_SOA-T_MIN];
						if (rrset && !(rrset->flags&CF_NEGATIVE)) {
							rr_bucket_t *rr=rrset->rrs;
							while(rr) {
								if (!add_rr(&ans,rlen,T_SOA,rr->rdlen,rr+1,S_AUTHORITY,&cb,udp,cached->qname,
									    ans_ttl(rrset->ttl,rrset->ts,queryts,rrset->flags)))
									goto error_cached;
								rr=rr->next;
							}
						}
						free_cent(cached  DBG1);
						pdnsd_free(cached);
					}
				}
				goto cleanup_return;
			}
			if(!(cached->flags&DF_LOCAL))
				aa=0;

			if (!add_to_response(qe->qtype,&ans,rlen,cached,&cb,udp,qname,queryts,&sva,&ar))
				goto error_cached;
			if (hdr->rd && qe->qtype!=T_CNAME && qe->qtype!=QT_ALL && follow_cname_chain(cached,qname))
				/* The rd bit is set and the response contains a cname (while a different type was requested),
				 * so repeat the inquiry with the cname.
				 * add_to_response() has already added the cname to the response.
				 * Because of follow_cname_chain(), qname now contains the last cname in the chain. */
				;
			else {
				/* maintain a list for authority records: We will add every name server we got an authoritative
				 * answer from (and only those) to this list. This list will be appended to the record. This
				 * is at max one ns record per result. For extensibility, however, we support an arbitrary number
				 * of rrs (including 0) 
				 * We only do this for the last record in a cname chain, to prevent answer bloat. */
				rr_set_t *rrset;
				int rretp=T_NS;
				if((qe->qtype>=T_MIN && qe->qtype<=T_MAX && !have_rr(cached,qe->qtype)) ||
				   (qe->qtype==QT_MAILB && !have_rr(cached,T_MB) && !have_rr(cached,T_MG) && !have_rr(cached,T_MR)) ||
				   (qe->qtype==QT_MAILA && !have_rr(cached,T_MD) && !have_rr(cached,T_MF)))
				{
					/* no record of requested type in the answer section. */
					rretp=T_SOA;
				}
				rrset=cached->rr[rretp-T_MIN];
				if(rrset && (rrset->flags&CF_NEGATIVE))
					rrset=NULL;
				if(!rrset) {
					/* Try to find a name server higher up the hierarchy .
					 */
					dns_cent_t *prev=cached;
					unsigned scnt=rhnsegcnt(prev->qname);
					unsigned tcnt=(rretp==T_NS?prev->c_ns:prev->c_soa);
					if((cached=lookup_cache((tcnt!=cundef && tcnt<scnt)?skipsegs(prev->qname,scnt-tcnt):prev->qname,NULL))) {
						rrset=cached->rr[rretp-T_MIN];
						if(rrset && (rrset->flags&CF_NEGATIVE))
							rrset=NULL;
					}
					if(!rrset && (prev->flags&DF_LOCAL)) {
						unsigned char *nm=getlocalowner(prev->qname,rretp);
						if(nm) {
							if(cached) {
								free_cent(cached  DBG1);
								pdnsd_free(cached);
							}
							if((cached=lookup_cache(nm,NULL)))
								rrset=cached->rr[rretp-T_MIN];
						}
					}
					free_cent(prev  DBG1);
					pdnsd_free(prev);
				}
				if (rrset) {
					rr_bucket_t *rr=rrset->rrs;
					while (rr) {
						if (!add_ar(&ar, rretp, rr->rdlen,rr+1, cached->qname,
							    ans_ttl(rrset->ttl,rrset->ts,queryts,rrset->flags)))
							goto error_cached;
						rr=rr->next;
					}
				}
				hops=0;  /* this will break the loop */
			}
			if(cached) {
				free_cent(cached  DBG1);
				pdnsd_free(cached);
			}
		} while (--hops>=0);
	}

	{
		rr_ext_t *rre;
		/* Add the authority section */
		for (rre=dlist_first(ar); rre; rre=dlist_next(rre)) {
			if (rre->tp == T_NS || rre->tp == T_SOA) {
				unsigned char *nm = rre->tnm + rre->tsz;
				time_t ttl;
				memcpy(&ttl,skiprhn(nm),sizeof(time_t));
				if (!add_additional_rr(nm, &sva, &ans, rlen, udp, &cb, rre->tp, rre->tsz,rre->tnm,
						       ttl, S_AUTHORITY))
				{
					/* ans has already been freed and set to NULL */
					goto cleanup_return;
				}
			}
		}

		/* now add the name server addresses */
		for (rre=dlist_first(ar); rre; rre=dlist_next(rre)) {
			if (rre->tp == T_NS || rre->tp == RRETP_ADD) {
				if (!add_additional_a(rre->tnm, &sva, &ans, rlen, udp, queryts, &cb))
					goto cleanup_return;
			}
		}
	}
	if (aa)
		ans->aa=1;
	goto cleanup_return;

	/* You may not like goto's, but here we avoid lots of code duplication. */
error_cached:
	free_cent(cached  DBG1);
	pdnsd_free(cached);
error_ans:
	pdnsd_free(ans);
	ans=NULL;
cleanup_return:
	dlist_free(sva);
	dlist_free(ar);
	dlist_free(cb);
	return (unsigned char *)ans;
}

/*
 * Decode the query (the query messgage is in data and rlen bytes long) into q
 * XXX: data needs to be aligned
 */
static int decode_query(unsigned char *data, long rlen, dlist *qp)
{
	int i,res;
	dns_hdr_t *hdr=(dns_hdr_t *)data; /* aligned, so no prob. */
	unsigned char *ptr=(unsigned char *)(hdr+1);
	long sz=rlen-sizeof(dns_hdr_t);
	dlist q;
	uint16_t qdcount=ntohs(hdr->qdcount);
	
	if (qdcount==0) 
		return RC_FORMAT;
	
	q=NULL;
	for (i=0;i<qdcount;i++) {
		dns_queryel_t *qe;
		int qlen;
		unsigned char qbuf[256];
		res=decompress_name(data,rlen,&ptr,&sz,qbuf,&qlen);
		if (res==RC_TRUNC) {
			if (hdr->tc) {
				if (i==0) /*not even one complete query*/
					goto return_rc_format;
				break;
			}
			else
				goto return_rc_format;
		}
		if (res!=RC_OK)
			goto cleanup_return;
		if (sz<4) {
			/* truncated in qname or qclass*/
			if (i==0) /*not even one complete query*/
				goto return_rc_format;
			break;
		}
		if(!(q=dlist_grow(q,sizeof(dns_queryel_t)+qlen)))
			return RC_SERVFAIL;
		qe=dlist_last(q);
		GETINT16(qe->qtype,ptr);
		GETINT16(qe->qclass,ptr);
		sz-=4;
		memcpy(qe->query,qbuf,qlen);
	}
	*qp=q;
	return RC_OK;

 return_rc_format:
	res=RC_FORMAT;
 cleanup_return:
	dlist_free(q);
	return res;
}

/* Make a dns error reply message
 * Id is the query id and still in network order.
 * op is the opcode to fill in, rescode - name says it all.
 */
static void mk_error_reply(unsigned short id, unsigned short opcode,unsigned short rescode,dns_hdr_t *rep)
{
	rep->id=id;
	rep->qr=QR_RESP;
	rep->opcode=opcode;
	rep->aa=0;
	rep->tc=0;
	rep->rd=0;
	rep->ra=1;
	rep->z1=0;
	rep->au=0;
	rep->z2=0;
	rep->rcode=rescode;
	rep->qdcount=0;
	rep->ancount=0;
	rep->nscount=0;
	rep->arcount=0;
}

#if 0
/* Debug code contributed by Kiyo Kelvin Lee. */
static void debug_dump_query(void *data, long len)
{
	unsigned char *udata = (unsigned char *)data;
	dns_hdr_t *hdr = (dns_hdr_t *)data;
	char buf[1024];
	char *cp = buf;
	long i, n, l;
	l = (len > 256) ? 256 : len;
	for (i = 0; i < l; i++)
	{
		n = sprintf(cp, "%02x", udata[i]);
		cp += n;
	}
	*cp++ = ' ';
	for (i = 0; i < l; i++)
	{
		*cp++ = isprint(udata[i]) ? udata[i] : '.';
	}
	*cp = '\0';
	DEBUG_MSG("data=%p len=%d\n", udata, len);
	DEBUG_MSG("data%s=%s\n", (l < len) ? "(first 256 bytes)" : "", buf);
	DEBUG_MSG(
		"id=%04x rd=%d tc=%d aa=%d opcode=%04x "
		"qr=%d rcode=%04x z1=%d au=%d z2=%d ra=%d\n",
		hdr->id, hdr->rd, hdr->tc, hdr->aa, hdr->opcode,
		hdr->qr, hdr->rcode, hdr->z1, hdr->au, hdr->z2, hdr->ra);
	DEBUG_MSG(
		"qdcount=%04x ancount=%04x nscount=%04x arcount=%04x\n",
		hdr->qdcount, hdr->ancount, hdr->nscount, hdr->arcount);
}
#else
#define debug_dump_query(d, r)
#endif

/*
 * Analyze and answer the query in data. The answer is returned. rlen is at call the query length and at
 * return the length of the answer. You have to free the answer after sending it.
 */
static unsigned char *process_query(unsigned char *data, long *rlenp, char udp)
{
	long rlen= *rlenp;
	int res;
	dns_hdr_t *hdr;
	dlist q;
	dns_hdr_t *ans;

	debug_dump_query(data, rlen);

	DEBUG_MSG("Received query.\n");
	/*
	 * We will ignore all records that come with a query, except for the actual query records.
	 * We will send back the query in the response. We will reject all non-queries, and
	 * some not supported thingies. 
	 * If anyone notices behaviour that is not in standard conformance, please notify me!
	 */
	hdr=(dns_hdr_t *)data;
	if (rlen<2) { 
		DEBUG_MSG("Message too short.\n");
		return NULL; /* message too short: no id provided. */
	}
	if (rlen<sizeof(dns_hdr_t)) {
		DEBUG_MSG("Message too short.\n");
		res=RC_FORMAT;
		goto error_reply;
	}
	if (hdr->qr==QR_RESP) {
		DEBUG_MSG("Response, not query.\n");
		return NULL; /* RFC says: discard */
	}
	if (hdr->opcode!=OP_QUERY) {
		DEBUG_MSG("No query.\n");
		res=RC_NOTSUPP;
		goto error_reply;
	}
	if (hdr->z1!=0 || hdr->z2!=0) {
		DEBUG_MSG("Malformed query.\n");
		res=RC_FORMAT;
		goto error_reply;
	}
	if (hdr->rcode!=RC_OK) {
		DEBUG_MSG("Bad rcode.\n");
		return NULL; /* discard (may cause error storms) */
	}

	res=decode_query(data,rlen,&q);
	if (res!=RC_OK) {
		goto error_reply;
	}

#if DEBUG>0
	if (debug_p) {
		dns_queryel_t *qe;
		DEBUG_MSG("Questions are:\n");
		for (qe=dlist_first(q); qe; qe=dlist_next(qe)) {
			DEBUG_RHN_MSG("\tqc=%s (%i), qt=%s (%i), query=\"%s\"\n",get_cname(qe->qclass),qe->qclass,get_tname(qe->qtype),qe->qtype,RHN2STR(qe->query));
		}
	}
#endif

	if (!(ans=(dns_hdr_t *)compose_answer(q, hdr, rlenp, udp))) {
		/* An out of memory condition or similar could cause NULL output. Send failure notification */
		dlist_free(q);
		res=RC_SERVFAIL;
		goto error_reply;
	}
	dlist_free(q);
	return (unsigned char *)ans;


 error_reply:
	*rlenp=sizeof(dns_hdr_t);
	{
		dns_hdr_t *resp=pdnsd_malloc(sizeof(dns_hdr_t));
		if (resp) {
			mk_error_reply(hdr->id,rlen>=3?hdr->opcode:OP_QUERY,res,resp);
		}
		else if (++da_mem_errs<=MEM_MAX_ERRS) {
			log_error("Out of memory in query processing.");
		}
		return (unsigned char *)resp;
	}
}

/*
 * Called by *_answer_thread exit handler to clean up process count.
 */
inline static void decrease_procs()
{

	pthread_mutex_lock(&proc_lock);
	procs--;
	qprocs--;
	pthread_mutex_unlock(&proc_lock);
}

static void udp_answer_thread_cleanup(void *data)
{
	pdnsd_free(data);
	decrease_procs();
}

/*
 * A thread opened to answer a query transmitted via udp. Data is a pointer to the structure udp_buf_t that
 * contains the received data and various other parameters.
 * After the query is answered, the thread terminates
 * XXX: data must point to a correctly aligned buffer
 */
static void *udp_answer_thread(void *data)
{
	struct msghdr msg;
	struct iovec v;
	struct cmsghdr *cmsg;
#if defined(SRC_ADDR_DISC)
	char ctrl[CMSG_SPACE(sizeof(pkt_info_t))];
#endif
	long rlen=((udp_buf_t *)data)->len;
	/* XXX: process_query is assigned to this, this mallocs, so this points to aligned memory */
	unsigned char *resp;
	int thrid;
	pthread_cleanup_push(udp_answer_thread_cleanup, data);
	THREAD_SIGINIT;

	if (!global.strict_suid) {
		if (!run_as(global.run_as)) {
			pdnsd_exit();
		}
	}

	for(;;) {
		pthread_mutex_lock(&proc_lock);
		if (procs<global.proc_limit)
			break;
		pthread_mutex_unlock(&proc_lock);
		usleep_r(50000);
	}
	procs++;
	thrid=thrid_cnt++;
	pthread_mutex_unlock(&proc_lock);

	if (pthread_setspecific(thrid_key, &thrid) != 0) {
		log_error("pthread_setspecific failed.");
		pdnsd_exit();
	}

	if (!(resp=process_query(((udp_buf_t *)data)->buf,&rlen,1))) {
		/*
		 * A return value of NULL is a fatal error that prohibits even the sending of an error message.
		 * logging is already done. Just exit the thread now.
		 */
		pthread_exit(NULL); /* data freed by cleanup handler */
	}
	pthread_cleanup_push(free, resp);
	if (rlen>512) {
		rlen=512;
		((dns_hdr_t *)resp)->tc=1; /*set truncated bit*/
	}
	DEBUG_MSG("Outbound msg len %li, tc=%i, rc=\"%s\"\n",rlen,((dns_hdr_t *)resp)->tc,get_ename(((dns_hdr_t *)resp)->rcode));

	v.iov_base=(char *)resp;
	v.iov_len=rlen;
	msg.msg_iov=&v;
	msg.msg_iovlen=1;
#if (TARGET!=TARGET_CYGWIN)
#if defined(SRC_ADDR_DISC)
	msg.msg_control=ctrl;
	msg.msg_controllen=sizeof(ctrl);
#else
	msg.msg_control=NULL;
	msg.msg_controllen=0;
#endif
	msg.msg_flags=0;  /* to avoid warning message by Valgrind */
#endif

#ifdef ENABLE_IPV4
	if (run_ipv4) {

		msg.msg_name=&((udp_buf_t *)data)->addr.sin4;
		msg.msg_namelen=sizeof(struct sockaddr_in);
# if defined(SRC_ADDR_DISC) 
#  if (TARGET==TARGET_LINUX)
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
# if DEBUG>0
		{
			char buf[ADDRSTR_MAXLEN];

			DEBUG_MSG("Answering to: %s", inet_ntop(AF_INET,&((udp_buf_t *)data)->addr.sin4.sin_addr,buf,ADDRSTR_MAXLEN));
#  if defined(SRC_ADDR_DISC)
#   if (TARGET==TARGET_LINUX)
			DEBUG_MSGC(", source address: %s\n", inet_ntop(AF_INET,&((udp_buf_t *)data)->pi.pi4.ipi_spec_dst,buf,ADDRSTR_MAXLEN));
#   else
			DEBUG_MSGC(", source address: %s\n", inet_ntop(AF_INET,&((udp_buf_t *)data)->pi.ai4,buf,ADDRSTR_MAXLEN));
#   endif
#  else
			DEBUG_MSGC("\n");
#  endif
		}
# endif /* DEBUG */
	}
#endif
#ifdef ENABLE_IPV6
	ELSE_IPV6 {

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
# if DEBUG>0
		{
			char buf[ADDRSTR_MAXLEN];

			DEBUG_MSG("Answering to: %s", inet_ntop(AF_INET6,&((udp_buf_t *)data)->addr.sin6.sin6_addr,buf,ADDRSTR_MAXLEN));
#  if defined(SRC_ADDR_DISC)
			DEBUG_MSGC(", source address: %s\n", inet_ntop(AF_INET6,&((udp_buf_t *)data)->pi.pi6.ipi6_addr,buf,ADDRSTR_MAXLEN));
#  else
			DEBUG_MSGC("\n");
#  endif
		}
# endif /* DEBUG */
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
		if (++da_udp_errs<=UDP_MAX_ERRS) {
			log_error("Error in udp send: %s",strerror(errno));
		}
	} else {
		int tmp;
		socklen_t sl=sizeof(tmp);
		getsockopt(((udp_buf_t *)data)->sock, SOL_SOCKET, SO_ERROR, &tmp, &sl);
#ifdef SOCKET_LOCKING
		pthread_mutex_unlock(&s_lock);
#endif
	}
	
	pthread_cleanup_pop(1);  /* free(resp) */
	pthread_cleanup_pop(1);  /* free(data) */
	return NULL;
}

int init_udp_socket()
{
	int sock;
	int so=1;
	union {
#ifdef ENABLE_IPV4
		struct sockaddr_in sin4;
#endif
#ifdef ENABLE_IPV6
		struct sockaddr_in6 sin6;
#endif
	} sin;
	socklen_t sinl;

#ifdef ENABLE_IPV4
	if (run_ipv4) {
		if ((sock=socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP))==-1) {
			log_error("Could not open udp socket: %s",strerror(errno));
			return -1;
		}
		memset(&sin.sin4,0,sizeof(struct sockaddr_in));
		sin.sin4.sin_family=AF_INET;
		sin.sin4.sin_port=htons(global.port);
		sin.sin4.sin_addr=global.a.ipv4;
		SET_SOCKA_LEN4(sin.sin4);
		sinl=sizeof(struct sockaddr_in);
	}
#endif
#ifdef ENABLE_IPV6
	ELSE_IPV6 {
		if ((sock=socket(PF_INET6,SOCK_DGRAM,IPPROTO_UDP))==-1) {
			log_error("Could not open udp socket: %s",strerror(errno));
			return -1;
		}
		memset(&sin.sin6,0,sizeof(struct sockaddr_in6));
		sin.sin6.sin6_family=AF_INET6;
		sin.sin6.sin6_port=htons(global.port);
		sin.sin6.sin6_flowinfo=IPV6_FLOWINFO;
		sin.sin6.sin6_addr=global.a.ipv6;
		SET_SOCKA_LEN6(sin.sin6);
		sinl=sizeof(struct sockaddr_in6);
	}
#endif

#ifdef SRC_ADDR_DISC
# if (TARGET!=TARGET_LINUX)
	if (run_ipv4) {
# endif
		/* The following must be set on any case because it also applies for IPv4 packets sent to
		 * ipv6 addresses. */
# if (TARGET==TARGET_LINUX )
		if (setsockopt(sock,SOL_IP,IP_PKTINFO,&so,sizeof(so))!=0) {
# else
		if (setsockopt(sock,IPPROTO_IP,IP_RECVDSTADDR,&so,sizeof(so))!=0) {
# endif
			log_error("Could not set options on udp socket: %s",strerror(errno));
			close(sock);
			return -1;
		}
# if (TARGET!=TARGET_LINUX)
	}
# endif

# ifdef ENABLE_IPV6
	if (!run_ipv4) {
		if (setsockopt(sock,SOL_IPV6,IPV6_PKTINFO,&so,sizeof(so))!=0) {
			log_error("Could not set options on udp socket: %s",strerror(errno));
			close(sock);
			return -1;
		}
	}
# endif
#endif
	if (bind(sock,(struct sockaddr *)&sin,sinl)!=0) {
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
	pthread_t pt;
	udp_buf_t *buf;
	struct msghdr msg;
	struct iovec v;
	struct cmsghdr *cmsg;
	char ctrl[512];
#if defined(ENABLE_IPV6) && (TARGET==TARGET_LINUX)
	struct in_pktinfo sip;
#endif
	/* (void)dummy; */ /* To inhibit "unused variable" warning */

	THREAD_SIGINIT;


	if (!global.strict_suid) {
		if (!run_as(global.run_as)) {
			pdnsd_exit();
		}
	}

	sock=udp_socket;

	while (1) {
		if (!(buf=(udp_buf_t *)pdnsd_calloc(1,sizeof(udp_buf_t)))) {
			if (++da_mem_errs<=MEM_MAX_ERRS) {
				log_error("Out of memory in request handling.");
			}
			break;
		}

		buf->sock=sock;

		v.iov_base=(char *)buf->buf;
		v.iov_len=udp_buf_len;
		msg.msg_iov=&v;
		msg.msg_iovlen=1;
#if (TARGET!=TARGET_CYGWIN)
		msg.msg_control=ctrl;
		msg.msg_controllen=sizeof(ctrl);
#endif

#if defined(SRC_ADDR_DISC)
# ifdef ENABLE_IPV4
		if (run_ipv4) {
			msg.msg_name=&buf->addr.sin4;
			msg.msg_namelen=sizeof(struct sockaddr_in);
			if ((qlen=recvmsg(sock,&msg,0))>=0) {
				cmsg=CMSG_FIRSTHDR(&msg);
				while(cmsg) {
#  if (TARGET==TARGET_LINUX)
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
					if (++da_udp_errs<=UDP_MAX_ERRS) {
						log_error("Could not discover udp destination address");
					}
					goto free_buf_continue;
				}
			} else if (errno!=EINTR) {
				if (++da_udp_errs<=UDP_MAX_ERRS) {
					log_error("error in UDP recv: %s", strerror(errno));
				}
			}
		}
# endif
# ifdef ENABLE_IPV6
		ELSE_IPV6 {
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
#  if (TARGET==TARGET_LINUX)
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
						if (++da_udp_errs<=UDP_MAX_ERRS) {
							log_error("Could not discover udp destination address");
						}
						goto free_buf_continue;
					}
				}
			} else if (errno!=EINTR) {
				if (++da_udp_errs<=UDP_MAX_ERRS) {
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
				if (++da_udp_errs<=UDP_MAX_ERRS) {
					log_error("error in UDP recv: %s", strerror(errno));
				}
			}
		}
# endif
# ifdef ENABLE_IPV6
		ELSE_IPV6 {
			msg.msg_name=&buf->addr.sin6;
			msg.msg_namelen=sizeof(struct sockaddr_in6);
			qlen=recvmsg(sock,&msg,0);
			if (qlen<0 && errno!=EINTR) {
				if (++da_udp_errs<=UDP_MAX_ERRS) {
					log_error("error in UDP recv: %s", strerror(errno));
				}
			}
		}
# endif
#endif

		if (qlen>=0) {
			pthread_mutex_lock(&proc_lock);
			if (qprocs<global.proc_limit+global.procq_limit) {
				qprocs++;
				pthread_mutex_unlock(&proc_lock);
				buf->len=qlen;
				if(pthread_create(&pt,&attr_detached,udp_answer_thread,(void *)buf)==0)
					continue;
				/* If thread creation failed, free resources associated with it. */
				pthread_mutex_lock(&proc_lock);
				qprocs--;
			}
			pthread_mutex_unlock(&proc_lock);
		}
	free_buf_continue:
		pdnsd_free(buf);
		usleep_r(50000);
	}

	udp_socket=-1;
	close(sock);
	if (tcp_socket==-1)
	  pdnsd_exit();
	return NULL;
}

#ifndef NO_TCP_SERVER

static void tcp_answer_thread_cleanup(void *csock)
{
	close(*((int *)csock));
	pdnsd_free(csock);
	decrease_procs();
}

/*
 * Process a dns query via tcp. The argument is a pointer to the socket.
 */
static void *tcp_answer_thread(void *csock)
{
	/* XXX: This should be OK, the original must be (and is) aligned */
	int sock=*((int *)csock);
	int thrid;

	pthread_cleanup_push(tcp_answer_thread_cleanup, csock);
	THREAD_SIGINIT;

	if (!global.strict_suid) {
		if (!run_as(global.run_as)) {
			pdnsd_exit();
		}
	}

	for(;;) {
		pthread_mutex_lock(&proc_lock);
		if (procs<global.proc_limit)
			break;
		pthread_mutex_unlock(&proc_lock);
		usleep_r(50000);
	}
	procs++;
	thrid=thrid_cnt++;
	pthread_mutex_unlock(&proc_lock);

	if (pthread_setspecific(thrid_key, &thrid) != 0) {
		log_error("pthread_setspecific failed.");
		pdnsd_exit();
	}

	/* rfc1035 says we should process multiple queries in succession, so we are looping until
	 * the socket is closed by the other side or by tcp timeout. 
	 * This in fact makes DoSing easier. If that is your concern, you should disable pdnsd's
	 * TCP server.*/
	while (1) {
		int rlen,olen;
		long nlen;
		unsigned char *buf,*resp;

#ifdef NO_POLL
		fd_set fds;
		struct timeval tv;
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		tv.tv_usec=0;
		tv.tv_sec=global.tcp_qtimeout;
		if (select(sock+1,&fds,NULL,NULL,&tv)<=0)
			pthread_exit(NULL); /* socket is closed by cleanup handler */
#else
		struct pollfd pfd;
		pfd.fd=sock;
		pfd.events=POLLIN;
		if (poll(&pfd,1,global.tcp_qtimeout*1000)<=0)
			pthread_exit(NULL); /* socket is closed by cleanup handler */
#endif
		{
			uint16_t rlen_net;
			if (read(sock,&rlen_net,sizeof(rlen_net))!=sizeof(rlen_net)) {
				/*
				 * If the socket timed or was closed before we even received the 
				 * query length, we cannot return an error. So exit silently.
				 */
				pthread_exit(NULL); /* socket is closed by cleanup handler */
			}
			rlen=ntohs(rlen_net);
		}
		if (rlen == 0) {
			log_error("TCP zero size query received.\n");
			pthread_exit(NULL);
		}
		buf=(unsigned char *)pdnsd_malloc(rlen);
		if (!buf) {
			if (++da_mem_errs<=MEM_MAX_ERRS) {
				log_error("Out of memory in request handling.");
			}
			pthread_exit(NULL); /* socket is closed by cleanup handler */
		}
		pthread_cleanup_push(free, buf);

		olen=0;
		while(olen<rlen) {
			int rv;
#ifdef NO_POLL
			FD_ZERO(&fds);
			FD_SET(sock, &fds);
			tv.tv_usec=0;
			tv.tv_sec=global.tcp_qtimeout;
			if (select(sock+1,&fds,NULL,NULL,&tv)<=0)
				pthread_exit(NULL);  /* buf freed and socket closed by cleanup handlers */
#else
			pfd.fd=sock;
			pfd.events=POLLIN;
			if (poll(&pfd,1,global.tcp_qtimeout*1000)<=0)
				pthread_exit(NULL);  /* buf freed and socket closed by cleanup handlers */
#endif
			rv=read(sock,buf+olen,rlen-olen);
			if (rv<=0) {
				/*
				 * If the promised length was not sent, we should return an error message,
				 * but if read fails that way, it is unlikely that it will arrive. Nevertheless...
				 */
				if (olen>=2) { /* We need the id to send a valid reply. */
					uint16_t slen_net;
					dns_hdr_t err;
					mk_error_reply(((dns_hdr_t*)buf)->id,
						       olen>=3?((dns_hdr_t*)buf)->opcode:OP_QUERY,
						       RC_FORMAT,
						       &err);
					slen_net=htons(sizeof(err));
					if (write_all(sock,&slen_net,sizeof(slen_net))==sizeof(slen_net))
						write_all(sock,&err,sizeof(err)); /* error anyway. */
				}
				pthread_exit(NULL); /* buf freed and socket closed by cleanup handlers */
			}
			olen += rv;
		}
		nlen=rlen;
		if (!(resp=process_query(buf,&nlen,0))) {
			/*
			 * A return value of NULL is a fatal error that prohibits even the sending of an error message.
			 * logging is already done. Just exit the thread now.
			 */
			pthread_exit(NULL);
		}
		pthread_cleanup_pop(1);  /* free(buf) */
		pthread_cleanup_push(free,resp);
		{
			uint16_t slen_net=htons(nlen);
			if (write_all(sock,&slen_net,sizeof(slen_net))!=sizeof(slen_net) || 
			    write_all(sock,resp,nlen)!=nlen) {
				pthread_exit(NULL); /* resp is freed and socket is closed by cleanup handlers */
			}
		}
		pthread_cleanup_pop(1);  /* free(resp) */
#ifndef TCP_SUBSEQ
		/* Do not allow multiple queries in one sequence.*/
		break;
#endif
	}

	/* socket is closed by cleanup handler */
	pthread_cleanup_pop(1);
	return NULL;
}

int init_tcp_socket()
{
	int sock;
	union {
#ifdef ENABLE_IPV4
		struct sockaddr_in sin4;
#endif
#ifdef ENABLE_IPV6
		struct sockaddr_in6 sin6;
#endif
	} sin;
	socklen_t sinl;

#ifdef ENABLE_IPV4
	if (run_ipv4) {
		if ((sock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP))==-1) {
			log_error("Could not open tcp socket: %s",strerror(errno));
			return -1;
		}
		memset(&sin.sin4,0,sizeof(struct sockaddr_in));
		sin.sin4.sin_family=AF_INET;
		sin.sin4.sin_port=htons(global.port);
		sin.sin4.sin_addr=global.a.ipv4;
		SET_SOCKA_LEN4(sin.sin4);
		sinl=sizeof(struct sockaddr_in);
	}
#endif
#ifdef ENABLE_IPV6
	ELSE_IPV6 {
		if ((sock=socket(PF_INET6,SOCK_STREAM,IPPROTO_TCP))==-1) {
			log_error("Could not open tcp socket: %s",strerror(errno));
			return -1;
		}
		memset(&sin.sin6,0,sizeof(struct sockaddr_in6));
		sin.sin6.sin6_family=AF_INET6;
		sin.sin6.sin6_port=htons(global.port);
		sin.sin6.sin6_flowinfo=IPV6_FLOWINFO;
		sin.sin6.sin6_addr=global.a.ipv6;
		SET_SOCKA_LEN6(sin.sin6);
		sinl=sizeof(struct sockaddr_in6);
	}
#endif
	{
		int so=1;
		/* The SO_REUSEADDR socket option tells the kernel that even if this port
		   is busy (in the TIME_WAIT state), go ahead and reuse it anyway. If it
		   is busy, but with another state, we should get an address already in
		   use error. It is useful if pdnsd is shut down, and then restarted right
		   away while sockets are still active on its port. There is a slight risk
		   though. If unexpected data comes in, it may confuse pdnsd, but while
		   this is possible, it is not likely.
		*/
		if(setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&so,sizeof(so)))
			log_warn("Could not set options on tcp socket: %s",strerror(errno));
	}
	if (bind(sock,(struct sockaddr *)&sin,sinl)) {
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

	/* (void)p; */  /* To inhibit "unused variable" warning */

	THREAD_SIGINIT;

	if (!global.strict_suid) {
		if (!run_as(global.run_as)) {
			pdnsd_exit();
		}
	}

	sock=tcp_socket;
	
	if (listen(sock,5)) {
		if (++da_tcp_errs<=TCP_MAX_ERRS) {
			log_error("Could not listen on tcp socket: %s",strerror(errno));
		}
		goto close_sock_return;
	}
	
	while (1) {
		if (!(csock=(int *)pdnsd_malloc(sizeof(int)))) {
			if (++da_mem_errs<=MEM_MAX_ERRS) {
				log_error("Out of memory in request handling.");
			}
			break;
		}
		if ((*csock=accept(sock,NULL,0))==-1) {
			pdnsd_free(csock);
			if (errno==EINTR)
				break;
			else if (first) {
				first=0; /* special handling, not da_tcp_errs*/
				log_error("tcp accept failed: %s",strerror(errno));
			}
		} else {
			/*
			 * With creating a new thread, we follow recommendations
			 * in rfc1035 not to block
			 */
			pthread_mutex_lock(&proc_lock);
			if (qprocs<global.proc_limit+global.procq_limit) {
				qprocs++;
				pthread_mutex_unlock(&proc_lock);
				if(pthread_create(&pt,&attr_detached,tcp_answer_thread,(void *)csock)==0)
					continue;
				/* If thread creation failed, free resources associated with it. */
				pthread_mutex_lock(&proc_lock);
				qprocs--;
			}
			pthread_mutex_unlock(&proc_lock);
			close(*csock);
			pdnsd_free(csock);
		}
		usleep_r(50000);
	}
 close_sock_return:
	tcp_socket=-1;
	close(sock);
	if (udp_socket==-1)
		pdnsd_exit();
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
		if (pthread_create(&tcps,&attr_detached,tcp_server_thread,NULL)) {
			log_error("Could not create tcp server thread. Exiting.");
			pdnsd_exit();
		} else
			log_info(2,"tcp server thread started.");
	}
#endif

	if (udp_socket!=-1) {
		if (pthread_create(&udps,&attr_detached,udp_server_thread,NULL)) {
			log_error("Could not create udp server thread. Exiting.");
			pdnsd_exit();
		} else
			log_info(2,"udp server thread started.");
	}
}
