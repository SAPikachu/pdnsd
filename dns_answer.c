/* dns_answer.c - Receive and process incoming dns queries.
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

#ifndef lint
static char rcsid[]="$Id: dns_answer.c,v 1.5 2000/06/03 21:15:11 thomas Exp $";
#endif

/*
 * STANDARD CONFORMITY
 * 
 * There are several standard conformity issues noted in the comments.
 * Some additional comments:
 *
 * I always set RA but I ignore RD largely (in everything but CNAME recursion), 
 * not because it is not supported, but because I _always_ do a recursive 
 * resolve in order to be able to cache the results.
 *
 */

#include "config.h"
#include "ipvers.h"
#include <pthread.h>
#include <sys/uio.h>
#include <netdb.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "dns.h"
#include "dns_answer.h"
#include "dns_query.h"
#include "helpers.h"
#include "cache.h"
#include "error.h"

/*
 * This is for error handling to prevent spewing the log files.
 * Maximums of different message types are set.
 * Races do not really matter here, so no locks.
 */
#define TCP_MAX_ERRS 5
#define UDP_MAX_ERRS 5
#define MEM_MAX_ERRS 5
#define MISC_MAX_ERRS 5
int da_tcp_errs=0;
int da_udp_errs=0;
int da_mem_errs=0;
int da_misc_errs=0;
pthread_t tcps;
pthread_t udps;

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
# ifdef ENABLE_IPV6
		struct in6_pktinfo  pi6;
# endif
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

typedef struct {
	unsigned short num;
	/*data starts here*/
	dns_queryel_t  first_q;
} dns_query_t;



#define S_ANSWER     1
#define S_AUTHORITY  2
#define S_ADDITIONAL 3

/* T_AAAA is translated to T_A (always added in combination) */
typedef struct {
	unsigned short tp;
	unsigned char nm[256];
} sva_t; 

/*
 * Add an rr from a rr_bucket_t (as in cache) into a dns message in ans. Ans is growed
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
static int add_rr(dns_hdr_t **ans, unsigned long *sz, rr_bucket_t *rr, unsigned short type, char section, compbuf_t **cb, char udp, time_t queryts, unsigned char *rrn, time_t ts, time_t ttl, unsigned short flags)
{
	unsigned char nbuf[256];
	int nlen,ilen,blen,osz;
#ifdef DNS_NEW_RRS
	int j,k,wlen;
#endif
	rr_hdr_t *rrh;

	osz=*sz;
	if (!(nlen=compress_name(rrn,nbuf,*sz,cb))) {
		free(*ans);
		return 0;
	}

	/* This buffer is over-allocated usually due to compression. Never mind, just a few bytes,
	 * and the buffer is freed soon*/
	*ans=(dns_hdr_t *)realloc(*ans,*sz+sizeof(rr_hdr_t)+nlen+rr->rdlen/*+strlen(rr->oname)+1*/);
	if (!*ans)
		return 0;
/*	strcpy((char *)(*ans)+*sz,rr->oname); 
        *sz+=strlen(rr->oname);
        *(((char *)(*ans))+(*sz))='\0';
        *sz+=1; */
	memcpy((unsigned char *)(*ans)+*sz,nbuf,nlen); 
	*sz+=nlen;
	rrh=(rr_hdr_t *)(((unsigned char *)(*ans))+(*sz));
	rrh->type=htons(type);
	rrh->class=htons(C_IN);
	if (flags&CF_LOCAL)
		rrh->ttl=htonl(ttl);
	else {
		rrh->ttl=queryts-ts;
		rrh->ttl=htonl(rrh->ttl>ttl?0:ttl-rrh->ttl);
	}
	rrh->rdlength=0;
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
		if (!(rrh->rdlength=compress_name(((unsigned char *)(rr+1)), ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			free(*ans);
			return 0;
		}
		*sz+=rrh->rdlength;
		break;
	case T_MINFO:
#ifdef DNS_NEW_RRS
	case T_RP:
#endif
		if (!(rrh->rdlength=compress_name(((unsigned char *)(rr+1)), ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			free(*ans);
			return 0;
		}
		*sz+=rrh->rdlength;
		ilen=strlen((char *)(rr+1))+1;
		if (!(blen=compress_name(((unsigned char *)(rr+1))+ilen, ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			free(*ans);
			return 0;
		}
		rrh->rdlength+=blen;
		*sz+=blen;
		break;
	case T_MX:
#ifdef DNS_NEW_RRS
	case T_AFSDB:
	case T_RT:
	case T_KX:
#endif
		memcpy(((unsigned char *)(*ans))+(*sz),(unsigned char *)(rr+1),2);
		*sz+=2;
		if (!(blen=compress_name(((unsigned char *)(rr+1))+2, ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			free(*ans);
			return 0;
		}
		rrh->rdlength=2+blen;
		*sz+=blen;
		break;
	case T_SOA:
		if (!(rrh->rdlength=compress_name(((unsigned char *)(rr+1)), ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			free(*ans);
			return 0;
		}
		*sz+=rrh->rdlength;
		ilen=strlen((char *)(rr+1))+1;
		if (!(blen=compress_name(((unsigned char *)(rr+1))+ilen, ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			free(*ans);
			return 0;
		}
		rrh->rdlength+=blen;
		*sz+=blen;
		ilen+=strlen(((char *)(rr+1))+ilen)+1;
		memcpy(((unsigned char *)(*ans))+(*sz),((unsigned char *)(rr+1))+ilen,sizeof(soa_r_t));
		*sz+=sizeof(soa_r_t);
		rrh->rdlength+=sizeof(soa_r_t);
		break;
#ifdef DNS_NEW_RRS
	case T_PX:
		memcpy(((unsigned char *)(*ans))+(*sz),(unsigned char *)(rr+1),2);
		*sz+=2;
		ilen=2;
		if (!(blen=compress_name(((unsigned char *)(rr+1))+ilen, ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			free(*ans);
			return 0;
		}
		rrh->rdlength=2+blen;
		*sz+=blen;
		ilen+=strlen((char *)(rr+1))+1;
		if (!(blen=compress_name(((unsigned char *)(rr+1))+ilen, ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			free(*ans);
			return 0;
		}
		rrh->rdlength+=blen;
		*sz+=blen;
		break;
	case T_SRV:
		memcpy(((unsigned char *)(*ans))+(*sz),(unsigned char *)(rr+1),6);
		*sz+=6;
		if (!(blen=compress_name(((unsigned char *)(rr+1))+6, ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			free(*ans);
			return 0;
		}
		rrh->rdlength=6+blen;
		*sz+=blen;
		break;
	case T_NXT:
		if (!(blen=compress_name(((unsigned char *)(rr+1))+6, ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			free(*ans);
			return 0;
		}
		rrh->rdlength=blen;
		*sz+=blen;
		ilen=strlen(((char *)(rr+1)))+1;
		wlen=(rr->rdlen-ilen)<0?0:(rr->rdlen-ilen);
		memcpy(((unsigned char *)(*ans))+(*sz),((unsigned char *)(rr+1))+ilen,wlen);
		*sz+=wlen;
		rrh->rdlength+=wlen;

		break;
	case T_NAPTR:
		memcpy(((unsigned char *)(*ans))+(*sz),(unsigned char *)(rr+1),4);
		*sz+=4;
		rrh->rdlength=4;
		for (j=0;j<3;j++) {
			k=*(((unsigned char *)(rr+1))+*sz);
			*(((unsigned char *)(*ans))+(*sz))=k;
			(*sz)++;
			for (;k>0;k--) {
				*(((unsigned char *)(*ans))+(*sz))=*(((unsigned char *)(rr+1))+*sz);
				(*sz)++;
			}
		}
		if (!(blen=compress_name(((unsigned char *)(rr+1))+*sz, ((unsigned char *)(*ans))+(*sz),*sz,cb))) {
			free(*ans);
			return 0;
		}
		rrh->rdlength+=blen;
		*sz+=blen;
		break;
#endif
	default:
		rrh->rdlength=rr->rdlen;
		memcpy(((unsigned char *)(*ans))+(*sz),((unsigned char *)(rr+1)),rr->rdlen);
		*sz+=rr->rdlen;
	}
	if (udp && (*sz)/*+rrh->rdlength*/>512 && section==S_ADDITIONAL) /* only add the record if we do not increase the length over 512 */
		*sz=osz;                                           /* in additionals for udp answer*/
	else {
		rrh->rdlength=htons(rrh->rdlength);
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
/*	rrh->rdlength=htons(rr->rdlen);
        memcpy(((unsigned char *)(*ans))+(*sz),((unsigned char *)rr)+sizeof(rr_bucket_t),rr->rdlen);
	*sz+=rr->rdlen;*/
	return 1;
}

/*
 * Add the fitting elements of the cached record to the message in ans, where ans
 * is growed to fit, sz is the size of the packet and is modified to be the new size.
 * The query is in qe. 
 * cb is the buffer used for message compression. *cb should be NULL if you call add_to_response
 * the first time. It gets filled with a pointer to compression information that can be
 * reused in subsequent calls to add_to_response.
 */
static int add_to_response(dns_queryel_t qe, dns_hdr_t **ans, unsigned long *sz, dns_cent_t *cached, compbuf_t **cb, char udp, unsigned char *rrn, unsigned long queryts, sva_t **sva, int *svan)
{
	unsigned char buf[256];
	int i;
	rr_bucket_t *b;
	/* first of all, add cnames. Well, actually, there should be at max one in the record. */
	if (cached->rr[T_CNAME-T_MIN] != NULL) {
		b=cached->rr[T_CNAME-T_MIN]->rrs;
		while (b) {
			if (!add_rr(ans, sz, b,T_CNAME,S_ANSWER,cb,udp,queryts,rrn,cached->rr[T_CNAME-T_MIN]->ts,
				    cached->rr[T_CNAME-T_MIN]->ttl,cached->rr[T_CNAME-T_MIN]->flags)) 
				return 0;
			b=b->next;
		}
	}
	/* We need no switch for qclass, since we already have filtered packets we cannot understand */
	if (qe.qtype==QT_AXFR || qe.qtype==QT_IXFR) {
		/* I do not know what to do in this case. Since we do not maintain zones (and since we are
		   no master server, so it is not our task), I just return a not implemeted message. If anyone
		   knows how to do this better, please notify me. 
		   Anyway, this feature is rarely used in client communication, and there is no need for
		   other name servers to ask pdnsd. Btw: many bind servers reject an ?XFR query for security
		   reasons. */
		return RC_NOTSUPP; 
	} else if (qe.qtype==QT_MAILB) {
		b=cached->rr[T_MB-T_MIN]->rrs;
		while (b) {
			if (!add_rr(ans, sz,b ,T_MB,S_ANSWER,cb,udp,queryts,rrn,cached->rr[T_MB-T_MIN]->ts,
				    cached->rr[T_MB-T_MIN]->ttl,cached->rr[T_MB-T_MIN]->flags))
				return 0;
			b=b->next;
		}
		b=cached->rr[T_MG-T_MIN]->rrs;
		while (b) {
			if (!add_rr(ans, sz,b ,T_MG,S_ANSWER,cb,udp,queryts,rrn,cached->rr[T_MG-T_MIN]->ts,
				    cached->rr[T_MG-T_MIN]->ttl,cached->rr[T_MG-T_MIN]->flags)) 
				return 0;
			b=b->next;
		}
		b=cached->rr[T_MR-T_MIN]->rrs;
		while (b) {
			if (!add_rr(ans, sz,b ,T_MR,S_ANSWER,cb,udp,queryts,rrn,cached->rr[T_MR-T_MIN]->ts,
				    cached->rr[T_MR-T_MIN]->ttl,cached->rr[T_MR-T_MIN]->flags)) 
				return 0;
			b=b->next;
		}
	} else if (qe.qtype==QT_MAILA) {
		b=cached->rr[T_MD-T_MIN]->rrs;
		while (b) {
			if (!add_rr(ans, sz,b ,T_MD,S_ANSWER,cb,udp,queryts,rrn,cached->rr[T_MD-T_MIN]->ts,
				    cached->rr[T_MD-T_MIN]->ttl,cached->rr[T_MD-T_MIN]->flags)) 
				return 0;
			b=b->next;
		}
		b=cached->rr[T_MF-T_MIN]->rrs;
		while (b) {
			if (!add_rr(ans, sz,b ,T_MF,S_ANSWER,cb,udp,queryts,rrn,cached->rr[T_MF-T_MIN]->ts,
				    cached->rr[T_MF-T_MIN]->ttl,cached->rr[T_MF-T_MIN]->flags)) 
				return 0;
			b=b->next;
		}
	} else if (qe.qtype==QT_ALL) {
		for (i=T_MIN;i<=T_MAX;i++) {
			if (i==T_CNAME)
				continue; /* cnames are added below without name filtering */
			b=cached->rr[i-T_MIN]->rrs;
			while (b) {
				if (!add_rr(ans, sz,b ,i,S_ANSWER,cb,udp,queryts,rrn,cached->rr[i-T_MIN]->ts,
					    cached->rr[i-T_MIN]->ttl,cached->rr[i-T_MIN]->flags)) 
					return 0;
				if (svan && sva && (i==T_NS || i==T_A || i==T_AAAA)) {
				        /* mark it as added */
					(*svan)++;
					if (!(*sva=realloc(*sva,sizeof(sva_t)**svan))) {
						return 0;
					}
					(*sva)[*svan-1].tp=i;
					rhn2str(rrn,buf);
					strcpy((char *)(*sva)[*svan-1].nm,(char *)buf);
				}
				b=b->next;
			}
		}
	} else {
		/* Unsupported elements have been filtered.*/
		b=cached->rr[qe.qtype-T_MIN]->rrs;
		while (b) {
			if (!add_rr(ans, sz,b ,qe.qtype,S_ANSWER,cb,udp,queryts,rrn,cached->rr[qe.qtype-T_MIN]->ts,
				    cached->rr[qe.qtype-T_MIN]->ttl,cached->rr[qe.qtype-T_MIN]->flags)) 
				return 0;
			if (svan && sva && (i==T_NS || i==T_A || i==T_AAAA)) {
				/* mark it as added */
				(*svan)++;
				if (!(*sva=realloc(*sva,sizeof(sva_t)**svan))) {
					return 0;
				}
				(*sva)[*svan-1].tp=qe.qtype;
				rhn2str(rrn,buf);
				strcpy((char *)(*sva)[*svan-1].nm,(char *)buf);
			}
			b=b->next;
		}
	}
	return 1;
}

#define AR_NUM 5
int ar_recs[AR_NUM]={T_NS, T_MD, T_MF, T_MB, T_MX}; 
int ar_offs[AR_NUM]={0,0,0,0,2}; /* offsets from record data start to server name */

typedef struct rre_s {
	unsigned char  nm[256];
	struct rre_s   *next;
	rr_bucket_t    rr;
	unsigned char  buf[256]; /* this is buffer space for the ns record */
	time_t         ts;
	time_t         ttl;
	unsigned short flags;
} rr_ext_t;

/*
 * Compose an answer message for the decoded query in q, hdr is the header of the dns requestm
 * rlen is set to be the answer lenght.
 */
static unsigned char *compose_answer(dns_query_t *q, dns_hdr_t *hdr, unsigned long *rlen, char udp) 
{
	char aa=1;
	unsigned char buf[256],bufr[256],oname[256];
	sva_t *sva;
	int i,j,rc,rc6,hops,cont,cnc,svan=0;
	unsigned long queryts=time(NULL);
	rr_bucket_t *rr,*rr2,*at;
	rr_ext_t *ar,*au,**tmp;
	compbuf_t *cb=NULL;
	dns_hdr_t *ans;
	dns_queryel_t *qe;
	dns_cent_t *cached/*,*bcached*/;
	dns_cent_t *ae;

	ar=NULL;
	ans=(dns_hdr_t *)calloc(sizeof(dns_hdr_t),1);
	if (!ans)
		return NULL;
	ans->id=hdr->id;
	ans->qr=QR_RESP;
	ans->opcode=OP_QUERY;
	ans->aa=0;
	ans->tc=0; /* If tc is needed, it is set when the response is sent in udp_answer_thread. */
	ans->rd=hdr->rd;
	ans->ra=1;
	ans->z=0;
	ans->rcode=RC_OK;
	ans->qdcount=htons(q->num);
	ans->ancount=0; /* this is first filled in and will be modified */
	ans->nscount=0;
	ans->arcount=0;

	*rlen=sizeof(dns_hdr_t);
	/* first, add the query to the response */
	for (i=0;i<q->num;i++) {
		if (!(ans=(dns_hdr_t *)realloc(ans,*rlen+strlen((char *)(&q->first_q)[i].query)+5)))
			return NULL;
		strcpy(((char *)ans)+*rlen,(char *)(&q->first_q)[i].query);
		*rlen+=strlen((char *)(&q->first_q)[i].query)+1;
		((std_query_t *)(((unsigned char *)ans)+*rlen))->qtype=htons((&q->first_q)[i].qtype);
		((std_query_t *)(((unsigned char *)ans)+*rlen))->qclass=htons((&q->first_q)[i].qclass);
		*rlen+=4;
	}
	/* second, the answer section*/
	for (i=0;i<q->num;i++) {
		qe=&(&q->first_q)[i];
		memset(bufr,0,256);
		strcpy((char *)bufr,(char *)qe->query);
		rhn2str(qe->query,buf);
		/* look if we have a cached copy. otherwise, perform a nameserver query. Same with timeout */
		hops=MAX_HOPS;
		do {
			cont=0;
			if ((rc=p_dns_cached_resolve(NULL,buf, bufr, &cached, MAX_HOPS,qe->qtype,queryts))!=RC_OK) {
				while (ar) {
					au=ar->next;
					free_rr(*ar);
					free(ar);
					ar=au;
				}
				if (cb)
					free(cb);
				ans->rcode=rc;
				return (unsigned char *)ans;
			}
/*			if (!(cached->flags&CF_LOCAL))*/
			aa=0;
			strcpy((char *)oname,(char *)buf);
			if (!add_to_response(*qe,&ans,rlen,cached,&cb,udp,bufr,queryts,&sva,&svan)) {
				while (ar) {
					au=ar->next;
					free_rr(*ar);
					free(ar);
					ar=au;
				}
				if (cb)
					free(cb);
				return NULL;
			}
			cnc=follow_cname_chain(cached,buf,bufr);
			hops--;
			/* If there is only a cname and rd is set, add the cname to the response (add_to_response
			 * has already done this) and repeat the inquiry with the c name */
/*			if ((qe->qtype>=QT_MIN || cached->rr[qe->qtype-T_MIN]==NULL) && cached->rr[T_CNAME-T_MIN]!=NULL && hdr->rd!=0) {*/
			if ((qe->qtype>=QT_MIN || !cached->rr[qe->qtype-T_MIN]) && cnc>0 && hdr->rd!=0) {
				/* We did follow_cname_chain, so bufr and buf must contain the last cname in the chain.*/
				/*memset(bufr,0,256);
				strcpy(bufr,(char *)(cached->rr[T_CNAME-T_MIN]+1));
				rhn2str(bufr,buf);*/
				cont=1;
			}
			/* maintain a list for authority records: We will add every name server we got an authoritative
			 * answer from (and only those) to this list. This list will be appended to the record. This
			 * is at max one ns record per result. For extensibility, however, we support an arbitrary number
			 * of rrs (including 0) 
			 * We only do this for the last record in a cname chain, to prevent answer bloat.*/
			if (!cont) {
				tmp=&ar;
				while (*tmp) tmp=&(*tmp)->next;
				rr=cached->rr[T_NS-T_MIN]->rrs;;
				while (rr) {
					if (!(rr2=copy_rr(rr)) || !(*tmp=calloc(sizeof(rr_ext_t),1))) {
						free(ans);
						while (ar) {
							au=ar->next;
							free_rr(ar->rr);
							free(ar);
							ar=au;
						}
						if (cb)
							free(cb);
						return NULL;
					}
					memcpy(&(*tmp)->nm,bufr,256);
					(*tmp)->ts=cached->rr[T_NS-T_MIN]->ts;
					(*tmp)->ttl=cached->rr[T_NS-T_MIN]->ttl;
					(*tmp)->flags=cached->rr[T_NS-T_MIN]->flags;
					memcpy(&(*tmp)->rr,rr2,sizeof(rr_bucket_t)+rr2->rdlen);
					free(rr2);
#if 0
					if (!(cached->flags&CF_LOCAL)) {
						/* set the timestamp correct */
						(*tmp)->ttl=(*tmp)->ttl<time(NULL)-cached->ts?0:(*tmp)->ttl<time(NULL)-cached->ts;
					}
#endif
					rr=rr->next;
					tmp=&(*tmp)->next;
				}
			} else {
				free_cent(*cached);
				free(cached);
			}
		} while (cont && hops>=0);
	}

        /* Add the authority section */
	au=ar;
	while (au) {
		rc=1;
		for (j=0;j<svan;j++) {
			if (sva[j].tp==T_NS && strcmp((char *)sva[j].nm,(char *)buf)==0) {
				rc=0;
				break;
			}
		}
		if (rc) {
			if (!add_rr(&ans, rlen, &au->rr, T_NS, S_AUTHORITY, &cb,udp,queryts,au->nm,au->ts,au->ttl,au->flags)) {
				free_cent(*cached);
				free(cached);
				while (ar) {
					au=ar->next;
					free_rr(ar->rr);
					free(ar);
					ar=au;
				}
				if (cb)
					free(cb);
				return NULL;
			}
			/* mark it as added */
			svan++;
			if (!(sva=realloc(sva,sizeof(sva_t)*svan))) {
				free_cent(*cached);
				free(cached);
				if (cb)
					free(cb);
				return NULL;
			}
			sva[svan-1].tp=T_NS;
			strcpy((char *)sva[svan-1].nm,(char *)buf);
		}
		au=au->next;
	}
	/* Add the additional section */
	sva=NULL;
	svan=0;
	for (i=0;i<AR_NUM;i++) {
		at=cached->rr[ar_recs[i]-T_MIN]->rrs;
		while (at) {
			rhn2str(((unsigned char *)(at+1))+ar_offs[i],buf);
			if ((ae=lookup_cache(buf))) {
				/* Check if already added; no double additionals */
				rc=1;
				for (j=0;j<svan;j++) {
					if (sva[j].tp==T_A && strcmp((char *)sva[j].nm,(char *)buf)==0) {
						rc=0;
						break;
					}
				}
				rc6=1;
				for (j=0;j<svan;j++) {
					if (sva[j].tp==T_AAAA && strcmp((char *)sva[j].nm,(char *)buf)==0) {
						rc6=0;
						break;
					}
				}
				if (rc || rc6) {
                                        /* add_rr will do nothing when sz>512 bytes. */
					if ((rr=ae->rr[T_A-T_MIN]->rrs) && rc)
						add_rr(&ans, rlen, rr, T_A, S_ADDITIONAL, &cb, udp,queryts,(unsigned char *)(at+1),
						       ae->rr[T_A-T_MIN]->ts,ae->rr[T_A-T_MIN]->ttl,ae->rr[T_A-T_MIN]->flags); 
#ifdef DNS_NEW_RRS
					if ((rr=ae->rr[T_AAAA-T_MIN]->rrs) && rc6)
						add_rr(&ans, rlen, rr, T_AAAA, S_ADDITIONAL, &cb,udp,queryts,(unsigned char *)(at+1),
						       ae->rr[T_AAAA-T_MIN]->ts,ae->rr[T_AAAA-T_MIN]->ttl,ae->rr[T_AAAA-T_MIN]->flags);
#endif
				        /* mark it as added */
					svan++;
					if (!(sva=realloc(sva,sizeof(sva_t)*svan))) {
						free_cent(*cached);
						free(cached);
						if (cb)
							free(cb);
						return NULL;
					}
					sva[svan-1].tp=T_A;
					strcpy((char *)sva[svan-1].nm,(char *)buf);
				}
				free_cent(*ae);
				free(ae);
					
			}
			at=at->next;
		}
	}
	/*ar=cached->auth;*/
	/* now add the name server addresses */
	while(ar) {
		rhn2str(ar->buf,buf);
		if ((ae=lookup_cache(buf))) {
			rc=1;
			for (i=0;i<svan;i++) {
				if (sva[j].tp==T_A && strcmp((char *)sva[i].nm,(char *)buf)==0) {
					rc=0;
					break;
				}
			}
			rc6=1;
			for (i=0;i<svan;i++) {
				if (sva[j].tp==T_AAAA && strcmp((char *)sva[i].nm,(char *)buf)==0) {
					rc6=0;
					break;
				}
			}
			if (rc || rc6) {
				/* add_rr will do nothing when sz>512 bytes. */
				if ((rr=ae->rr[T_A-T_MIN]->rrs) && rc)
					add_rr(&ans, rlen, rr, T_A, S_ADDITIONAL, &cb, udp,queryts,ar->buf,
					       ae->rr[T_A-T_MIN]->ts,ae->rr[T_A-T_MIN]->ttl,ae->rr[T_A-T_MIN]->flags); 
#ifdef DNS_NEW_RRS
				if ((rr=ae->rr[T_AAAA-T_MIN]->rrs) && rc6)
					add_rr(&ans, rlen, rr, T_AAAA, S_ADDITIONAL, &cb,udp,queryts,ar->buf,
					       ae->rr[T_AAAA-T_MIN]->ts,ae->rr[T_AAAA-T_MIN]->ttl,ae->rr[T_AAAA-T_MIN]->flags);
#endif
				/* mark it as added */
				svan++;
				if (!(sva=realloc(sva,sizeof(sva_t)*svan))) {
					free_cent(*cached);
					free(cached);
					if (cb)
						free(cb);
					return NULL;
				}
				sva[svan-1].tp=T_A;
				strcpy((char *)sva[svan-1].nm,(char *)buf);
			}
			free_cent(*ae);
			free(ae);
		}
		au=ar->next;
		free_rr(ar->rr);
		free(ar);
		ar=au;
	}
	if (sva)
		free(sva);
	free_cent(*cached);
	free(cached);
	if (cb)
		free(cb);
	if (aa)
		ans->aa=1;
	return (unsigned char *)ans;
}

/* Decode the query (the query messgage is in data and rlen bytes long) into q */
static int decode_query(unsigned char *data,unsigned long rlen, dns_query_t **q)
{
	int i,res,l;
	dns_hdr_t *hdr=(dns_hdr_t *)data;
	unsigned char *ptr=(unsigned char *)(hdr+1);
	long sz=rlen-sizeof(dns_hdr_t);
	if (ntohs(hdr->qdcount)==0) 
		return RC_FORMAT;
	
	*q=(dns_query_t *)calloc(sizeof(dns_query_t)+sizeof(dns_queryel_t)*ntohs(hdr->qdcount),1);
	if (!*q)
		return RC_SERVFAIL;
	(*q)->num=ntohs(hdr->qdcount);
	
	for (i=0;i<ntohs(hdr->qdcount);i++) {
		res=decompress_name(data,(&(*q)->first_q)[i].query,&ptr,&sz,rlen,&l);
		if (res==RC_TRUNC) {
			if (hdr->tc) {
				(*q)->num=i;
				if ((*q)->num==0) {
					free(*q);
					return RC_FORMAT; /*not even one complete query*/
				}
				break;
			} else {
				free(*q);
				return RC_FORMAT;
			}
		} else if (res!=RC_OK) {
			free(*q);
			return res;
		}
		if (sz<4) {
			/* truncated in qname or qclass*/
			(*q)->num=i;
			if ((*q)->num==0) {
				free(*q);
				return RC_FORMAT; /*not even one complete query*/
			}
			break;
		}
		(&(*q)->first_q)[i].qtype=ntohs(*((unsigned short *)ptr));
		sz-=2;
		ptr+=2;
		if ((&(*q)->first_q)[i].qtype<T_MIN || ((&(*q)->first_q)[i].qtype>T_MAX && (/*(&(*q)->first_q)[i].qtype!=QT_AXFR && */
			(&(*q)->first_q)[i].qtype!=QT_MAILA && (&(*q)->first_q)[i].qtype!=QT_MAILB && (&(*q)->first_q)[i].qtype!=QT_ALL))) {
			free(*q);
			return RC_NOTSUPP; /*unknown type*/
		}
		(&(*q)->first_q)[i].qclass=ntohs(*((unsigned short *)ptr));
		sz-=2;
		ptr+=2;
		if ((&(*q)->first_q)[i].qclass!=C_IN && (&(*q)->first_q)[i].qclass!=QC_ALL) {
			free(*q);
			return RC_NOTSUPP; /*only C_IN supported*/
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
	rep.z=0;
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
static unsigned char *process_query(unsigned char *data, unsigned long *rlen, char udp)
{
#if DEBUG>0
	unsigned char buf[256];
#endif

	int res;
	dns_hdr_t *hdr;
	dns_query_t *q;
	dns_hdr_t *resp=(dns_hdr_t *)calloc(sizeof(dns_hdr_t),1);
	dns_hdr_t *ans;
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
		free(resp);
		return NULL; /*message too short: no id provided. */
	}
	if (*rlen<sizeof(dns_hdr_t)) {
		*rlen=sizeof(dns_hdr_t);
		*resp=mk_error_reply(hdr->id,*rlen>=3?hdr->opcode:OP_QUERY,RC_FORMAT);
		return (unsigned char *)resp;
	}
	if (hdr->qr==QR_RESP) {
		*rlen=sizeof(dns_hdr_t);
		*resp=mk_error_reply(hdr->id,hdr->opcode,RC_REFUSED);
		return (unsigned char *)resp;
	}
	if (hdr->opcode!=OP_QUERY) {
		*rlen=sizeof(dns_hdr_t);
		*resp=mk_error_reply(hdr->id,hdr->opcode,RC_NOTSUPP);
		return (unsigned char *)resp;
	}
	if (hdr->z!=0) {
		*rlen=sizeof(dns_hdr_t);
		*resp=mk_error_reply(hdr->id,hdr->opcode,RC_FORMAT);
		return (unsigned char *)resp;
	}
	if (hdr->rcode!=RC_OK) {
		*rlen=sizeof(dns_hdr_t);
		*resp=mk_error_reply(hdr->id,hdr->opcode,RC_FORMAT);
		return (unsigned char *)resp;
	}

	res=decode_query(data,*rlen,&q);
	if (res) {
		*rlen=sizeof(dns_hdr_t);
		*resp=mk_error_reply(hdr->id,hdr->opcode,res);
		return (unsigned char *)resp;
	}

#if DEBUG>0
	if (debug_p) {
		printf("Received query. Questions are:\n ");
		for (res=0;res<q->num;res++) {
			rhn2str((&q->first_q)[res].query,buf);
			printf("\tqc=%s (%i), qt=%s (%i), query=\"%s\"\n",get_cname((&q->first_q)[res].qclass),(&q->first_q)[res].qclass,get_tname((&q->first_q)[res].qtype),(&q->first_q)[res].qtype,buf);
		}
	}
#endif

	if (!(ans=(dns_hdr_t *)compose_answer(q, hdr, rlen, udp))) {
		/* An out of memory condition or similar could cause NULL output. Send failure notification */
		*rlen=sizeof(dns_hdr_t);
		*resp=mk_error_reply(hdr->id,hdr->opcode,RC_SERVFAIL);
		return (unsigned char *)resp;
	}
	free(resp);
	free(q);
	return (unsigned char *)ans;
}

/*
 * A thread opened to answer a query transmitted via udp. Data is a pointer to the structure udp_buf_t that
 * contains the received data and various other parameters.
 * After the query is answered, the thread terminates
 */
void *udp_answer_thread(void *data)
{
#if DEBUG>0
	char buf[50];
#endif
	struct msghdr msg;
	struct iovec v;
	struct cmsghdr *cmsg;
	char ctrl[512];
	unsigned long rlen=((udp_buf_t *)data)->len;
	unsigned char *resp=process_query(((udp_buf_t *)data)->buf,&rlen,1);
	if (!resp) {
		/*
		 * A return value of NULL is a fatal error that prohibits even the sending of an error message.
		 * logging is already done. Just exit the thread now.
		 */
		free(data);
		return NULL;
	}
	if (rlen>512) {
		rlen=512;
		((dns_hdr_t *)resp)->tc=1; /*set truncated bit*/
	}
	DEBUG_MSG4("Outbound msg len %li, tc=%i, rc=\"%s\"\n",rlen,((dns_hdr_t *)resp)->tc,get_ename(((dns_hdr_t *)resp)->rcode));


	v.iov_base=resp;
	v.iov_len=rlen;
	msg.msg_iov=&v;
	msg.msg_iovlen=1;
	msg.msg_control=ctrl;
	msg.msg_controllen=512;

#ifdef ENABLE_IPV4
	if (run_ipv4) {

		msg.msg_name=&((udp_buf_t *)data)->addr.sin4;
		msg.msg_namelen=sizeof(struct sockaddr_in);
# if TARGET==TARGET_LINUX
		((udp_buf_t *)data)->pi.pi4.ipi_spec_dst=((udp_buf_t *)data)->pi.pi4.ipi_addr;
		cmsg=CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len=CMSG_LEN(sizeof(struct in_pktinfo));
		cmsg->cmsg_level=SOL_IP;
		cmsg->cmsg_type=IP_PKTINFO;
		memcpy(CMSG_DATA(cmsg),&((udp_buf_t *)data)->pi.pi4,sizeof(struct in_pktinfo));
		msg.msg_controllen=CMSG_SPACE(sizeof(struct in_pktinfo));
# endif		
		DEBUG_MSG2("Answering to: %s, ", inet_ntoa(((udp_buf_t *)data)->addr.sin4.sin_addr));
# if TARGET==TARGET_LINUX
		DEBUG_MSG2("source address: %s\n", inet_ntoa(((udp_buf_t *)data)->pi.pi4.ipi_spec_dst));
# endif
	}
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6) {

		msg.msg_name=&((udp_buf_t *)data)->addr.sin6;
		msg.msg_namelen=sizeof(struct sockaddr_in6);
# if TARGET==TARGET_LINUX
		cmsg=CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len=CMSG_LEN(sizeof(struct in6_pktinfo));
		cmsg->cmsg_level=SOL_IPV6;
		cmsg->cmsg_type=IPV6_PKTINFO;
		memcpy(CMSG_DATA(cmsg),&((udp_buf_t *)data)->pi.pi6,sizeof(struct in6_pktinfo));
		msg.msg_controllen=CMSG_SPACE(sizeof(struct in6_pktinfo));
# endif

		DEBUG_MSG2("Answering to: %s, ", inet_ntop(AF_INET6,&((udp_buf_t *)data)->addr.sin6.sin6_addr,buf,50));
# if TARGET==TARGET_LINUX
		DEBUG_MSG2("source address: %s\n", inet_ntop(AF_INET6,&((udp_buf_t *)data)->pi.pi6.ipi6_addr,buf,50));
# endif
	}
#endif

	if (sendmsg(((udp_buf_t *)data)->sock,&msg,0)<0) {
		if (da_udp_errs<UDP_MAX_ERRS) {
			da_udp_errs++;
			log_error("Error in udp send: %s",strerror(errno));
		}
	}

	free(resp);
	free(data);
	return NULL;
}

/* 
 * Listen on the specified port for udp packets and answer them (each in a new thread to be nonblocking)
 * This was changed to support sending UDP packets with exactly the same source address as they were coming
 * to us, as required by rfc2181. Although this is a sensible requirement, it is slightly more difficult
 * and may introduce portability issues.
 */
void *udp_server_thread(void *dummy)
{
	struct protoent *pe=getprotobyname("udp");
	int sock;
	long qlen;
#ifdef ENABLE_IPV4
	struct sockaddr_in sin4;
#endif
#ifdef ENABLE_IPV6
	struct sockaddr_in6 sin6;
#endif
	struct sockaddr *sin;
	int sinl;
	pthread_attr_t attr;
	pthread_t pt;
	udp_buf_t *buf;
	struct msghdr msg;
	struct iovec v;
	struct cmsghdr *cmsg;
	char ctrl[512];
	int so=1;
	(void)dummy; /* To inhibit "unused variable" warning */

	if (!pe) {
		if (da_udp_errs<UDP_MAX_ERRS) {
			da_udp_errs++;
			log_error("Could not get udp protocol: %s",strerror(errno));
		}
		return NULL;
	}
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		if ((sock=socket(PF_INET,SOCK_DGRAM,pe->p_proto))==-1) {
			if (da_udp_errs<UDP_MAX_ERRS) {
				da_udp_errs++;
				log_error("Could not open udp socket: %s",strerror(errno));
			}
			return NULL;
		}
		sin4.sin_family=AF_INET;
		sin4.sin_port=htons(global.port);
		sin4.sin_addr.s_addr=INADDR_ANY;
		SET_SOCKA_LEN4(sin4);
		sin=(struct sockaddr *)&sin4;
		sinl=sizeof(sin4);
	}
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6) {
		if ((sock=socket(PF_INET6,SOCK_DGRAM,pe->p_proto))==-1) {
			if (da_udp_errs<UDP_MAX_ERRS) {
				da_udp_errs++;
				log_error("Could not open udp socket: %s",strerror(errno));
			}
			return NULL;
		}
		sin6.sin6_family=AF_INET6;
		sin6.sin6_port=htons(global.port);
		sin6.sin6_flowinfo=IPV6_FLOWINFO;
		sin6.sin6_addr=in6addr_any;
		SET_SOCKA_LEN6(sin6);
		sin=(struct sockaddr *)&sin6;
		sinl=sizeof(sin6);
	}
#endif
	if (bind(sock,sin,sinl)!=0) {
		if (da_udp_errs<UDP_MAX_ERRS) {
			da_udp_errs++;
			log_error("Could bind to udp socket: %s",strerror(errno));
		}
		close(sock);
		return NULL;
	}

#if TARGET==TARGET_LINUX /* RFC compat (only Linux): set source address correctly. */
	if (setsockopt(sock,SOL_IP,IP_PKTINFO,&so,sizeof(so))!=0) {
		if (da_udp_errs<UDP_MAX_ERRS) {
			da_udp_errs++;
			log_error("Could not set options on udp socket: %s",strerror(errno));
		}
		close(sock);
		return NULL;
	}
#endif

	while (1) {
		if (!(buf=(udp_buf_t *)calloc(sizeof(udp_buf_t),1))) {
			if (da_mem_errs<MEM_MAX_ERRS) {
				da_mem_errs++;
				log_error("Out of memory in request handling.");
			}
			return NULL;
		}
		
		buf->sock=sock;

		v.iov_base=buf->buf;
		v.iov_len=512;
		msg.msg_iov=&v;
		msg.msg_iovlen=1;
		msg.msg_control=ctrl;
		msg.msg_controllen=512;

#if TARGET==TARGET_LINUX /* RFC compat (only Linux): set source address correctly. */
# ifdef ENABLE_IPV4
		if (run_ipv4) {
			msg.msg_name=&buf->addr.sin4;
			msg.msg_namelen=sizeof(struct sockaddr_in);
			if ((qlen=recvmsg(sock,&msg,0))<0) {
				free(buf);
				usleep(50000);
				continue;
			}
			cmsg=CMSG_FIRSTHDR(&msg);
			while(cmsg) {
				if (cmsg->cmsg_level==SOL_IP && cmsg->cmsg_type==IP_PKTINFO) {
					memcpy(&buf->pi.pi4,CMSG_DATA(cmsg),sizeof(struct in_pktinfo));
					break;
				}
				cmsg=CMSG_NXTHDR(&msg,cmsg);
			}
			if (!cmsg) {
				if (da_udp_errs<UDP_MAX_ERRS) {
					da_udp_errs++;
					log_error("Could not discover udp destination address");
				}
				free(buf);
				usleep(50000);
				continue;
			}
		}
# endif
# ifdef ENABLE_IPV6
		if (run_ipv6) {
			msg.msg_name=&buf->addr.sin6;
			msg.msg_namelen=sizeof(struct sockaddr_in6);
			if ((qlen=recvmsg(sock,&msg,0))<0) {
				free(buf);
				usleep(50000);
				continue;
			}
			cmsg=CMSG_FIRSTHDR(&msg);
			while(cmsg) {
				if (cmsg->cmsg_level==SOL_IPV6 && cmsg->cmsg_type==IPV6_PKTINFO) {
					memcpy(&buf->pi.pi6,CMSG_DATA(cmsg),sizeof(struct in6_pktinfo));
					break;
				}
				cmsg=CMSG_NXTHDR(&msg,cmsg);
			}
			if (!cmsg) {
				if (da_udp_errs<UDP_MAX_ERRS) {
					da_udp_errs++;
					log_error("Could not discover udp destination address");
				}
				free(buf);
				usleep(50000);
				continue;
			}
		}
# endif
#else /* TARGET==TARGET_LINUX*/
# ifdef ENABLE_IPV4
		if (run_ipv4) {
			msg.msg_name=&buf->addr.sin4;
			msg.msg_namelen=sizeof(struct sockaddr_in);
			if ((qlen=recvmsg(sock,&msg,0))<0) {
				free(buf);
				usleep(50000);
				continue;
			}
		}
# endif
# ifdef ENABLE_IPV6
		if (run_ipv6) {
			msg.msg_name=&buf->addr.sin6;
			msg.msg_namelen=sizeof(struct sockaddr_in6);
			if ((qlen=recvmsg(sock,&msg,0))<0) {
				free(buf);
				usleep(50000);
				continue;
			}
		}
# endif
#endif
		if (qlen==-1) {
			free(buf);
			if (errno==EINTR)
				return NULL;
		} else {
			buf->len=qlen;
			pthread_attr_init(&attr);
			pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
			pthread_create(&pt,&attr,udp_answer_thread,(void *)buf);
		}
	}
	close(sock);
}

/*
 * Process a dns query via tcp. The argument is a pointer to the socket.
 */
void *tcp_answer_thread(void *csock)
{
	dns_hdr_t err;
	unsigned short rlen,olen;
	unsigned long nlen;
	int sock=*((int *)csock);
	unsigned char *buf;
	unsigned char *resp;
	free(csock);
	rlen=htons(rlen);
	/* rfc1035 says we should process multiple queries in succession, so we are looping until
	 * the socket is closed by the other side or by tcp timeout */
	while (1) {
		if (read(sock,&rlen,sizeof(rlen))!=sizeof(rlen)) {
			/*
			 * If the socket timed or was closed before we even received the 
			 * query length, we cannot return an error. So exit silently.
			 */
			close(sock);
			return NULL; 
		}
		rlen=ntohs(rlen);
		buf=(unsigned char *)calloc(sizeof(unsigned char),rlen);
		if (!buf) {
			if (da_mem_errs<MEM_MAX_ERRS) {
				da_mem_errs++;
				log_error("Out of memory in request handling.");
			}
			close (sock);
			return NULL;
		}
		if ((olen=read(sock,buf,rlen))<rlen) {
			/*
			 * If the promised length was not sent, we should return an error message,
			 * but if read fails that way, it is unlikely that it will arrive. Nevertheless...
			 */
			if (olen<=2) {
				/*
				 * If we did not get the id, we cannot set a valid reply.
				 */
				free(buf);
				close(sock);
				return NULL;
			} else {
				err=mk_error_reply(*((unsigned short *)buf),olen>=3?((dns_hdr_t *)buf)->opcode:OP_QUERY,RC_FORMAT);
				if (write(sock,&err,sizeof(err))!=sizeof(err)) {
					free(buf);
					close(sock);
					return NULL;
				}
				
			}
		} else {
			nlen=rlen;
			if (!(resp=process_query(buf,&nlen,0))) {
				/*
				 * A return value of NULL is a fatal error that prohibits even the sending of an error message.
				 * logging is already done. Just exit the thread now.
				 */
				free(buf);
				close(sock);
				return NULL;
			}
			rlen=nlen;
			free(buf);
			rlen=htons(rlen);
			if (write(sock,&rlen,sizeof(rlen))!=sizeof(rlen)) {
				free(resp);
				close(sock);
				return NULL;
			}
			if (write(sock,resp,ntohs(rlen))!=ntohs(rlen)) {
				free(resp);
				close(sock);
				return NULL;
			}
			free(resp);
		}
	}
	return NULL;
}

/*
 * Listen on the specified port for tcp connects and answer them (each in a new thread to be nonblocking)
 */
void *tcp_server_thread(void *p)
{
	struct protoent *pe=getprotobyname("tcp");
	int sock;
#ifdef ENABLE_IPV4
	struct sockaddr_in sin4;
#endif
#ifdef ENABLE_IPV6
	struct sockaddr_in6 sin6;
#endif
	struct sockaddr *sin;
	int sinl;
	pthread_t pt;
	pthread_attr_t attr;
	int *csock;
	int first=1;
	(void)p; /* To inhibit "unused variable" warning */

	if (!pe) {
		if (da_tcp_errs<TCP_MAX_ERRS) {
			da_tcp_errs++;
			log_error("Could not get tcp protocol: %s",strerror(errno));
		}
		return NULL;
	}
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		if ((sock=socket(PF_INET,SOCK_STREAM,pe->p_proto))==-1) {
			if (da_tcp_errs<TCP_MAX_ERRS) {
				da_tcp_errs++;
				log_error("Could not open tcp socket: %s",strerror(errno));
			}
			return NULL;
		}
		sin4.sin_family=AF_INET;
		sin4.sin_port=htons(global.port);
		sin4.sin_addr.s_addr=INADDR_ANY;
		SET_SOCKA_LEN4(sin4);
		sin=(struct sockaddr *)&sin4;
		sinl=sizeof(sin4);
	}
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6) {
		if ((sock=socket(PF_INET6,SOCK_STREAM,pe->p_proto))==-1) {
			if (da_tcp_errs<TCP_MAX_ERRS) {
				da_tcp_errs++;
				log_error("Could not open tcp socket: %s",strerror(errno));
			}
			return NULL;
		}
		sin6.sin6_family=AF_INET6;
		sin6.sin6_port=htons(global.port);
		sin6.sin6_flowinfo=IPV6_FLOWINFO;
		sin6.sin6_addr=in6addr_any;
		SET_SOCKA_LEN6(sin6);
		sin=(struct sockaddr *)&sin6;
		sinl=sizeof(sin6);
	}
#endif
	if (bind(sock,sin,sinl)) {
		if (da_tcp_errs<TCP_MAX_ERRS) {
			da_tcp_errs++;
			log_error("Could not bind tcp socket: %s",strerror(errno));
		}
		return NULL;
	}
	
	if (listen(sock,5)) {
		if (da_tcp_errs<TCP_MAX_ERRS) {
			da_tcp_errs++;
			log_error("Could not listen on tcp socket: %s",strerror(errno));
		}
		return NULL;
	}
	
	while (1) {
		if (!(csock=(int *)calloc(sizeof(int),1))) {
			if (da_mem_errs<MEM_MAX_ERRS) {
				da_mem_errs++;
				log_error("Out of memory in request handling.");
			}
			return NULL;
		}
		if ((*csock=accept(sock,NULL,0))==-1) {
			free(csock);
			if (errno!=EINTR && first) {
				first=0; /* special handling, not da_tcp_errs*/
				log_error("tcp accept failed: %s",strerror(errno));
			}
			usleep(50000);
		} else {
			/*
			 * With creating a new thread, we follow recommendations
			 * in rfc1035 not to block
			 */
			pthread_attr_init(&attr);
			pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
			pthread_create(&pt,&attr,tcp_answer_thread,(void *)csock);
		}
	}
	close(sock);
	return NULL;
}

/*
 * Starts the tcp server thread and the udp server thread. Both threads
 * are not terminated, so only a signal can interrupt the server.
 */
void start_dns_servers()
{
	pthread_attr_t attrt,attru;
	pthread_attr_init(&attrt);
	pthread_attr_setdetachstate(&attrt,PTHREAD_CREATE_DETACHED);
	if (pthread_create(&tcps,&attrt,tcp_server_thread,NULL)) {
		log_error("Could not create tcp server thread. Exiting.");
		pdnsd_exit();
	} else
		log_info(2,"tcp server thread started.");

	pthread_attr_init(&attru);
	pthread_attr_setdetachstate(&attru,PTHREAD_CREATE_DETACHED);
	if (pthread_create(&udps,&attru,udp_server_thread,NULL)) {
		log_error("Could not create tcp server thread. Exiting.");
		pdnsd_exit();
	} else
		log_info(2,"udp server thread started.");
}
