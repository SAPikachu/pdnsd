/* dns_query.c - Execute outgoing dns queries and write entries to cache
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
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include "ipvers.h"
#include "dns_query.h"
#include "cache.h"
#include "dns.h"
#include "conff.h"
#include "servers.h"
#include "helpers.h"
#include "netdev.h"
#include "error.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: dns_query.c,v 1.4 2000/06/04 16:50:08 thomas Exp $";
#endif

unsigned short rid=0; /* rid is the value we fill into the id field. It does not need to be thread-safe. 
		       * We just use it as a debugging aid, and it is not really needed since we use tcp 
		       * connections */

/*
 * Take a rr and do The Right Thing: add it to the cache list if the oname matches the owner name of the
 * cent, otherwise add it to the cache under the right name, creating it when necessary.
 * Note aside: Is locking of the added records required? (surely not for data integrity, but maybe for
 * efficiency in not fetching records twice)
 */
static int rr_to_cache(dns_cent_t *cent, time_t ttl, unsigned char *oname, int dlen, void *data , int tp, int flags, time_t queryts, unsigned long serial)
{
	dns_cent_t ce;
	unsigned char buf[256];
	rhn2str(oname,buf);
	if (strcmp((char *)buf,(char *)cent->qname)==0) {
		/* it is for the record we are editing. add_to_cent is sufficient. 
		 * however, make sure there are no double records. This is done by
		 * add_to_cent */
#ifdef RFC2181_ME_HARDER
		if (cent->rr[tp-T_MIN]->ttl!=ttl)
			return 0;
#endif
		return add_cent_rr(cent,ttl,queryts,flags,dlen,data,tp);
	} else {
		/* try to find a matching record in cache */
		if (have_cached(buf)) {
 			return add_cache_rr_add(buf,ttl,queryts,flags,dlen,data,tp,serial);
		} else {
			if (init_cent(&ce, buf)) {
				if (add_cent_rr(&ce, ttl, queryts,flags, dlen, data, tp)) {
					add_cache(ce);
					free_cent(ce);
					return 1;
				}
			}
			return 0;
		}
	}
	return 0;
}

typedef struct {
	int           num;
	unsigned char first_ns[256];
} ns_t;

/*
 * Takes a pointer (ptr) to a buffer with recnum rrs,decodes them and enters them
 * into a dns_cent_t. *ptr is modified to point after the last rr, and *lcnt is decremented
 * by the size of the rrs.
 * The domain names of all name servers found are placed in *ns, which is automatically grown
 * It may be null initially and must be freed when you are done with it.
 */
static int rrs2cent(dns_cent_t **cent, unsigned char **ptr, long *lcnt, int recnum, unsigned char *msg, long msgsz, int flags, ns_t **ns,time_t queryts,unsigned long serial)
{
	unsigned char oname[256];
	unsigned char db[530];
	rr_hdr_t *rhdr;
	int rc;
	int i;
#ifdef DNS_NEW_RRS
	int j,k;
#endif
	int len;
	int slen;
	unsigned char *bptr,*nptr;
	long blcnt;

	for (i=0;i<recnum;i++) {
		if ((rc=decompress_name(msg, oname, ptr, lcnt, msgsz, &len))!=RC_OK) {
			return rc==RC_TRUNC?RC_FORMAT:rc;
		}
		if (*lcnt<sizeof(rr_hdr_t)) 
			return RC_FORMAT;
		*lcnt-=sizeof(rr_hdr_t);
		rhdr=(rr_hdr_t *)*ptr;
		*ptr+=sizeof(rr_hdr_t);
		if (*lcnt<ntohs(rhdr->rdlength))
			return RC_FORMAT;
		if (!(ntohs(rhdr->type)<T_MIN || ntohs(rhdr->type)>T_MAX || ntohs(rhdr->class)!=C_IN)) {
			/* skip otherwise */
			/* Some types contain names that may be compressed, so these need to be processed.
			 * the other records are taken as they are
			 * The maximum lenth for a decompression buffer is 530 bytes (maximum SOA record length) */
			switch (ntohs(rhdr->type)) {
			case T_CNAME:
			case T_MB:
			case T_MD:
			case T_MF:
			case T_MG:
			case T_MR:
			case T_NS:
			case T_PTR:
				blcnt=*lcnt; /* make backups for decompression, because rdlength is the authoritative */
				bptr=*ptr;   /* record length and pointer and size will by modified by that */
				if ((rc=decompress_name(msg, db, &bptr, &blcnt, msgsz, &len))!=RC_OK) {
					return rc==RC_TRUNC?RC_FORMAT:rc;
				}
				if (*lcnt-blcnt>ntohs(rhdr->rdlength))
					return RC_FORMAT;
				if (ntohs(rhdr->rdlength)>530)
					return RC_FORMAT;
				if (!rr_to_cache(*cent, ntohl(rhdr->ttl), oname, len, db, ntohs(rhdr->type),flags,queryts,serial))
					return RC_SERVFAIL;
				if (ntohs(rhdr->type)==T_NS) {
					/* add to the nameserver list. */
					if (!*ns) {
						if (!(*ns=calloc(sizeof(ns_t),1))) {
							return RC_SERVFAIL;
						}
						(*ns)->num=1;
					} else {
						(*ns)->num++;
						if (!(*ns=realloc(*ns,sizeof(ns_t)*(*ns)->num))) {
							return RC_SERVFAIL;
						}
					}
					rhn2str(db,(&(*ns)->first_ns)[(*ns)->num-1]);
				} 
				break;
			case T_MINFO:
#ifdef DNS_NEW_RRS
			case T_RP:
#endif
				blcnt=*lcnt;
				bptr=*ptr;
				nptr=db;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK) {
					return rc==RC_TRUNC?RC_FORMAT:rc;
				}
				nptr+=len;
				slen=len;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK) {
					return rc==RC_TRUNC?RC_FORMAT:rc;
				}
				/*nptr+=len;*/
				slen+=len;
				if (*lcnt-blcnt>ntohs(rhdr->rdlength))
					return RC_FORMAT;
				if (ntohs(rhdr->rdlength)>530)
					return RC_FORMAT;
				if (!rr_to_cache(*cent, ntohl(rhdr->ttl), oname, slen, db, ntohs(rhdr->type),flags,queryts,serial))
					return RC_SERVFAIL;
				break;
			case T_MX:
#ifdef DNS_NEW_RR
			case T_AFSDB:
			case T_RT:
			case T_KX:
#endif
				if (*lcnt<2)
					return RC_FORMAT;
				memcpy(db,*ptr,2); /* copy the preference field*/
				blcnt=*lcnt-2;
				bptr=*ptr+2;
				nptr=db+2;
				slen=2;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK) {
					return rc==RC_TRUNC?RC_FORMAT:rc;
				}
				/*nptr+=len;*/
				slen+=len;
				if (*lcnt-blcnt>ntohs(rhdr->rdlength))
					return RC_FORMAT;
				if (ntohs(rhdr->rdlength)>530)
					return RC_FORMAT;
				if (!rr_to_cache(*cent, ntohl(rhdr->ttl), oname, slen, db, ntohs(rhdr->type),flags,queryts,serial))
					return RC_SERVFAIL;
				break;
			case T_SOA:
				blcnt=*lcnt;
				bptr=*ptr;
				nptr=db;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK) {
					return rc==RC_TRUNC?RC_FORMAT:rc;
				}
				nptr+=len;
				slen=len;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK) {
					return rc==RC_TRUNC?RC_FORMAT:rc;
				}
				nptr+=len;
				slen+=len;
				blcnt-=20;
				if (blcnt<20)
					return RC_FORMAT;
				memcpy(nptr,bptr,20); /*copy the rest of the SOA record*/
				slen+=20;
				if (*lcnt-blcnt>ntohs(rhdr->rdlength))
					return RC_FORMAT;
				if (ntohs(rhdr->rdlength)>530)
					return RC_FORMAT;
				if (!rr_to_cache(*cent, ntohl(rhdr->ttl), oname, slen, db, ntohs(rhdr->type),flags,queryts,serial))
					return RC_SERVFAIL;
				break;
#ifdef DNS_NEW_RRS
			case T_PX:
				if (*lcnt<2)
					return RC_FORMAT;
				memcpy(db,*ptr,2); /* copy the preference field*/
				blcnt=*lcnt-2;
				bptr=*ptr+2;
				nptr=db+2;
				slen=2;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK) {
					return rc==RC_TRUNC?RC_FORMAT:rc;
				}
				nptr+=len;
				slen+=len;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK) {
					return rc==RC_TRUNC?RC_FORMAT:rc;
				}
				nptr+=len;
				slen+=len;
				if (*lcnt-blcnt>ntohs(rhdr->rdlength))
					return RC_FORMAT;
				if (ntohs(rhdr->rdlength)>530)
					return RC_FORMAT;
				if (!rr_to_cache(*cent, ntohl(rhdr->ttl), oname, slen, db, ntohs(rhdr->type),flags,queryts,serial))
					return RC_SERVFAIL;
				break;
			case T_SRV:
				if (*lcnt<6)
					return RC_FORMAT;
				memcpy(db,*ptr,6);
				blcnt=*lcnt-6;
				bptr=*ptr+6;
				nptr=db+6;
				slen=6;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK) {
					return rc==RC_TRUNC?RC_FORMAT:rc;
				}
				/*nptr+=len;*/
				slen+=len;
				if (*lcnt-blcnt>ntohs(rhdr->rdlength))
					return RC_FORMAT;
				if (ntohs(rhdr->rdlength)>530)
					return RC_FORMAT;
				if (!rr_to_cache(*cent, ntohl(rhdr->ttl), oname, slen, db, ntohs(rhdr->type),flags,queryts,serial))
					return RC_SERVFAIL;
				break;
			case T_NXT:
				blcnt=*lcnt;
				bptr=*ptr;
				nptr=db;
				slen=0;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK) {
					return rc==RC_TRUNC?RC_FORMAT:rc;
				}
				nptr+=len;
				len=blcnt<ntohs(rhdr->rdlength)-len?blcnt:((ntohs(rhdr->rdlength)-len<0?0:ntohs(rhdr->rdlength)-len));
				memcpy(nptr,bptr,len);
				slen+=len;
				blcnt-=len;
				if (*lcnt-blcnt>ntohs(rhdr->rdlength))
					return RC_FORMAT;
				if (ntohs(rhdr->rdlength)>530)
					return RC_FORMAT;
				if (!rr_to_cache(*cent, ntohl(rhdr->ttl), oname, slen, db, ntohs(rhdr->type),flags,queryts,serial))
					return RC_SERVFAIL;
				break;
			case T_NAPTR:
				if (*lcnt<4)
					return RC_FORMAT;
				memcpy(db,*ptr,4); /* copy the preference field*/
				blcnt=*lcnt-4;
				bptr=*ptr+4;
				nptr=db+4;
				slen=4;
				/* 3 text strings following */
				for (j=0;j<3;j++) {
					if (blcnt==0)
						return RC_FORMAT;
					k=*bptr;
					blcnt--;
					slen++;
					*nptr=k;
					nptr++;
					bptr++;
					for (;k>0;k--) {
						if (blcnt==0)
							return RC_TRUNC;
						*nptr=*bptr;
						blcnt--;
						nptr++;
						bptr++;
						slen++;
					}
				}
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK) {
					return rc==RC_TRUNC?RC_FORMAT:rc;
				}
				/*nptr+=len;*/
				slen+=len;
				if (*lcnt-blcnt>ntohs(rhdr->rdlength))
					return RC_FORMAT;
				if (ntohs(rhdr->rdlength)>530)
					return RC_FORMAT;
				if (!rr_to_cache(*cent, ntohl(rhdr->ttl), oname, slen, db, ntohs(rhdr->type),flags,queryts,serial))
					return RC_SERVFAIL;
				break;
#endif
			default:
				if (!rr_to_cache(*cent, ntohl(rhdr->ttl), oname, ntohs(rhdr->rdlength), *ptr, ntohs(rhdr->type),flags,queryts,serial))
					return RC_SERVFAIL;
			}
		}
		*lcnt-=ntohs(rhdr->rdlength);
		*ptr+=ntohs(rhdr->rdlength);
	}
	return RC_OK;
}

/* ------ following is the parallel query code.
 * It has been observed that a whole lot of name servers are just damn lame, with response time
 * of about 1 min. If that slow one is by chance the first server we try, serializing that tries is quite
 * sub-optimal. Also when doing serial queries, the timeout values given in the config will add up, which
 * is not the Right Thing. Now that serial queries are in place, this is still true for CNAME recursion,
 * and for recursion in quest for the holy AA, but not totally for querying multiple servers.
 * The impact not network bandwith should be only marginal (given todays bandwith).
 *
 * The actual strategy is to do (max) PAR_QUERIES parallel queries, and, if these time out or fail, do again
 * that number of queries, until we are successful or there are no more servers to query.
 * Since the memory footprint of a thread is considerably large on some systems, and because we have better
 * control, we will do the parallel queries multiplexed in one thread.
 */

/*
 * The function that will actually execute a query. It takes a state structure in st.
 * st->state must be set to QS_INITIAL before calling. 
 * This may return one of the RC_* codes, where RC_OK indicates success, the other
 * RC codes indicate the appropriate errors. -1 is the return value that indicates that
 * you should call p_exec_query again with the same state for the result until you get
 * a return value >0. Alternatively, call p_cancel_query to cancel it.
 * Timeouts are already handled by this function.
 * Any records that the query has yielded and that are not a direct answer to the query
 * (i.e. are records for other domains) are added to the cache, while the direct answers
 * are returned in ent.
 * All ns records, to whomever they might belong, are additionally returned in the ns list.
 * Free it when done.
 *
 * If you want to tell me that this function has a truly ugly coding style, ah, well...
 * You are right, somehow, but I feel it is conceptually elegant ;-)
 */
static int p_exec_query(dns_cent_t **ent, unsigned char *rrn, unsigned char *name, int *aa, query_stat_t *st, ns_t **ns, unsigned long serial) 
{
	struct protoent *pe;
	int i,rv;
	unsigned int sz;
	unsigned long queryts;
	long lcnt;
	unsigned char *rrp;
#if DEBUG>0
	char buf[ADDRSTR_MAXLEN];
#endif

	switch (st->state){
	case QS_INITIAL:
		if (!st->lean_query)
			st->qt=QT_ALL;
		st->transl=htons(sizeof(dns_hdr_t)+strlen((char *)rrn)+5);
		st->hdr=(dns_hdr_t *)calloc(sizeof(dns_hdr_t)+strlen((char *)rrn)+5,1);
		if (!st->hdr) {
			st->state=QS_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
		if (!(pe=getprotobyname("tcp"))) {
			free(st->hdr);
			DEBUG_MSG2("getprotobyname failed: %s\n", strerror(errno));
			st->state=QS_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
#ifdef ENABLE_IPV4
		if (run_ipv4) {
			if ((st->sock=socket(PF_INET,SOCK_STREAM,pe->p_proto))==-1) {
				free(st->hdr);
				DEBUG_MSG2("Could not open socket: %s\n", strerror(errno));
				st->state=QS_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
			/* sin4 is intialized, hopefully. */
		}
#endif
#ifdef ENABLE_IPV6
		if (run_ipv6) {
			if ((st->sock=socket(PF_INET6,SOCK_STREAM,pe->p_proto))==-1) {
				free(st->hdr);
				DEBUG_MSG2("Could not open socket: %s\n", strerror(errno));
				st->state=QS_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
			/* sin6 is intialized, hopefully. */
		}
#endif
		st->myrid=rid;
		rid++;
		st->hdr->id=htons(st->myrid);
		st->hdr->qr=QR_QUERY;
		st->hdr->opcode=OP_QUERY;
		st->hdr->aa=0;
		st->hdr->tc=0;
		st->hdr->rd=1;
		st->hdr->ra=1;
		st->hdr->z=0;
		st->hdr->rcode=RC_OK;
		st->hdr->qdcount=htons(1);
		st->hdr->ancount=0;
		st->hdr->nscount=0;
		st->hdr->arcount=0;
		strcpy(((char *)(st->hdr+1)),(char *)rrn);
		*(((unsigned char *)(st->hdr+1))+strlen((char *)rrn))='\0';
		((std_query_t *)(((unsigned char *)(st->hdr+1))+strlen((char *)rrn)+1))->qtype=htons(/*QT_ALL*/st->qt);
		((std_query_t *)(((unsigned char *)(st->hdr+1))+strlen((char *)rrn)+1))->qclass=htons(C_IN);
		/* transmit query by tcp*/
		fcntl(st->sock,F_SETFL,O_NONBLOCK);
		st->rts=time(NULL);
		if ((rv=connect(st->sock,st->sin,st->sinl))!=0)
		{
			if (errno==EINPROGRESS) {
				st->state=QS_ALLOC;
			} else {
				/* Since "connection refused" does not cost any time, we do not try to switch the
				 * server status to offline */
				free(st->hdr);
				close(st->sock);
				DEBUG_MSG3("Error while connecting to %s: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),strerror(errno));
				st->state=QS_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
		} else {
			st->state=QS_CONNECT;
			return -1; /* hold on */ 
		}
		/* fall through in case of EINPROGRESS */
	case QS_ALLOC:
#ifdef NO_POLL
		FD_ZERO(&st->writes);
		FD_SET(sock,&st->writes);
		st->tv.tv_sec=0;
		st->tv.tv_usec=0/*PAR_GRAN*1000*/;
		rv=select(st->sock+1,NULL,&st->writes,NULL,&st->tv);
#else
		st->polls.fd=st->sock;
		st->polls.events=POLLOUT;
		rv=poll(&st->polls,1,0/*PAR_GRAN*/);
#endif
		if (rv==0) {
			if (st->rts-time(NULL)>st->timeout) {
				free(st->hdr);
				close(st->sock);
				/* timed out. Try to mark the server as offline if possible */
				if (st->si>0)
					mark_server_down(st->si);
				DEBUG_MSG2("Timeout while connecting to %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN));
				st->state=QS_DONE;
				return RC_SERVFAIL; /* mock error code */
			} else {
				return -1;
			}
		} else if (rv==-1) {
			free(st->hdr);
			close(st->sock);
			DEBUG_MSG2("poll failed: %s\n",strerror(errno));
			st->state=QS_DONE;
			return RC_SERVFAIL; /* mock error code */
		} else {
			sz=sizeof(rv);
			if (getsockopt(st->sock,SOL_SOCKET,SO_ERROR,&rv,&sz)==-1 || rv!=0) {
				free(st->hdr);
				close(st->sock);
				if (rv)
					DEBUG_MSG2("Error on socket: %s\n",strerror(rv));
				else
					DEBUG_MSG2("getsockopt failed: %s\n",strerror(errno));
				st->state=QS_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
		}
		st->state=QS_CONNECT;
		st->rts=time(NULL);
		/* fall through if ok */
	case QS_CONNECT:
		if (write(st->sock,&st->transl,sizeof(st->transl))==-1) {
			if (errno!=EAGAIN) {
				free(st->hdr);
				close(st->sock);
				DEBUG_MSG3("Error while sending data to %s: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),strerror(errno));
				st->state=QS_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
			if (time(NULL)-st->rts>st->timeout) {
				free(st->hdr);
				close(st->sock);
				/* timed out. Try to mark the server as offline if possible */
				if (st->si>=0)
					mark_server_down(st->si);
				DEBUG_MSG2("Timeout while sending data to %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN));
				st->state=QS_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
			return -1;
		}
		st->state=QS_LWRITTEN;
		st->rts=time(NULL);
		/* fall through on success */
	case QS_LWRITTEN:
		if (write(st->sock,st->hdr,ntohs(st->transl))==-1) {
			if (errno!=EAGAIN) {
				free(st->hdr);
				close(st->sock);
				DEBUG_MSG3("Error while sending data to %s: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),strerror(errno));
				st->state=QS_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
			if (time(NULL)-st->rts>st->timeout) {
				free(st->hdr);
				close(st->sock);
				/* timed out. Try to mark the server as offline if possible */
				if (st->si>=0)
					mark_server_down(st->si);
				DEBUG_MSG2("Timeout while sending data to %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN));
				st->state=QS_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
			return -1;
		}
		st->state=QS_QWRITTEN;
		st->rts=time(NULL);
		/* fall through on success */
	case QS_QWRITTEN:
		if (read(st->sock,&st->recvl,sizeof(st->recvl))!=sizeof(st->recvl)) {
			if (errno==EAGAIN) {
				if (time(NULL)-st->rts>st->timeout) {
					free(st->hdr);
					close(st->sock);
					/* timed out. Try to mark the server as offline if possible */
					if (st->si>0)
						mark_server_down(st->si);
					DEBUG_MSG2("Timeout while waiting for data from %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN));
					st->state=QS_DONE;
					return RC_SERVFAIL; /* mock error code */
				}
				return -1;
			} else {
				free(st->hdr);
				close(st->sock);
				DEBUG_MSG3("Error while receiving data from %s: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),strerror(errno));
				st->state=QS_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
		}
		st->recvl=ntohs(st->recvl);
		st->state=QS_LREAD;
		if (!(st->recvbuf=(dns_hdr_t *)calloc(st->recvl,1))) {
			free(st->hdr);
			close(st->sock);
			DEBUG_MSG1("Out of memory in query.\n");
			st->state=QS_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
		st->rts=time(NULL);
		/* fall through on success */
	case QS_LREAD:
		if (read(st->sock,st->recvbuf,st->recvl)!=st->recvl) {
			if (errno==EAGAIN) {
				if (time(NULL)-st->rts>st->timeout) {
					free(st->recvbuf);
					free(st->hdr);
					close(st->sock);
					/* timed out. Try to mark the server as offline if possible */
					if (st->si>0)
						mark_server_down(st->si);
					DEBUG_MSG2("Timeout while waiting for data from %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN));
					st->state=QS_DONE;
					return RC_SERVFAIL; /* mock error code */
				}
				return -1;
			} else {
				free(st->recvbuf);
				free(st->hdr);
				close(st->sock);
				DEBUG_MSG3("Error while receiving data from %s: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),strerror(errno));
				st->state=QS_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
		}
	
                /* Basic sanity checks */
		if (st->recvl<sizeof(dns_hdr_t) || ntohs(st->recvbuf->id)!=st->myrid || st->recvbuf->qr!=QR_RESP || 
		    st->recvbuf->opcode!=OP_QUERY || st->recvbuf->tc || st->recvbuf->z || 
		    (st->recvbuf->rcode!=RC_OK && st->recvbuf->rcode!=RC_NOTSUPP)) {
			free(st->hdr);
			rv=st->recvbuf->rcode;
			free(st->recvbuf);
			close(st->sock);
			st->state=QS_DONE;
			if (rv!=RC_OK) {
				DEBUG_MSG3("Server %s returned error code: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),get_ename(rv));
				return rv;
			}
			DEBUG_MSG2("Server %s returned invalid answer\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN));
			return RC_SERVFAIL; /* mock error code */
		}

		if (!(st->recvbuf->rcode==RC_NOTSUPP || !st->recvbuf->ra)){
			st->state=QS_DONE;
			/* break on success, and if no requery is needed */
			break;
		}
		/* seems as if we have got no recursion avaliable. We will have to do it by ourselves (sigh...) */
		st->state=QS_REQUERY;
		free(st->recvbuf);
		st->hdr->rd=0;
		st->myrid=rid;
		rid++;
		st->hdr->id=htons(st->myrid);
		st->rts=time(NULL);
		/* fall through on requery */
	case QS_REQUERY:
		DEBUG_MSG2("Server %s does not support recursive query. Querying nonrecursive.\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN));
		if (write(st->sock,&st->transl,sizeof(st->transl))==-1) {
			if (errno!=EAGAIN) {
				free(st->hdr);
				close(st->sock);
				DEBUG_MSG3("Error while sending data to %s: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),strerror(errno));
				st->state=QS_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
			if (time(NULL)-st->rts>st->timeout) {
				free(st->hdr);
				close(st->sock);
				/* timed out. Try to mark the server as offline if possible */
				if (st->si>=0)
					mark_server_down(st->si);
				DEBUG_MSG2("Timeout while sending data to %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN));
				st->state=QS_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
			return -1;
		}
		st->state=QS_LWRITTEN2;
		st->rts=time(NULL);
		/* fall through on success */
	case QS_LWRITTEN2:
		while (write(st->sock,st->hdr,ntohs(st->transl))==-1) {
			if (errno!=EAGAIN) {
				free(st->hdr);
				close(st->sock);
				DEBUG_MSG3("Error while sending data to %s: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),strerror(errno));
				st->state=QS_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
			if (time(NULL)-st->rts>st->timeout) {
				free(st->hdr);
				close(st->sock);
				/* timed out. Try to mark the server as offline if possible */
				if (st->si>=0)
					mark_server_down(st->si);
				DEBUG_MSG2("Timeout while sending data to %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN));
				st->state=QS_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
			return -1;
		}
		st->state=QS_QWRITTEN2;
		st->rts=time(NULL);
		/* fall through on success */
	case QS_QWRITTEN2:
		if (read(st->sock,&st->recvl,sizeof(st->recvl))!=sizeof(st->recvl)) {
			if (errno==EAGAIN) {
				if (time(NULL)-st->rts>st->timeout) {
					free(st->hdr);
					close(st->sock);
					/* timed out. Try to mark the server as offline if possible */
					if (st->si>0)
						mark_server_down(st->si);
					DEBUG_MSG3("Error while receiving data from %s: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),strerror(errno));
					st->state=QS_DONE;
					return RC_SERVFAIL; /* mock error code */
				}
				return -1;
			} else {
				free(st->hdr);
				close(st->sock);
				DEBUG_MSG2("Timeout while receiving data from %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN));
				st->state=QS_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
		}
		st->recvl=ntohs(st->recvl);
		if (!(st->recvbuf=(dns_hdr_t *)calloc(st->recvl,1))) {
			free(st->hdr);
			close(st->sock);
			DEBUG_MSG1("Out of memory in query.\n");
			st->state=QS_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
		st->rts=time(NULL);
		st->state=QS_LREAD2;
		/* fall through on success */
	case QS_LREAD2:
		if (read(st->sock,st->recvbuf,st->recvl)!=st->recvl) {
			if (errno==EAGAIN) {
				if (time(NULL)-st->rts>st->timeout) {
					free(st->recvbuf);
					free(st->hdr);
					close(st->sock);
					/* timed out. Try to mark the server as offline if possible */
					if (st->si>0)
						mark_server_down(st->si);
					DEBUG_MSG3("Error while receiving data from %s: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),strerror(errno));
					st->state=QS_DONE;
					return RC_SERVFAIL; /* mock error code */
				}
				return -1;
			} else {
				free(st->recvbuf);
				free(st->hdr);
				close(st->sock);
				DEBUG_MSG2("Timeout while receiving data from %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN));
				st->state=QS_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
		}

		/* Basic sanity checks */
		if (st->recvl<sizeof(dns_hdr_t) || ntohs(st->recvbuf->id)!=st->myrid || st->recvbuf->qr!=QR_RESP || 
		    st->recvbuf->opcode!=OP_QUERY || st->recvbuf->tc || st->recvbuf->z || st->recvbuf->rcode!=RC_OK) {
			free(st->hdr);
			rv=st->recvbuf->rcode;
			free(st->recvbuf);
			close(st->sock);
			st->state=QS_DONE;
			if (rv!=RC_OK) {
				DEBUG_MSG3("Server %s returned error code: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),get_ename(rv));
				return rv;
			}
			DEBUG_MSG2("Server %s returned invalid answer\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN));
			return RC_SERVFAIL; /* mock error code */
		}
		st->state=QS_DONE;
		break;
	case QS_DONE:
		return -1;
	}

        /* If we reach this code, we have successful received an answer,
	 * because we have returned error codes on errors or -1 on AGAIN.
	 * conditions.
	 * So we *should* have a correct dns record in recvbuf by now.
	 * first, if there are any query records, skip them
	 */
	free(st->hdr);
	close(st->sock);
	queryts=time(NULL);
	lcnt=st->recvl;
	rrp=(unsigned char *)(st->recvbuf+1);

	lcnt-=sizeof(dns_hdr_t);
	for (i=0; i<ntohs(st->recvbuf->qdcount);i++) {
		while(*rrp!='\0') {
			rrp++;
			lcnt--;
			if (lcnt<=0) {
				free(st->recvbuf);
				return RC_SERVFAIL; /* mock error code */
			}
		}
		rrp+=5; /*The zero byte plus two shorts (qtype and qclass);*/
		lcnt-=5;
		if (lcnt<=0) {
			free(st->recvbuf);
			return RC_SERVFAIL; /* mock error code */
		}
	}
	/* second: evaluate the results (by putting them in a dns_cent_t */
	*ent=(dns_cent_t *)calloc(sizeof(dns_cent_t),1);
	if (!*ent) {
		free(st->recvbuf);
		return RC_SERVFAIL; /* mock error code */
	}
	if (!init_cent(*ent,name)) {
		free(st->recvbuf);
		return RC_SERVFAIL; /* mock error code */
	}
	/* By marking aa, we mean authoritative AND complete. */
	if (st->qt==QT_ALL)
		*aa=st->recvbuf->aa;
	else
		*aa=0;
	if (!*aa) {
		st->flags|=CF_NOAUTH;
	}
	if (rrs2cent(ent,&rrp,&lcnt,ntohs(st->recvbuf->ancount), (unsigned char *)st->recvbuf,st->recvl,st->flags,ns,queryts,serial)!=RC_OK) {
		free_cent(**ent);
		free(*ent);
		free(st->recvbuf);
		return RC_SERVFAIL;
	}

	if (ntohs(st->recvbuf->nscount)>0) {
		if (rrs2cent(ent,&rrp,&lcnt,ntohs(st->recvbuf->nscount), (unsigned char *)st->recvbuf,st->recvl,st->flags|CF_ADDITIONAL,ns,queryts,serial)!=RC_OK) {
			free(st->recvbuf);
			free_cent(**ent);
			free(*ent);
			return RC_SERVFAIL;
		}
	}
	
	if (ntohs(st->recvbuf->arcount)>0) {
		if (rrs2cent(ent,&rrp,&lcnt,ntohs(st->recvbuf->arcount), (unsigned char *)st->recvbuf,st->recvl,st->flags|CF_ADDITIONAL,ns,queryts,serial)!=RC_OK) {
			free(st->recvbuf);
			free_cent(**ent);
			free(*ent);
			return RC_SERVFAIL;
		}
	}
	free(st->recvbuf);
	return RC_OK;
}

/*
 * Cancel a query, freeing all resources. Any query state is valid as input (this may even be called
 * if a call to p_exec_query already returned error or success) 
 */
static void p_cancel_query(query_stat_t *st) 
{
	switch (st->state){
	case QS_LREAD:
	case QS_LREAD2:
		free(st->recvbuf); /* fall deep */
	case QS_ALLOC:
	case QS_CONNECT:
	case QS_LWRITTEN:
	case QS_QWRITTEN:
	case QS_REQUERY:
	case QS_LWRITTEN2:
	case QS_QWRITTEN2:
		free(st->hdr);
		close(st->sock);
		st->state=QS_DONE;
	}
}

/*
 * Initialize a query_serv_t (server list for parallel query)
 */
static void init_qserv(query_serv_t *q)
{
	q->num=0;
	q->qs=NULL;
}

/*
 * Add a server entry to a query_serv_t
 */
static int add_qserv(query_serv_t *q, pdnsd_a *a, int port, long timeout, int si, int flags, int nocache, int thint, char lean_query)
{
	q->num++;
	q->qs=realloc(q->qs,sizeof(query_stat_t)*q->num);
	if (!q->qs)
		return 0;
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		q->qs[q->num-1].a.sin4.sin_family=AF_INET;
		q->qs[q->num-1].a.sin4.sin_port=htons(port);
		q->qs[q->num-1].a.sin4.sin_addr=a->ipv4;
		SET_SOCKA_LEN4(q->qs[q->num-1].a.sin4);
		q->qs[q->num-1].sin=(struct sockaddr *)&q->qs[q->num-1].a.sin4;
		q->qs[q->num-1].sinl=sizeof(struct sockaddr_in);
	}
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6) {
		q->qs[q->num-1].a.sin6.sin6_family=AF_INET6;
		q->qs[q->num-1].a.sin6.sin6_port=htons(port);
		q->qs[q->num-1].a.sin6.sin6_flowinfo=IPV6_FLOWINFO;
		q->qs[q->num-1].a.sin6.sin6_addr=a->ipv6;
		SET_SOCKA_LEN6(q->qs[q->num-1].a.sin6);
		q->qs[q->num-1].sin=(struct sockaddr *)&q->qs[q->num-1].a.sin6;
		q->qs[q->num-1].sinl=sizeof(struct sockaddr_in6);
	}
#endif
	q->qs[q->num-1].timeout=timeout;
	q->qs[q->num-1].si=si;
	q->qs[q->num-1].flags=flags;
	q->qs[q->num-1].nocache=nocache;
	q->qs[q->num-1].qt=thint;
	q->qs[q->num-1].lean_query=lean_query;
	q->qs[q->num-1].state=QS_INITIAL;
	return 1;
}

/*
 * Free resources used by a query_serv_t
 */
static void del_qserv(query_serv_t *q)
{
	if (q->qs)
		free(q->qs);
}

/*
 * Performs a semi-parallel query on the servers in q. PAR_QUERIES are executed parall at a time.
 * name is the query name in dotted notation, rrn the same in dns protocol format (number.string etc),
 * ent is the dns_cent_t that will be filled. Sv is the server index (as given as si in add_qserv.
 * hops is the number of recursions left.
 * thint is a hint on the requested query type used to decide whether an aa record must be fetched
 * or a non-authoritative answer will be enough.
 *
 * nocache is needed because we add AA records to the cache. If the nocache flag is set, we do not
 * take the original values for the record, but flags=0 and ttl=0 (but only if we do not already have
 * a cached record for that set). This settings cause the record be purged on the next cache addition.
 * It will also not be used again.
 */
static int p_recursive_query(query_serv_t *q, unsigned char *rrn, unsigned char *name, dns_cent_t **ent, int *sv, int hops, int thint)
{
	int aa_needed;
	pdnsd_a serva;
	int aa=0;
	int i,j,k,rv,ad,mc,qo,se,done,nons;
	dns_cent_t *nent,*servent;
	query_serv_t serv;
	unsigned char nsbuf[256],nsname[256];
	unsigned long serial=get_serial();
	ns_t *ns=NULL;
#ifdef DEBUG
	char buf[ADDRSTR_MAXLEN];
#endif
	qo=done=0;

	ad=q->num/PAR_QUERIES;
	if (ad*PAR_QUERIES<q->num)
		ad++;
	for (j=0;j<ad;j++) {
		mc=q->num-j*PAR_QUERIES;
		if (mc>PAR_QUERIES)
			mc=PAR_QUERIES;
		do {
			qo=1;
			for (i=0;i<mc;i++) {
				if (q->qs[PAR_QUERIES*j+i].state!=QS_DONE) {
					qo=0;
					if ((rv=p_exec_query(ent, rrn, name, &aa, &q->qs[PAR_QUERIES*j+i],&ns,serial))==RC_OK) {
						for (k=0;k<mc;k++) {
							p_cancel_query(&q->qs[PAR_QUERIES*j+k]);
						}
						se=PAR_QUERIES*j+i;
						*sv=q->qs[PAR_QUERIES*j+i].si;
						DEBUG_MSG2("Query to %s succeeded.\n",socka2str(q->qs[PAR_QUERIES*j+i].sin,buf,ADDRSTR_MAXLEN));
						break;
					}
				}
			}
			if (!qo)
				usleep(50000);
		} while (!qo);
		if (qo)
			break;
	}
	if (rv!=RC_OK) {
		DEBUG_MSG1("No query succeeded.\n");
		return rv;
	}
	
	/*
	 * Look into the query type hint. If it is a wildcard (QT_*), we need an authoritative answer.
	 * Same if there is no record that answers the query. Mark the cache record if it is not an aa.
	 */
	aa_needed=0;
	if (thint>=QT_MIN && thint<=QT_MAX)
		aa_needed=1;
	else if (thint>=T_MIN && thint<=T_MAX) {
/*		if (!((*ent)->rr[thint-T_MIN]))*/
		if (!(*ent)->rr[thint-T_MIN] && !(*ent)->rr[T_CNAME-T_MIN])
			aa_needed=1;
	}

	if (ns && ns->num>0 && !aa && aa_needed) {
		init_qserv(&serv);
		/* Authority records present. Ask them, because the answer was non-authoritative. To do so, we first put 
		 * the Authority and the additional section into a dns_cent_t and look for name servers in the Authority 
		 * section and their addresses in the Answer and additional sections. If none are found, we also need to 
		 * resolve the name servers.*/
		if (hops>=0) {
			for (j=0;j<ns->num;j++) {
				strcpy((char *)nsname,(char *)(&ns->first_ns)[j]);
				if (!str2rhn(nsname,nsbuf))
					continue;
				/* look it up in the cache or resolve it if needed. The records received should be in the cache now,
				   so it's ok */
#ifdef ENABLE_IPV4
				if (run_ipv4) {
					serva.ipv4.s_addr=INADDR_ANY;
					if (p_dns_cached_resolve(NULL,nsname,nsbuf, &servent, hops-1, T_A,time(NULL))==RC_OK) {
						if (servent->rr[T_A-T_MIN])
							memcpy(&serva.ipv4,(unsigned char *)(servent->rr[T_A-T_MIN]+1),sizeof(serva.ipv4));
						free_cent(*servent);
						free(servent);
					}
				}
#endif
#ifdef ENABLE_IPV6
				if (run_ipv6) {
					serva.ipv6=in6addr_any;
#ifdef DNS_NEW_RRS
					if (p_dns_cached_resolve(NULL,nsname,nsbuf, &servent, hops-1, T_A,time(NULL))==RC_OK) {
						if (servent->rr[T_AAAA-T_MIN])
							memcpy(&serva.ipv6,(unsigned char *)(servent->rr[T_AAAA-T_MIN]+1),sizeof(serva.ipv6));
						free_cent(*servent);
						free(servent);
					}
#endif
					if (!is_inaddr_any(&serva)) {
						if (p_dns_cached_resolve(NULL,nsname,nsbuf, &servent, hops-1, T_A,time(NULL))==RC_OK) {
							if (servent->rr[T_A-T_MIN])
								IPV6_MAPIPV4((struct in_addr *)(servent->rr[T_A-T_MIN]+1),&serva.ipv6);
							free_cent(*servent);
							free(servent);
						}
					}
				}
#endif
				
				if (!is_inaddr_any(&serva)) {
					/* We've got an address. Add it to the list if it wasn't one of the servers we queried. */
					nons=1;
					/* The given address may not be ours!!! */
					/* in netdev.c */
					if (is_local_addr(&serva))
						nons=0;
					if (nons) {
						for (i=0;i<q->num;i++) {
							if (ADDR_EQUIV(SOCKA_A(q->qs[i].sin),&serva)) {
								nons=0;
								break;
							}
						}
					}
					if (nons) {
						/* lean query mode is inherited */
						if (!add_qserv(&serv, &serva, 53, q->qs[se].timeout, -1, q->qs[se].flags, 0,thint,q->qs[se].lean_query)) {
							free_cent(**ent);
							free(*ent);
							free(ns);
							return RC_SERVFAIL;
						}
					}
				}
			}
			if (serv.num>0) {
				if (p_dns_cached_resolve(&serv,  name, rrn, &nent,hops-1,thint,time(NULL))==RC_OK) {
					del_qserv(&serv);
					free_cent(**ent);
					free(*ent);
					*ent=nent;
					
					free(ns);
					return RC_OK;
				}
			}
		}
		del_qserv(&serv);
		/*
		 * If we didn't get rrs from any of the authoritative servers, take the one we had. However, set its timeout to 0,
		 * so that it won't be used again unless it is necessary.
		 */
		for (j=0;j<T_NUM;j++) {
			if ((*ent)->rr[j])
				(*ent)->rr[j]->ttl=0;
		}
	}
	free(ns);

	return RC_OK;
}

/* 
 * following the resolvers. Some take a list of servers for parallel query. The others query the servers supplied by the user.
 */
int p_dns_resolve_from(query_serv_t *q, unsigned char *name, unsigned char *rrn , dns_cent_t **cached, int hops, int thint)
{
	int dummy;
	if (p_recursive_query(q, rrn, name,cached, &dummy, hops, thint)==RC_OK) {
		return RC_OK;
	}
	return RC_NAMEERR;          /* Could not find a record on any server */
} 

int p_dns_resolve(unsigned char *name, unsigned char *rrn , dns_cent_t **cached, int hops, int thint)
{
	int i,rc;
	int one_up=0;
	query_serv_t serv;
	/* first, update records set onquery */
	test_onquery();
	/* try the servers in the order of their definition */
	init_qserv(&serv);
	for (i=0;i<serv_num;i++) {
		if (servers[i].is_up==1) {
			add_qserv(&serv, &servers[i].a, servers[i].port, servers[i].timeout, i, mk_flag_val(&servers[i]),servers[i].nocache,thint,servers[i].lean_query);
			one_up=1;
		}
	}
	if (!one_up) {
		DEBUG_MSG1("No server is marked up.\n");
		del_qserv(&serv);
		return RC_SERVFAIL; /* No server up */
	}


	if ((rc=p_recursive_query(&serv, rrn, name,cached,&i, hops, thint))==RC_OK) {
		if (!servers[i].nocache)
			add_cache(**cached);
		del_qserv(&serv);
		return RC_OK;
	}
	del_qserv(&serv);
	return rc;          /* Could not find a record on any server */
} 

/*
 * Resolve records for name/rrn into dns_cent_t, type thint
 * q is the set of servers to query from. Set q to NULL if you want to ask the servers registered with pdnsd.
 */

int p_dns_cached_resolve(query_serv_t *q, unsigned char *name, unsigned char *rrn , dns_cent_t **cached, int hops, int thint, unsigned long queryts)
{
	dns_cent_t *bcached;
	int rc;
	int need_req=0;
	int timed=0;
	long ttl;
	int auth=0;
	int i,nopurge=0;
	short flags=0;

	DEBUG_MSG3("Starting cached resolve for: %s, query %s\n",name,get_tname(thint));
	if ((*cached=lookup_cache(name))) {
		DEBUG_MSG1("Record found in cache.\n");
		auth=0;
		nopurge=0;
		for (i=0;i<T_MAX;i++) {
			if ((*cached)->rr[i] && ((*cached)->rr[i]->flags&CF_LOCAL || 
						 (*cached)->rr[i]->ttl>=time(NULL)-(*cached)->rr[i]->ts)) {
				if (!(*cached)->rr[i]->flags&CF_NOAUTH) {
					auth=1;
				}
				if ((*cached)->rr[i]->flags&CF_NOPURGE) {
					nopurge=1;
				}
				if (auth && nopurge)
					break;
			}
		}
		flags=(*cached)->rr[thint-T_MIN]->flags;
		ttl=(*cached)->rr[thint-T_MIN]->ttl;
		if (thint>=QT_MIN && thint<=QT_MAX  && !auth)
			need_req=!(flags&CF_LOCAL);
		else {
			/*A CNAME as answer is also correct. */
/*			if (!((*cached)->rr[thint-T_MIN] || (*cached)->rr[T_CNAME-T_MIN]))*/
			if (ttl==0 && !(*cached)->rr[T_CNAME-T_MIN])
				need_req=!auth;
			else {
				if (ttl-queryts+CACHE_LAT<=0)
					timed=1;
			}
		}
		DEBUG_MSG5("Requery decision: req=%i, timed=%i, flags=%i, ttl=%li\n",need_req!=0,timed,flags,ttl-queryts);
	}
	if (!(*cached) || need_req || (timed && !(flags&CF_LOCAL))) {
		bcached=*cached;
		DEBUG_MSG1("Trying name servers.\n");
		if (q) 
			rc=p_dns_resolve_from(q,name, rrn, cached,hops,thint);
		else
			rc=p_dns_resolve(name, rrn, cached,hops,thint);
		if (rc!=RC_OK) {
			if (rc==RC_SERVFAIL && bcached && nopurge) {
				/* We could not get a new record, but we have a timed-out cached one
				   with the nopurge flag set. This means that we shall use it even
				   if timed out when no new one is available*/
				DEBUG_MSG1("Falling back to cached record.\n");
				*cached=bcached;
			} else {
				if (bcached) {
					free_cent(*bcached);
					free(bcached);
				}
				return RC_SERVFAIL;
			}
		} else {
			if (bcached) {
				free_cent(*bcached);
				free(bcached);
			}
		}
	} else {
		DEBUG_MSG1("Using cached record.\n");
	}
	return RC_OK;
}
