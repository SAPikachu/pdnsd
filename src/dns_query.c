/* dns_query.c - Execute outgoing dns queries and write entries to cache
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

#include <config.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include "list.h"
#include "consts.h"
#include "ipvers.h"
#include "dns_query.h"
#include "cache.h"
#include "dns.h"
#include "conff.h"
#include "servers.h"
#include "helpers.h"
#include "netdev.h"
#include "error.h"
#include "debug.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: dns_query.c,v 1.41 2001/05/09 17:51:52 tmm Exp $";
#endif

#if defined(NO_TCP_QUERIES) && M_PRESET!=UDP_ONLY
# error "You may not define NO_TCP_QUERIES when M_PRESET is not set to UDP_ONLY"
#endif
#if defined(NO_UDP_QUERIES) && M_PRESET!=TCP_ONLY
# error "You may not define NO_UDP_QUERIES when M_PRESET is not set to TCP_ONLY"
#endif

/* The method we use for querying other servers */
int query_method=M_PRESET;

/*
 * Take a rr and do The Right Thing: add it to the cache list if the oname matches the owner name of the
 * cent, otherwise add it to the cache under the right name, creating it when necessary.
 * Note aside: Is locking of the added records required? (surely not for data integrity, but maybe for
 * efficiency in not fetching records twice)
 */
static int rr_to_cache(dns_cent_t *cent, time_t ttl, unsigned char *oname, int dlen, void *data , int tp, int flags, time_t queryts, unsigned long serial,
    char trusted, unsigned char *nsdomain)
{
	dns_cent_t ce;
	unsigned char buf[256],cbuf[256];
	int dummy;
	rhn2str(oname,buf);
	if (stricomp((char *)buf,(char *)cent->qname)) {
		/* it is for the record we are editing. add_cent_rr is sufficient. 
		 * however, make sure there are no double records. This is done by
		 * add_cent_rr */
#ifdef RFC2181_ME_HARDER
		if (cent->rr[tp-T_MIN] && cent->rr[tp-T_MIN]->ttl!=(ttl>global.max_ttl?global.max_ttl:ttl))
			return 0;
#endif
		return add_cent_rr(cent,ttl,queryts,flags,dlen,data,tp,1);
	} else {
		if (!trusted)
			domain_match(&dummy, nsdomain, oname, cbuf);
		if (trusted ||  cbuf[0]=='\0') {
			/* try to find a matching record in cache */
			if (have_cached(buf)) {
				return add_cache_rr_add(buf,ttl,queryts,flags,dlen,data,tp,serial);
			} else {
				if (init_cent(&ce, buf, 0, queryts, 0, 1)) {
					if (add_cent_rr(&ce, ttl, queryts, flags, dlen, data, tp, 1)) {
						add_cache(ce);
						free_cent(ce, 1);
						return 1;
					}
				}
				return 0;
			}
		} else {
#if DEBUG>0
			rhn2str(nsdomain,cbuf);
			DEBUG_MSG3("Record for %s not in nsdomain %s; dropped.\n",buf,cbuf);
#endif
			return 1; /* don't add, but don't complain either */
		}
	}
	return 0;
}

typedef struct {
	unsigned char name[256];
	unsigned char nsdomain[256];
} nsr_t;

/*
 * Takes a pointer (ptr) to a buffer with recnum rrs,decodes them and enters them
 * into a dns_cent_t. *ptr is modified to point after the last rr, and *lcnt is decremented
 * by the size of the rrs.
 * The domain names of all name servers found are placed in *ns, which is automatically grown
 * It may be null initially and must be freed when you are done with it.
 */
static int rrs2cent(dns_cent_t **cent, unsigned char **ptr, long *lcnt, int recnum, unsigned char *msg, long msgsz, int flags, darray *ns,time_t queryts,
    unsigned long serial, char trusted, unsigned char *nsdomain, char tc)
{
	unsigned char oname[256];
	unsigned char db[530],tbuf[256];
	rr_hdr_t rhdr;
	int rc;
	int i;
#ifdef DNS_NEW_RRS
	int j,k;
#endif
	int len;
	int slen;
	unsigned char *bptr,*nptr;
	long blcnt;
	nsr_t *nsr;

	for (i=0;i<recnum;i++) {
		if ((rc=decompress_name(msg, oname, ptr, lcnt, msgsz, &len))!=RC_OK) {
			if (rc==RC_TRUNC && tc)
				return RC_OK;
			return rc==RC_TRUNC?RC_FORMAT:rc;
		}
		if (*lcnt<sizeof(rr_hdr_t)) {
			if (tc)
				return RC_OK;
			return RC_FORMAT;
		}
		*lcnt-=sizeof(rhdr);
		memcpy(&rhdr,*ptr,sizeof(rhdr));
		*ptr+=sizeof(rhdr);
		if (*lcnt<ntohs(rhdr.rdlength)) {
			if (tc)
				return RC_OK;
			return RC_FORMAT;
		}
		if (!(ntohs(rhdr.type)<T_MIN || ntohs(rhdr.type)>T_MAX || ntohs(rhdr.class)!=C_IN)) {
			/* skip otherwise */
			/* Some types contain names that may be compressed, so these need to be processed.
			 * the other records are taken as they are
			 * The maximum lenth for a decompression buffer is 530 bytes (maximum SOA record length) */
			switch (ntohs(rhdr.type)) {
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
				if ((rc=decompress_name(msg, db, &bptr, &blcnt, msgsz, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				if (*lcnt-blcnt!=ntohs(rhdr.rdlength))
					return RC_FORMAT;
				if (ntohs(rhdr.rdlength)>530)
					return RC_FORMAT;
				if (!rr_to_cache(*cent, ntohl(rhdr.ttl), oname, len, db, ntohs(rhdr.type),flags,queryts,serial,trusted,
						 nsdomain))
					return RC_SERVFAIL;
				if (ntohs(rhdr.type)==T_NS) {
					/* Don't accept possibliy poisoning nameserver entries in paranoid mode */
					if (!trusted)
						domain_match(&rc, nsdomain, oname, tbuf);
					if (trusted ||  tbuf[0]=='\0') {
						/* add to the nameserver list. */
						if (!*ns) {
							if (!(*ns=DA_CREATE(nsr_t)))
								return RC_SERVFAIL;
						}
						if (!(*ns=da_grow(*ns,1)))
							return RC_SERVFAIL;
						nsr=DA_LAST(*ns,nsr_t);
						rhn2str(db,nsr->name);
						rhncpy(nsr->nsdomain,oname);
					}
				} 
				break;
			case T_MINFO:
#ifdef DNS_NEW_RRS
			case T_RP:
#endif
				blcnt=*lcnt;
				bptr=*ptr;
				nptr=db;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				nptr+=len;
				slen=len;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				/*nptr+=len;*/
				slen+=len;
				if (*lcnt-blcnt!=ntohs(rhdr.rdlength))
					return RC_FORMAT;
				if (ntohs(rhdr.rdlength)>530)
					return RC_FORMAT;
				if (!rr_to_cache(*cent, ntohl(rhdr.ttl), oname, slen, db, ntohs(rhdr.type),flags,queryts,serial, trusted,
						 nsdomain))
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
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				/*nptr+=len;*/
				slen+=len;
				if (*lcnt-blcnt!=ntohs(rhdr.rdlength))
					return RC_FORMAT;
				if (ntohs(rhdr.rdlength)>530)
					return RC_FORMAT;
				if (!rr_to_cache(*cent, ntohl(rhdr.ttl), oname, slen, db, ntohs(rhdr.type),flags,queryts,serial, trusted,
						 nsdomain))
					return RC_SERVFAIL;
				break;
			case T_SOA:
				blcnt=*lcnt;
				bptr=*ptr;
				nptr=db;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				nptr+=len;
				slen=len;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				nptr+=len;
				slen+=len;
				if (blcnt<20)
					return RC_FORMAT;
				blcnt-=20;
				memcpy(nptr,bptr,20); /*copy the rest of the SOA record*/
				slen+=20;
				if (*lcnt-blcnt!=ntohs(rhdr.rdlength))
					return RC_FORMAT;
				if (ntohs(rhdr.rdlength)>530)
					return RC_FORMAT;
				if (!rr_to_cache(*cent, ntohl(rhdr.ttl), oname, slen, db, ntohs(rhdr.type),flags,queryts,serial, trusted,
						 nsdomain))
					return RC_SERVFAIL;
				/* Some nameservers obviously choose to send SOA records instead of NS ones.
				 * altough I think that this is poor behaviour, we'll have to work around that. */
				/* Don't accept possibliy poisoning nameserver entries in paranoid mode */
				if (!trusted) 
					domain_match(&rc,nsdomain, oname, tbuf);
				if (trusted ||  tbuf[0]=='\0') {
					/* add to the nameserver list. */
					if (!*ns) {
						if (!(*ns=DA_CREATE(nsr_t)))
							return RC_SERVFAIL;
					}
					if (!(*ns=da_grow(*ns,1)))
						return RC_SERVFAIL;
					nsr=DA_LAST(*ns,nsr_t);
					/* rhn2str will only convert the first name, which is the NS */
					rhn2str(db,nsr->name);
					rhncpy(nsr->nsdomain,oname);
				}
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
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				nptr+=len;
				slen+=len;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				nptr+=len;
				slen+=len;
				if (*lcnt-blcnt!=ntohs(rhdr.rdlength))
					return RC_FORMAT;
				if (ntohs(rhdr.rdlength)>530)
					return RC_FORMAT;
				if (!rr_to_cache(*cent, ntohl(rhdr.ttl), oname, slen, db, ntohs(rhdr.type),flags,queryts,serial,trusted,
						 nsdomain))
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
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				/*nptr+=len;*/
				slen+=len;
				if (*lcnt-blcnt!=ntohs(rhdr.rdlength))
					return RC_FORMAT;
				if (ntohs(rhdr.rdlength)>530)
					return RC_FORMAT;
				if (!rr_to_cache(*cent, ntohl(rhdr.ttl), oname, slen, db, ntohs(rhdr.type),flags,queryts,serial,trusted,
						 nsdomain))
					return RC_SERVFAIL;
				break;
			case T_NXT:
				blcnt=*lcnt;
				bptr=*ptr;
				nptr=db;
				slen=0;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				nptr+=len;
				/* XXX: This test can go away */
				if (blcnt<ntohs(rhdr.rdlength)-blcnt+*lcnt)
					return RC_FORMAT;
				if (ntohs(rhdr.rdlength)-blcnt+*lcnt<0)
					return RC_FORMAT;
				len=ntohs(rhdr.rdlength)-blcnt+*lcnt;
				memcpy(nptr,bptr,len);
				slen+=len;
				blcnt-=len;
				/* XXX: This test can go away */
				if (*lcnt-blcnt!=ntohs(rhdr.rdlength))
					return RC_FORMAT;
				if (ntohs(rhdr.rdlength)>530)
					return RC_FORMAT;
				if (!rr_to_cache(*cent, ntohl(rhdr.ttl), oname, slen, db, ntohs(rhdr.type),flags,queryts,serial,trusted,
						 nsdomain))
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
					if (blcnt<=0)
						return RC_FORMAT;
					k=*bptr;
					blcnt--;
					slen++;
					*nptr=k;
					nptr++;
					bptr++;
					for (;k>0;k--) {
						if (blcnt==0)
							return RC_FORMAT;
						*nptr=*bptr;
						blcnt--;
						nptr++;
						bptr++;
						slen++;
					}
				}
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				/*nptr+=len;*/
				slen+=len;
				if (*lcnt-blcnt!=ntohs(rhdr.rdlength))
					return RC_FORMAT;
				if (ntohs(rhdr.rdlength)>530)
					return RC_FORMAT;
				if (!rr_to_cache(*cent, ntohl(rhdr.ttl), oname, slen, db, ntohs(rhdr.type),flags,queryts,serial,trusted,
						 nsdomain))
					return RC_SERVFAIL;
				break;
#endif
			default:
				/* Validate types we use internally */
				if (ntohs(rhdr.type)==T_A && ntohs(rhdr.rdlength)!=4)
					return RC_FORMAT;
#ifdef DNS_NEW_RRS
				if (ntohs(rhdr.type)==T_AAAA && ntohs(rhdr.rdlength)!=16)
					return RC_FORMAT;
#endif
				if (!rr_to_cache(*cent, ntohl(rhdr.ttl), oname, ntohs(rhdr.rdlength), *ptr, ntohs(rhdr.type),flags,
						 queryts,serial,trusted, nsdomain))
					return RC_SERVFAIL;
			}
		}
		*lcnt-=ntohs(rhdr.rdlength);
		*ptr+=ntohs(rhdr.rdlength);
	}
	return RC_OK;
}

/* ------ following is the parallel query code.
 * It has been observed that a whole lot of name servers are just damn lame, with response time
 * of about 1 min. If that slow one is by chance the first server we try, serializing that tries is quite
 * sub-optimal. Also when doing serial queries, the timeout values given in the config will add up, which
 * is not the Right Thing. Now that serial queries are in place, this is still true for CNAME recursion,
 * and for recursion in quest for the holy AA, but not totally for querying multiple servers.
 * The impact on network bandwith should be only marginal (given todays bandwith).
 *
 * The actual strategy is to do (max) PAR_QUERIES parallel queries, and, if these time out or fail, do again
 * that number of queries, until we are successful or there are no more servers to query.
 * Since the memory footprint of a thread is considerably large on some systems, and because we have better
 * control, we will do the parallel queries multiplexed in one thread.
 */

/* The query state machine that is called from p_exec_query. This is called once for initialization (state
 * QSN_TCPINITIAL or QSN_UDPINITIAL is preset), and the state that it gives back may either be nstate QSN_DONE, 
 * in which case it must return a return code other than -1 and is called no more for this server 
 * (except perhaps in UDP mode if TCP failed; QSN_DONE makes QS_DONE be set in state), or the st->event 
 * structure must be setup correctly, because it is then used to setup a poll() or select() together with st.>sock. 
 * If that poll/select is succesful for that socket, p_exec_query is called again and will hand over to p_query_sm. 
 * So, you can assume that read(), write() and recvfrom() will not block at sthe start of a state handling when you 
 * have set st->event and returned -1 (which means "call again") as last step of the last state handling. */
static int p_query_sm(query_stat_t *st) 
{
	struct protoent *pe;
	int rv;
#if DEBUG>0
	char buf[ADDRSTR_MAXLEN];
#endif

	switch (st->nstate){
		/* TCP query code */
#ifndef NO_TCP_QUERIES
	case QSN_TCPINITIAL:
		if (!(pe=getprotobyname("tcp"))) {
			DEBUG_MSG2("getprotobyname failed: %s\n", strerror(errno));
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
# ifdef ENABLE_IPV4
		if (run_ipv4) {
			if ((st->sock=socket(PF_INET,SOCK_STREAM,pe->p_proto))==-1) {
				DEBUG_MSG2("Could not open socket: %s\n", strerror(errno));
				st->nstate=QSN_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
			/* sin4 is intialized, hopefully. */
		}
# endif
# ifdef ENABLE_IPV6
		if (run_ipv6) {
			if ((st->sock=socket(PF_INET6,SOCK_STREAM,pe->p_proto))==-1) {
				DEBUG_MSG2("Could not open socket: %s\n", strerror(errno));
				st->nstate=QSN_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
			/* sin6 is intialized, hopefully. */
		}
# endif
		/* transmit query by tcp*/
		/* make the socket non-blocking for connect only, so that connect will not
		 * hang */
		fcntl(st->sock,F_SETFL,O_NONBLOCK);
		if ((rv=connect(st->sock,st->sin,st->sinl))!=0)
		{
			if (errno==EINPROGRESS || errno==EPIPE) {
				st->nstate=QSN_TCPCONNECT;
				st->event=QEV_WRITE; /* wait for writablility; the connect is then done */
				return -1;
			} else if (errno==ECONNREFUSED) {
				close(st->sock);
				st->nstate=QSN_DONE;
				return RC_TCPREFUSED;
			} else {
				/* Since immediate connect() errors does not cost any time, we do not try to switch the
				 * server status to offline */
				close(st->sock);
				DEBUG_MSG3("Error while connecting to %s: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),strerror(errno));
				st->nstate=QSN_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
		} else
			st->nstate=QSN_TCPCONNECT;
		/* fall through in case of not EINPROGRESS */
	case QSN_TCPCONNECT:
		fcntl(st->sock,F_SETFL,0); /* reset O_NONBLOCK */
		/* Since we selected/polled, writeability should be no problem. If connect worked instantly,
		 * the buffer is empty and there is also no problem. */
		if (write(st->sock,&st->transl,sizeof(st->transl))==-1) {
			if (errno==ECONNREFUSED || errno==EPIPE) {
				/* This error may be delayed from connect() */
				close(st->sock);
				st->nstate=QSN_DONE;
				return RC_TCPREFUSED;
			} else {
				close(st->sock);
				DEBUG_MSG3("Error while sending data to %s: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),strerror(errno));
				st->nstate=QSN_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
		}
		st->nstate=QSN_TCPLWRITTEN;
		st->event=QEV_WRITE;
		return -1;
	case QSN_TCPLWRITTEN:
		if (write(st->sock,st->hdr,ntohs(st->transl))==-1) {
			close(st->sock);
			DEBUG_MSG3("Error while sending data to %s: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),strerror(errno));
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
		st->nstate=QSN_TCPQWRITTEN;
		st->event=QEV_READ;
		return -1;
	case QSN_TCPQWRITTEN:
		if (read(st->sock,&st->recvl,sizeof(st->recvl))!=sizeof(st->recvl)) {
			close(st->sock);
			DEBUG_MSG3("Error while receiving data from %s: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),strerror(errno));
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
		st->recvl=ntohs(st->recvl);
		if (!(st->recvbuf=(dns_hdr_t *)pdnsd_calloc(st->recvl,1))) {
			close(st->sock);
			DEBUG_MSG1("Out of memory in query.\n");
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
		st->nstate=QSN_TCPLREAD;
		st->event=QEV_READ;
		return -1;
	case QSN_TCPLREAD:
		if (read(st->sock,st->recvbuf,st->recvl)!=st->recvl) {
			close(st->sock);
			DEBUG_MSG3("Error while receiving data from %s: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),strerror(errno));
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
		st->nstate=QSN_DONE;
		close(st->sock);
		return RC_OK;
#endif		

#ifndef NO_UDP_QUERIES
		/* UDP query code */
	case QSN_UDPINITIAL:
		if (!(pe=getprotobyname("udp"))) {
			DEBUG_MSG2("getprotobyname failed: %s\n", strerror(errno));
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
# ifdef ENABLE_IPV4
		if (run_ipv4) {
			if ((st->sock=socket(PF_INET,SOCK_DGRAM,pe->p_proto))==-1) {
				DEBUG_MSG2("Could not open socket: %s\n", strerror(errno));
				st->nstate=QSN_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
		}
# endif
# ifdef ENABLE_IPV6
		if (run_ipv6) {
			if ((st->sock=socket(PF_INET6,SOCK_DGRAM,pe->p_proto))==-1) {
				DEBUG_MSG2("Could not open socket: %s\n", strerror(errno));
				st->nstate=QSN_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
		}
# endif
		/* connect */
		if (connect(st->sock,st->sin,st->sinl)==-1) {
			close(st->sock);
			DEBUG_MSG3("Error while connecting to %s: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),strerror(errno));
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
		
		/* transmit query by udp*/
		/* send will hopefully not block on a freshly opened socket (the buffer
		 * must be empty) */
		if (send(st->sock,st->hdr,ntohs(st->transl),0)==-1) {
			close(st->sock);
			DEBUG_MSG3("Error while sending data to %s: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),strerror(errno));
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
		if (!(st->recvbuf=(dns_hdr_t *)pdnsd_calloc(512,1))) {
			close(st->sock);
			DEBUG_MSG1("Out of memory in query.\n");
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
		st->nstate=QSN_UDPRECEIVE;
		st->event=QEV_READ;
		return -1;
	case QSN_UDPRECEIVE:
		if ((rv=recv(st->sock,st->recvbuf,512,0))<0) {
			close(st->sock);
			DEBUG_MSG3("Error while receiving data from %s: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),strerror(errno));
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
		st->recvl=rv;
		if (st->recvl<sizeof(dns_hdr_t) || ntohs(st->recvbuf->id)!=st->myrid) {
			DEBUG_MSG1("Bad answer received. Ignoring it.\n");
			/* no need to care about timeouts here. That is done at an upper layer. */
			st->nstate=QSN_UDPRECEIVE;
			st->event=QEV_READ;
			return -1;
		}
		st->nstate=QSN_DONE;
		close(st->sock);
		return RC_OK;
#endif
	case QSN_DONE:
		return -1;
	}
	return -1;
}

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
 * This function calls another query state machine function that supports TCP and UDP.
 *
 * If you want to tell me that this function has a truly ugly coding style, ah, well...
 * You are right, somehow, but I feel it is conceptually elegant ;-)
 */
static int p_exec_query(dns_cent_t **ent, unsigned char *rrn, unsigned char *name, int *aa, query_stat_t *st, darray *ns, unsigned long serial) 
{
	int i,j,rv;
	time_t queryts;
	long lcnt;
	time_t ttl;
	unsigned char *rrp;
#ifdef notdef
	unsigned char *soa;
#endif
	unsigned char nbuf[256];
#if DEBUG>0
	char buf[ADDRSTR_MAXLEN];
#endif
	std_query_t temp_q;
#ifdef notdef
	soa_r_t soa_r;
#endif

	switch (st->state){
	case QS_INITIAL:
		st->sin=(struct sockaddr *)(((char *)st)+st->s_offs);
		if (!st->lean_query)
			st->qt=QT_ALL;
		st->transl=htons(sizeof(dns_hdr_t)+rhnlen(rrn)+4);
		st->hdr=(dns_hdr_t *)pdnsd_calloc(st->transl,1);
		if (!st->hdr) {
			st->state=QS_DONE;
 			return RC_SERVFAIL; /* mock error code */
		}
		st->myrid=get_rand16();
		st->hdr->id=htons(st->myrid);
		st->hdr->qr=QR_QUERY;
		st->hdr->opcode=OP_QUERY;
		st->hdr->aa=0;
		st->hdr->tc=0;
		st->hdr->rd=1;
		st->hdr->ra=0;
		st->hdr->z1=0;
		st->hdr->au=0;
		st->hdr->z2=0;
		st->hdr->rcode=RC_OK;
		st->hdr->qdcount=htons(1);
		st->hdr->ancount=0;
		st->hdr->nscount=0;
		st->hdr->arcount=0;
		rhncpy((unsigned char *)(st->hdr+1),rrn);
		temp_q.qtype=htons(st->qt);
		temp_q.qclass=htons(C_IN);
		memcpy(((unsigned char *)(st->hdr+1))+rhnlen(rrn),&temp_q,4);
		if (!st->trusted)
			st->hdr->rd=0;
		st->recvbuf=NULL;
		if (st->qm==UDP_ONLY)
			st->nstate=QSN_UDPINITIAL;
		else
			st->nstate=QSN_TCPINITIAL;
		st->state=QS_QUERY;
		/* fall through */
		
	case QS_QUERY:
		if ((rv=p_query_sm(st))==RC_TCPREFUSED) {
			pdnsd_free(st->recvbuf);
			if (st->qm==TCP_UDP) {
				st->recvbuf=NULL;
				st->nstate=QSN_UDPINITIAL;
				st->myrid=get_rand16();
				st->hdr->id=htons(st->myrid);
				DEBUG_MSG2("TCP connection refused by %s. Trying to use UDP.\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN));
				return -1;
			}
			pdnsd_free(st->hdr);
			st->state=QS_DONE;
			DEBUG_MSG2("TCP connection refused by %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN));
			return RC_SERVFAIL;
		} else if (rv==-1) {
			return -1;
		} else if (rv!=RC_OK) {
			pdnsd_free(st->hdr);
			pdnsd_free(st->recvbuf);
			st->state=QS_DONE;
			return rv;
		}


		/* Basic sanity checks */
		if (st->recvl<sizeof(dns_hdr_t) || 
		    ntohs(st->recvbuf->id)!=st->myrid || 
		    st->recvbuf->qr!=QR_RESP || 
		    st->recvbuf->opcode!=OP_QUERY ||
		    st->recvbuf->z1 || st->recvbuf->z2 ||
		    (st->recvbuf->rcode!=RC_OK && st->recvbuf->rcode!=RC_NAMEERR && 
		     !(st->hdr->rd && st->recvbuf->rcode==RC_NOTSUPP))) {
			pdnsd_free(st->hdr);
			rv=st->recvbuf->rcode;
			pdnsd_free(st->recvbuf);
			/*close(st->sock);*/
			st->state=QS_DONE;
			if (rv!=RC_OK) {
				DEBUG_MSG3("Server %s returned error code: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),get_ename(rv));
				return rv;
			}
			DEBUG_MSG2("Server %s returned invalid answer\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN));
			return RC_SERVFAIL; /* mock error code */
		}

		if (st->recvbuf->rcode==RC_NOTSUPP){
			/* seems as if we have got no recursion avaliable. We will have to do it by ourselves (sigh...) */
			pdnsd_free(st->recvbuf);
			st->recvbuf=NULL;
			if (st->hdr) {
				st->hdr->rd=0;
				st->myrid=get_rand16();
				st->hdr->id=htons(st->myrid);
				DEBUG_MSG2("Server %s does not support recursive query. Querying nonrecursive.\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN));
				return -1;
			} else {
				pdnsd_free(st->hdr);
				st->state=QS_DONE;
				return RC_SERVFAIL;
			}
		}

		st->state=QS_DONE;
		/* break on success, and if no requery is needed */
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
	pdnsd_free(st->hdr);
	queryts=time(NULL);
	lcnt=st->recvl;
	rrp=(unsigned char *)(st->recvbuf+1);

	lcnt-=sizeof(dns_hdr_t);
	if (ntohs(st->recvbuf->qdcount)!=1) {
		pdnsd_free(st->recvbuf);
		DEBUG_MSG1("Bad number of query records in answer.\n");
		return RC_SERVFAIL;
	}
	/* check & skip the query record. */
	if ((rv=decompress_name((unsigned char *)st->recvbuf, nbuf, &rrp, &lcnt, st->recvl, &i))!=RC_OK)
		return rv==RC_TRUNC?RC_FORMAT:rv;

	i=0;
	while(1) {
		j=nbuf[i];
		if (nbuf[i]!=rrn[i]) {
			pdnsd_free(st->recvbuf);
			DEBUG_MSG1("Answer does not match query.\n");
			return RC_SERVFAIL;
		}
		if (!j) 
			break;
		i++;
		for (;j>0;j--) {
			if (tolower(nbuf[i])!=tolower(rrn[i])) {
				pdnsd_free(st->recvbuf);
				DEBUG_MSG1("Answer does not match query.\n");
				return RC_SERVFAIL;
			}
			i++;
		}		
	}
	
	if (lcnt<4) {
		pdnsd_free(st->recvbuf);
		return RC_SERVFAIL; /* mock error code */
	}
	rrp+=4; /* two shorts (qtype and qclass);*/
	lcnt-=4;
	/* second: evaluate the results (by putting them in a dns_cent_t */
	*ent=(dns_cent_t *)pdnsd_calloc(sizeof(dns_cent_t),1);
	if (!*ent) {
		pdnsd_free(st->recvbuf);
		return RC_SERVFAIL; /* mock error code */
	}

	/* negative cacheing for domains */
	if (st->recvbuf->rcode==RC_NAMEERR) {
		DEBUG_MSG3("Server %s returned error code: %s\n", socka2str(st->sin,buf,ADDRSTR_MAXLEN),get_ename(st->recvbuf->rcode));
		/* We did not get what we wanted. Cache according to policy */
		if (global.neg_domain_pol==C_ON || (global.neg_domain_pol==C_AUTH && st->recvbuf->aa)) {
			DEBUG_MSG2("Cacheing domain %s negative\n",name);
			if (!init_cent(*ent,name, DF_NEGATIVE, queryts, global.neg_ttl, 1)) {
				pdnsd_free(*ent);
				return RC_SERVFAIL; /* mock error code */
			}
			pdnsd_free(st->recvbuf);
			return RC_OK;
		} else {
			pdnsd_free(*ent);
			pdnsd_free(st->recvbuf);
			return RC_NAMEERR;
		}
	}

	if (!init_cent(*ent,name, 0, queryts, 0, 1)) {
		pdnsd_free(*ent);
		pdnsd_free(st->recvbuf);
		return RC_SERVFAIL; /* mock error code */
	}

	/* By marking aa, we mean authoritative AND complete. */
	if (st->qt==QT_ALL)
		*aa=st->recvbuf->aa;
	else
		*aa=0;
	if (!*aa)
		st->flags|=CF_NOAUTH;
	if (rrs2cent(ent,&rrp,&lcnt,ntohs(st->recvbuf->ancount), (unsigned char *)st->recvbuf,st->recvl,st->flags,
		     ns,queryts,serial, st->trusted, st->nsdomain, st->recvbuf->tc)!=RC_OK) {
		free_cent(**ent, 1);
		pdnsd_free(*ent);
		pdnsd_free(st->recvbuf);
		return RC_SERVFAIL;
	}

	if (ntohs(st->recvbuf->nscount)>0) {
		if (rrs2cent(ent,&rrp,&lcnt,ntohs(st->recvbuf->nscount), (unsigned char *)st->recvbuf,st->recvl,
			     st->flags|CF_ADDITIONAL,ns,queryts,serial, st->trusted, st->nsdomain, st->recvbuf->tc)!=RC_OK) {
			pdnsd_free(st->recvbuf);
			free_cent(**ent, 1);
			pdnsd_free(*ent);
			return RC_SERVFAIL;
		}
	}
	
	if (ntohs(st->recvbuf->arcount)>0) {
		if (rrs2cent(ent,&rrp,&lcnt,ntohs(st->recvbuf->arcount), (unsigned char *)st->recvbuf,st->recvl,
			     st->flags|CF_ADDITIONAL,ns,queryts,serial, st->trusted, st->nsdomain, st->recvbuf->tc)!=RC_OK) {
			pdnsd_free(st->recvbuf);
			free_cent(**ent, 1);
			pdnsd_free(*ent);
			return RC_SERVFAIL;
		}
	}

	/* Negative cacheing of rr sets */
	if (st->qt>=T_MIN && st->qt<=T_MAX && !(*ent)->rr[st->qt-T_MIN]) {
		/* We did not get what we wanted. Cache accoding to policy */
		if (global.neg_rrs_pol==C_ON || (global.neg_rrs_pol==C_AUTH && st->recvbuf->aa)) {
			ttl=global.neg_ttl;
			/* If we received a SOA, we should take the ttl of that record. */
			if ((*ent)->rr[T_SOA-T_MIN] && (*ent)->rr[T_SOA-T_MIN]->rrs) {
#ifdef notdef
				soa=(char *)((*ent)->rr[T_SOA-T_MIN]->rrs+1);
				/* Skip owner and maintainer. Lengths are validated in cache */
				while (*soa)
					soa+=*soa+1;
				soa++;
				while (*soa)
					soa+=*soa+1;
				soa++;
				memcpy(soa_r,soa,sizeof(soa_r));
				ttl=soa_r.expire;
#endif
				ttl=(*ent)->rr[T_SOA-T_MIN]->ttl+(*ent)->rr[T_SOA-T_MIN]->ts-time(NULL);
				ttl=ttl<0?0:ttl;
			}
			ttl=ttl<global.min_ttl?global.min_ttl:(ttl>global.max_ttl?global.max_ttl:ttl);
			DEBUG_MSG4("Cacheing type %s for domain %s negative with ttl %li\n",get_tname(st->qt),name,ttl);
			if (!add_cent_rrset(*ent, st->qt, global.neg_ttl, queryts, CF_NEGATIVE|st->flags, serial, 1)) {
			    free_cent(**ent, 1);
			    pdnsd_free(*ent);
			    pdnsd_free(st->recvbuf);
			    return RC_SERVFAIL;
			}
		}
	}

	pdnsd_free(st->recvbuf);
	return RC_OK;
}

/*
 * Cancel a query, freeing all resources. Any query state is valid as input (this may even be called
 * if a call to p_exec_query already returned error or success) 
 */
static void p_cancel_query(query_stat_t *st) 
{
	if (st->state==QS_QUERY){
		pdnsd_free(st->recvbuf);
		pdnsd_free(st->hdr);
		if (st->nstate!=QSN_TCPINITIAL && st->nstate!=QSN_UDPINITIAL && st->nstate!=QSN_DONE) {
			close(st->sock);
		}
	}
	st->state=QS_DONE;
}

/*
 * Initialize a query_serv_t (server list for parallel query)
 * This is there for historical reasons only.
 */
static void init_qserv(darray *q)
{
	*q=NULL;
}

/*
 * Add a server entry to a query_serv_t
 */
static int add_qserv(darray *q, pdnsd_a *a, int port, time_t timeout, int si, int flags, int nocache, int thint, char lean_query, char trusted,
    unsigned char *nsdomain)
{
	query_stat_t *qs;
	
	if (*q==NULL) {
		if ((*q=DA_CREATE(query_stat_t))==NULL)
			return 0;
	}
	if ((*q=da_grow(*q,1))==NULL)
		return 0;
	
	qs=DA_LAST(*q,query_stat_t);
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		memset(&qs->a.sin4,0,sizeof(qs->a.sin4));
		qs->a.sin4.sin_family=AF_INET;
		qs->a.sin4.sin_port=htons(port);
		qs->a.sin4.sin_addr=a->ipv4;
		SET_SOCKA_LEN4(qs->a.sin4);
		qs->s_offs=((char *)&qs->a.sin4)-((char *)qs);
		qs->sinl=sizeof(struct sockaddr_in);
	}
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6) {
		memset(&qs->a.sin6,0,sizeof(qs->a.sin6));
		qs->a.sin6.sin6_family=AF_INET6;
		qs->a.sin6.sin6_port=htons(port);
		qs->a.sin6.sin6_flowinfo=IPV6_FLOWINFO;
		qs->a.sin6.sin6_addr=a->ipv6;
		SET_SOCKA_LEN6(qs->a.sin6);
		qs->s_offs=((char *)&qs->a.sin6)-((char *)qs);
		qs->sinl=sizeof(struct sockaddr_in6);
	}
#endif
	qs->sin=NULL;
	qs->timeout=timeout;
	qs->si=si;
	qs->flags=flags;
	qs->nocache=nocache;
	qs->qt=thint;
	qs->lean_query=lean_query;
	qs->trusted=trusted;
	rhncpy(qs->nsdomain,nsdomain);
	qs->state=QS_INITIAL;
	qs->qm=query_method;
	return 1;
}

/*
 * Free resources used by a query_serv_t
 * There for historical reasons only.
 */
static void del_qserv(darray q)
{
	da_free(q);
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
static int p_recursive_query(darray q, unsigned char *rrn, unsigned char *name, dns_cent_t **ent, int *nocache, int hops, int thint)
{
	int aa_needed;
	pdnsd_a serva;
	int aa=0;
	int i,j,k,ad,mc,qo,done,nons,pc,srv,sv;
	int rv=0;
	dns_cent_t *nent,*servent;
	darray serv;
	query_stat_t *qs, *qse;
	unsigned char nsbuf[256],nsname[256];
	unsigned long serial=get_serial();
	darray ns=NULL;
	time_t ts;
	long maxto;
#ifdef ENABLE_IPV6
	struct in_addr ina;
#endif
#ifdef DEBUG
	char buf[ADDRSTR_MAXLEN];
#endif
#ifdef NO_POLL
	fd_set              reads;
	fd_set              writes;
	struct timeval      tv;
	int                 maxfd;
#else
	struct pollfd       *polls;
#endif

	qo=done=0;
	ad=da_nel(q)/global.par_queries;
	if (ad*global.par_queries<da_nel(q))
		ad++;
#ifndef NO_POLL
	if (!(polls=pdnsd_calloc(global.par_queries,sizeof(*polls)))) {
		log_warn("Out of memory in p_recursive_query!");
		return RC_SERVFAIL;
	}
#endif
	for (j=0;j<ad;j++) {
		mc=da_nel(q)-j*global.par_queries;
		if (mc>global.par_queries)
			mc=global.par_queries;
		/* First, call p_exec_query once for each parallel set to initialize.
		 * Then, as long as not all have the state QS_DONE or we have a timeout,
		 * build a poll/select set for all active queries and call them accordingly. */
		qo=1;
		for (i=0;i<mc;i++) {
			/* The below should not happen any more, but may once again
			 * (immediate success) */
			qs=DA_INDEX(q,global.par_queries*j+i,query_stat_t);
			rv=p_exec_query(ent, rrn, name, &aa, qs,&ns,serial);
			if (rv==RC_OK || rv==RC_NAMEERR) {
				for (k=0;k<mc;k++) {
					p_cancel_query(DA_INDEX(q,global.par_queries*j+k,query_stat_t));
				}
				if (rv==RC_OK) {
					qse=qs;
					sv=qs->si;
					*nocache=qs->nocache;
					DEBUG_MSG2("Query to %s succeeded.\n",socka2str(qs->sin,buf,ADDRSTR_MAXLEN));
				}
				done=1;
				break;
			}
			if (qs->state!=QS_DONE)
				qo=0;
		}
		if (!done && !qo) {
			/* we do time keeping by hand, because poll/select might be interrupted and
			 * the returned times are not always to be trusted upon */
			ts=time(NULL);
			do {
				/* build poll/select sets, maintain time. 
				 * If you do parallel queries, the highest timeout may be honored
				 * also for the other servers when their timeout is exceeded and
				 * the highest is not. This could be fixed, but this does not
				 * affect functionality or timeouts at all in practice (if we wait
				 * longer anyway, why not for more servers) and is therefore still there.*/
				maxto=0;
				pc=0;
				rv=RC_SERVFAIL;
				
# ifdef NO_POLL
				FD_ZERO(&reads);
				FD_ZERO(&writes);
				for (i=0;i<mc;i++) {
					if (q->qs[global.par_queries*j+i].state!=QS_DONE) {
						if (q->qs[global.par_queries*j+i].timeout>maxto)
							maxto=q->qs[global.par_queries*j+i].timeout;
						if (q->qs[global.par_queries*j+i].sock>maxfd)
							maxfd=q->qs[global.par_queries*j+i].sock;
						switch (q->qs[global.par_queries*j+i].event) {
						case QEV_READ:
							FD_SET(q->qs[global.par_queries*j+i].sock,&reads);
							break;
						case QEV_WRITE:
							FD_SET(q->qs[global.par_queries*j+i].sock,&writes);
							break;
						}
						pc++;
					}
				}
				if (pc==0) {
					/* In this case, ALL are done and we do not need to cancel any
					 * query. */
					qo=1;
					break;
				}
				maxto-=time(NULL)-ts;
				tv.tv_sec=maxto>0?maxto:0;
				tv.tv_usec=0;
				srv=select(maxfd+1,&reads,&writes,NULL,&tv);
# else
				for (i=0;i<mc;i++) {
					qs=DA_INDEX(q,global.par_queries*j+i,query_stat_t);
					if (qs->state!=QS_DONE) {
						if (qs->timeout>maxto)
							maxto=qs->timeout;
						
						polls[pc].fd=qs->sock;
						switch (qs->event) {
						case QEV_READ:
							polls[pc].events=POLLIN;
							break;
						case QEV_WRITE:
							polls[pc].events=POLLOUT;
							break;
						}
						pc++;
					}
				}
				if (pc==0) {
					/* In this case, ALL are done and we do not need to cancel any
					 * query. */
					qo=1;
					break;
				}
				maxto-=time(NULL)-ts;
				srv=poll(polls,pc,maxto>0?(maxto*1000):0);
# endif
				if (srv<0) {
					log_warn("poll/select failed: %s",strerror(errno));
					for (k=0;k<mc;k++)
						p_cancel_query(DA_INDEX(q,global.par_queries*j+k,query_stat_t));
					rv=RC_SERVFAIL;
					done=1;
					break;
				}
				
				qo=1;
				for (i=0;i<mc;i++) {
					qs=DA_INDEX(q,global.par_queries*j+i,query_stat_t);
					/* Check if we got a poll/select event, or whether we are timed out */
					if (qs->state!=QS_DONE) {
						if (time(NULL)-ts>=qs->timeout) {
							/* We have timed out. cancel this, and see whether we need to mark
							 * a server down. */
							p_cancel_query(qs);
							if (qs->si>=0)
								mark_server_down(qs->si);
							/* set rv, we might be the last! */
							rv=RC_SERVFAIL;
						} else {
							srv=0;
							/* This detection may seem subobtimal, but normally, we have at most 2-3 parallel
							 * queries, and anything else would be higher overhead, */
#ifdef NO_POLL
							switch (qs->event) {
							case QEV_READ:
								srv=FD_ISSET(qs->sock,&reads);
								break;
							case QEV_WRITE:
								srv=FD_ISSET(qs->sock,&writes);
								break;
							}
#else
							for (k=0;k<pc;k++) {
								if (polls[k].fd==qs->sock) {
									switch (qs->event) {
									case QEV_READ:
										srv=polls[k].revents&POLLIN;
										break;
									case QEV_WRITE:
										srv=polls[k].revents&POLLOUT;
										break;
									}
									break;
								}
							}
#endif
							if (srv) {
								rv=p_exec_query(ent, rrn, name, &aa, qs,&ns,serial);
								if (rv==RC_OK || rv==RC_NAMEERR) {
									for (k=0;k<mc;k++) {
										p_cancel_query(DA_INDEX(q,global.par_queries*j+k,query_stat_t));
									}
									if (rv==RC_OK) {
										qse=qs;
										sv=qs->si;
										*nocache=qs->nocache;
										DEBUG_MSG2("Query to %s succeeded.\n",
										    socka2str(qs->sin,buf,ADDRSTR_MAXLEN));
									}
									done=1;
									break;
								}
							}
							/* recheck, this might have changed after the last p_exec_query */
							if (qs->state!=QS_DONE) {
								qo=0;
							}
						} 
					}
				}
			} while (!qo && !done);
		}
		if (done)
			break;
	}
#ifndef NO_POLL
	pdnsd_free(polls);
#endif
	if (rv!=RC_OK) {
		DEBUG_MSG2("No query succeeded. Returning error code \"%s\"\n",get_ename(rv));
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
		/* This test will also succeed if we have a negative cached record. This is purposely. */
		if (!(*ent)->rr[thint-T_MIN] && !(*ent)->rr[T_CNAME-T_MIN])
			aa_needed=1;
	}

	if (ns && da_nel(ns)>0 && !aa && aa_needed && (sv==-1 || !DA_INDEX(servers,sv,servparm_t)->is_proxy)) {
		init_qserv(&serv);
		/* Authority records present. Ask them, because the answer was non-authoritative. To do so, we first put 
		 * the Authority and the additional section into a dns_cent_t and look for name servers in the Authority 
		 * section and their addresses in the Answer and additional sections. If none are found, we also need to 
		 * resolve the name servers.*/
		if (hops>=0) {
			for (j=0;j<da_nel(ns);j++) {
				nsr_t *nsr=DA_INDEX(ns,j,nsr_t);
				
				if (global.paranoid) {
					/* paranoia mode: don't query name servers that are not responsible */
					/* rhn2str(nsr->nsdomain,nsname); */
					domain_match(&i,nsr->nsdomain,rrn,nsname);
					if (nsname[0]!='\0')
						continue;
				}
				strcpy((char *)nsname,(char *)nsr->name);
				if (!str2rhn(nsname,nsbuf))
					continue;
				/* look it up in the cache or resolve it if needed. The records received should be in the cache now,
				   so it's ok */
				
#ifdef ENABLE_IPV4
				if (run_ipv4)
					serva.ipv4.s_addr=INADDR_ANY;
#endif
#ifdef ENABLE_IPV6
				if (run_ipv6)
					serva.ipv6=in6addr_any;
#endif

				if (p_dns_cached_resolve(NULL,nsname,nsbuf, &servent, hops-1, T_A,time(NULL))==RC_OK) {
#ifdef ENABLE_IPV4
					if (run_ipv4) {
						if (servent->rr[T_A-T_MIN] && servent->rr[T_A-T_MIN]->rrs)
							memcpy(&serva.ipv4,(unsigned char *)(servent->rr[T_A-T_MIN]->rrs+1),sizeof(serva.ipv4));
					}
#endif
#ifdef ENABLE_IPV6
					if (run_ipv6) {
# ifdef DNS_NEW_RRS
						if (servent->rr[T_AAAA-T_MIN] && servent->rr[T_AAAA-T_MIN]->rrs)
							memcpy(&serva.ipv6,(unsigned char *)(servent->rr[T_AAAA-T_MIN]->rrs+1),sizeof(serva.ipv6));
						else
# endif
							if (servent->rr[T_A-T_MIN] && servent->rr[T_A-T_MIN]->rrs) {
								/* XXX: memcpy for alpha (unaligned access) */
								memcpy(&ina,servent->rr[T_A-T_MIN]->rrs+1,sizeof(ina));
								IPV6_MAPIPV4(&ina,&serva.ipv6);
							}
						
					}
#endif
					free_cent(*servent, 1);
					pdnsd_free(servent);
				}
				
				if (!is_inaddr_any(&serva)) {
					/* We've got an address. Add it to the list if it wasn't one of the servers we queried. */
					nons=1;
					/* The given address may not be ours!!! */
					/* in netdev.c */
					if (is_local_addr(&serva))
						nons=0;
					if (nons) {
						for (i=0;i<da_nel(q);i++) {
							/* q->qs[i].sin is initialized in p_exec_query, and may thus not be
							   initialized */
							qs=DA_INDEX(q,i,query_stat_t);
							if (qs->sin && ADDR_EQUIV(SOCKA_A(qs->sin),&serva)) {
								nons=0;
								break;
							}
						}
					}
					if (nons) {
						/* lean query mode is inherited. CF_NOAUTH and CF_ADDITIONAL are not (as specified
						 * in CFF_NOINHERIT). */
						if (!add_qserv(&serv, &serva, 53, qse->timeout, -1, qse->flags&~CFF_NOINHERIT, 0,thint,
						    qse->lean_query,!global.paranoid,nsr->nsdomain)) {
							free_cent(**ent, 1);
							pdnsd_free(*ent);
							da_free(ns);
							return RC_SERVFAIL;
						}
					}
				}
			}
			if (da_nel(serv)>0) {
				rv=p_dns_cached_resolve(serv,  name, rrn, &nent,hops-1,thint,time(NULL));
				/* return the answer in any case. */
/*				if (rv==RC_OK || rv==RC_NAMEERR) {*/
					del_qserv(serv);
					free_cent(**ent, 1);
					pdnsd_free(*ent);
 					*ent=nent;
					
					da_free(ns);
					return rv;
/*				}*/
			}
		}
		del_qserv(serv);
		/*
		 * If we didn't get rrs from any of the authoritative servers, take the one we had. However, set its ttl to 0,
		 * so that it won't be used again unless it is necessary.
		 */
		for (j=0;j<T_NUM;j++) {
			if ((*ent)->rr[j])
				(*ent)->rr[j]->ttl=0;
		}
	}
	da_free(ns);

	return RC_OK;
}

/* 
 * following the resolvers. Some take a list of servers for parallel query. The others query the servers supplied by the user.
 */
static int p_dns_resolve_from(darray q, unsigned char *name, unsigned char *rrn , dns_cent_t **cached, int hops, int thint)
{
	int dummy;

	return p_recursive_query(q, rrn, name,cached, &dummy, hops, thint);
} 

/*
 * This checks the given name to resolve against the access list given for the server using the
 * include=, exclude= and policy= parameters.
 */
static int use_server(servparm_t *s, unsigned char *name)
{
	int i;
	slist_t *sl;
	
	if (s->alist) {
		for (i=0;i<da_nel(s->alist);i++) {
			sl=DA_INDEX(s->alist,i,slist_t);
			if (sl->domain[0]=='.') {
				/* match this domain and all subdomains */
				if ((strlen((char *)name)==strlen((char *)sl->domain)-1 && 
				     stricomp((char *)name,&sl->domain[1])) ||
				    (strlen((char *)name)>=strlen((char *)sl->domain) && 
				     stricomp((char *)(name+(strlen((char *)name)-strlen((char *)sl->domain))),sl->domain)))
					return sl->rule==C_INCLUDED;
			} else {
				/* match this domain exactly */
				if (stricomp((char *)name,sl->domain))
					return sl->rule==C_INCLUDED;
			}

		}
	}
	return s->policy==C_INCLUDED;
}


static int p_dns_resolve(unsigned char *name, unsigned char *rrn , dns_cent_t **cached, int hops, int thint)
{
	int i,rc,nocache;
	int one_up=0;
	darray serv;
	dns_cent_t *tc;
	servparm_t *sp;
	
	/* try the servers in the order of their definition */
	init_qserv(&serv);
	for (i=0;i<da_nel(servers);i++) {
		sp=DA_INDEX(servers,i,servparm_t);
		if (sp->is_up && use_server(sp,name)) {
			add_qserv(&serv, &sp->a, sp->port, sp->timeout, i, mk_flag_val(sp),sp->nocache,thint,sp->lean_query,1,(unsigned char *)"");
			one_up=1;
		}
	}
	if (!one_up) {
		DEBUG_MSG1("No server is marked up and allowed for this domain.\n");
		del_qserv(serv);
		return RC_SERVFAIL; /* No server up */
	}


	if ((rc=p_recursive_query(serv, rrn, name,cached,&nocache, hops, thint))==RC_OK) {
		if (!nocache) {
			add_cache(**cached);
			if ((tc=lookup_cache(name))) {
				/* The cache may hold more information  than the recent query yielded.
				 * try to get the merged record. If that fails, revert to the new one. */
				free_cent(**cached, 1);
				pdnsd_free(*cached);
				*cached=tc;
			}
		}
		del_qserv(serv);
		return RC_OK;
	}
	del_qserv(serv);
	return rc;          /* Could not find a record on any server */
} 

static int set_flags_ttl(short *flags, time_t *ttl, dns_cent_t *cached, int i)
{
	if (cached->rr[i-T_MIN]) {
		*flags|=cached->rr[i-T_MIN]->flags;
		if (*ttl<cached->rr[i-T_MIN]->ts+cached->rr[i-T_MIN]->ttl)
			*ttl=cached->rr[i-T_MIN]->ts+cached->rr[i-T_MIN]->ttl;
		return 1;
	}
	return 0;
}

/*
 * Resolve records for name/rrn into dns_cent_t, type thint
 * q is the set of servers to query from. Set q to NULL if you want to ask the servers registered with pdnsd.
 */
int p_dns_cached_resolve(darray q, unsigned char *name, unsigned char *rrn , dns_cent_t **cached, int hops, int thint, time_t queryts)
{
	dns_cent_t *bcached;
	int rc;
	int need_req=0;
	int timed=0;
	time_t ttl=0;
	int auth=0;
	int neg=0;
	int i,nopurge=0;
	short flags=0;

	DEBUG_MSG3("Starting cached resolve for: %s, query %s\n",name,get_tname(thint));
	if ((*cached=lookup_cache(name))) {
		DEBUG_MSG1("Record found in cache.\n");
		auth=0;
		nopurge=0;
		if ((*cached)->flags&DF_NEGATIVE) {
			if ((*cached)->ts+(*cached)->ttl+CACHE_LAT>=queryts)
				neg=1;
			else
				need_req=1;
		} else {
			for (i=0;i<T_MAX;i++) {
				if ((*cached)->rr[i]) {
					if (!((*cached)->rr[i]->flags&CF_NOAUTH) && !((*cached)->rr[i]->flags&CF_ADDITIONAL)) {
						auth=1;
					}
					if ((*cached)->rr[i]->flags&CF_NOPURGE) {
						nopurge=1;
				}
					if (auth && nopurge)
						break;
				}
			}
			if (!set_flags_ttl(&flags, &ttl, *cached, T_CNAME)) {
				if (thint==QT_ALL) {
					for (i=0;i<T_NUM;i++)
						set_flags_ttl(&flags, &ttl, *cached, i);
				} else if (thint==QT_MAILA) {
					set_flags_ttl(&flags, &ttl, *cached, T_MD);
					set_flags_ttl(&flags, &ttl, *cached, T_MF);
				} else if (thint==QT_MAILB) {
					set_flags_ttl(&flags, &ttl, *cached, T_MG);
					set_flags_ttl(&flags, &ttl, *cached, T_MB);
					set_flags_ttl(&flags, &ttl, *cached, T_MR);
				} else if (thint>=T_MIN && thint<=T_MAX) {
					if (set_flags_ttl(&flags, &ttl, *cached, thint))
						neg=(*cached)->rr[thint-T_MIN]->flags&CF_NEGATIVE && ttl-queryts+CACHE_LAT>=0;
				}
			}
			if (thint>=QT_MIN && thint<=QT_MAX  && !auth)
				need_req=!(flags&CF_LOCAL);
			else {
				if (ttl-queryts+CACHE_LAT<0)
					timed=1;
			}
		}
		DEBUG_MSG6("Requery decision: req=%i, neg=%i, timed=%i, flags=%i, ttl=%li\n",need_req!=0,
			   neg,timed,flags,ttl-queryts);
	}
	/* update server records set onquery */
	test_onquery();
	if (global.lndown_kluge && !(flags&CF_LOCAL)) {
		rc=1;
		for (i=0;i<da_nel(servers);i++) {
			if (DA_INDEX(servers,i,servparm_t)->is_up)
				rc=0;
		}
		if (rc) {
			DEBUG_MSG1("Link is down.\n");
			return RC_SERVFAIL;
		}
	}
	if (!(*cached) || (!((*cached)->flags&DF_LOCAL) && !neg && (need_req || (timed && !(flags&CF_LOCAL))))) {
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
					free_cent(*bcached, 1);
					pdnsd_free(bcached);
				}
				return rc;
			}
		} else {
			if (bcached) {
				free_cent(*bcached, 1);
				pdnsd_free(bcached);
			}
		}
	} else {
		DEBUG_MSG1("Using cached record.\n");
	}
	if (*cached && (*cached)->flags&DF_NEGATIVE) {
		free_cent(**cached, 1);
		pdnsd_free(*cached);
		return RC_NAMEERR;
	}
	return RC_OK;
}
