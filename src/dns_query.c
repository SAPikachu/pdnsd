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
static char rcsid[]="$Id: dns_query.c,v 1.59 2002/08/07 08:55:33 tmm Exp $";
#endif

#if defined(NO_TCP_QUERIES) && M_PRESET!=UDP_ONLY
# error "You may not define NO_TCP_QUERIES when M_PRESET is not set to UDP_ONLY"
#endif
#if defined(NO_UDP_QUERIES) && M_PRESET!=TCP_ONLY
# error "You may not define NO_UDP_QUERIES when M_PRESET is not set to TCP_ONLY"
#endif

/* The method we use for querying other servers */
int query_method=M_PRESET;

#ifdef ENABLE_IPV4
# ifdef ENABLE_IPV6
#  define SIN_ADDR(p) (run_ipv6?((struct sockaddr *) &(p)->a.sin6):((struct sockaddr *) &(p)->a.sin4))
#  define SIN_LEN (run_ipv6?sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in))
#  define SOCK_PDNSD_A(a) (run_ipv6?((pdnsd_a *) &(a).sin6.sin6_addr):((pdnsd_a *) &(a).sin4.sin_addr))
# else
#  define SIN_ADDR(p) ((struct sockaddr *) &(p)->a.sin4)
#  define SIN_LEN sizeof(struct sockaddr_in)
#  define SOCK_PDNSD_A(a) ((pdnsd_a *) &(a).sin4.sin_addr)
# endif
#else
#  define SIN_ADDR(p) ((struct sockaddr *) &(p)->a.sin6)
#  define SIN_LEN sizeof(struct sockaddr_in6)
#  define SOCK_PDNSD_A(a) ((pdnsd_a *) &(a).sin6.sin6_addr)
#endif

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
	if (stricomp(buf,cent->qname)) {
		/* it is for the record we are editing. add_cent_rr is sufficient. 
		 * however, make sure there are no double records. This is done by
		 * add_cent_rr */
#ifdef RFC2181_ME_HARDER
		if (cent->rr[tp-T_MIN] && cent->rr[tp-T_MIN]->ttl!=(ttl>global.max_ttl?global.max_ttl:(ttl<global.min_ttl?global.min_ttl:ttl)))
			return 0;
#endif
		return add_cent_rr(cent,ttl,queryts,flags,dlen,data,tp  DBG1);
	} else {
		if (!trusted)
			domain_match(&dummy, nsdomain, oname, cbuf);
		if (trusted ||  cbuf[0]=='\0') {
			/* try to find a matching record in cache */
			if (have_cached(buf)) {
				return add_cache_rr_add(buf,ttl,queryts,flags,dlen,data,tp,serial);
			} else {
				if (init_cent(&ce, buf, 0, queryts, 0  DBG1)) {
					if (add_cent_rr(&ce, ttl, queryts, flags, dlen, data, tp  DBG1)) {
						add_cache(&ce);
						free_cent(&ce  DBG1);
						return 1;
					}
				}
				return 0;
			}
		} else {
#if DEBUG>0
			rhn2str(nsdomain,cbuf);
			DEBUG_MSG("Record for %s not in nsdomain %s; dropped.\n",buf,cbuf);
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
typedef DYNAMIC_ARRAY(nsr_t) *nsr_array;

/*
 * Takes a pointer (ptr) to a buffer with recnum rrs,decodes them and enters them
 * into a dns_cent_t. *ptr is modified to point after the last rr, and *lcnt is decremented
 * by the size of the rrs.
 * The domain names of all name servers found are placed in *ns, which is automatically grown
 * It may be null initially and must be freed when you are done with it.
 */
static int rrs2cent(dns_cent_t *cent, unsigned char **ptr, long *lcnt, int recnum, unsigned char *msg, long msgsz, int flags, nsr_array *ns,time_t queryts,
    unsigned long serial, char trusted, unsigned char *nsdomain, char tc)
{
	unsigned char oname[256];
	unsigned char db[1040],tbuf[256];
	rr_hdr_t rhdr;
	int rc;
	int i;
#ifdef DNS_NEW_RRS
	int j,k,tlen;
#endif
	int len, uscore;
	int slen;
	unsigned char *bptr,*nptr;
	long blcnt;
	nsr_t *nsr;

	for (i=0;i<recnum;i++) {
		uint16_t type,rdlength;
		if ((rc=decompress_name(msg, oname, ptr, lcnt, msgsz, &len, &uscore))!=RC_OK) {
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
		rdlength=ntohs(rhdr.rdlength);
		if (*lcnt<rdlength) {
			if (tc)
				return RC_OK;
			return RC_FORMAT;
		}
		type=ntohs(rhdr.type);
		if (!(type<T_MIN || type>T_MAX || ntohs(rhdr.class)!=C_IN)) {
			uint32_t ttl;
			/* skip otherwise */
			/* Some types contain names that may be compressed, so these need to be processed.
			 * the other records are taken as they are
			 * The maximum lenth for a decompression buffer is 530 bytes (maximum SOA record length) */
#ifndef UNDERSCORE
			if (uscore && type!=T_SRV && type!=T_TXT) {
				/* Underscore is only allowed in SRV records */
				return RC_FORMAT;
			}
#endif
			ttl=ntohl(rhdr.ttl);

			switch (type) {
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
				if ((rc=decompress_name(msg, db, &bptr, &blcnt, msgsz, &len, NULL))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				if (*lcnt-blcnt!=rdlength)
					return RC_FORMAT;
				if (!rr_to_cache(cent, ttl, oname, len, db, type,flags,queryts,serial,trusted,
						 nsdomain))
					return RC_SERVFAIL;
				if (type==T_NS) {
					/* Don't accept possibliy poisoning nameserver entries in paranoid mode */
					if (!trusted)
						domain_match(&rc, nsdomain, oname, tbuf);
					if (trusted ||  tbuf[0]=='\0') {
						/* add to the nameserver list. */
						if (!(*ns=DA_GROW1(*ns)))
							return RC_SERVFAIL;
						nsr=&DA_LAST(*ns);
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
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len, NULL))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				PDNSD_ASSERT(len <= sizeof(db) - 256, "T_MINFO/T_RP: buffer limit reached");
				nptr+=len;
				slen=len;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len, NULL))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				/*nptr+=len;*/
				slen+=len;
				if (*lcnt-blcnt!=rdlength)
					return RC_FORMAT;
				if (!rr_to_cache(cent, ttl, oname, slen, db, type,flags,queryts,serial, trusted,
						 nsdomain))
					return RC_SERVFAIL;
				break;
			case T_MX:
#ifdef DNS_NEW_RRS
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
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len, NULL))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				/*nptr+=len;*/
				slen+=len;
				if (*lcnt-blcnt!=rdlength)
					return RC_FORMAT;
				if (!rr_to_cache(cent, ttl, oname, slen, db, type,flags,queryts,serial, trusted,
						 nsdomain))
					return RC_SERVFAIL;
				break;
			case T_SOA:
				blcnt=*lcnt;
				bptr=*ptr;
				nptr=db;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len, NULL))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				PDNSD_ASSERT(len <= sizeof(db) - 256, "T_SOA: buffer limit reached");
				nptr+=len;
				slen=len;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len, NULL))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				nptr+=len;
				slen+=len;
				PDNSD_ASSERT(slen <= sizeof(db) - 20, "T_SOA: buffer limit reached");
				if (blcnt<20)
					return RC_FORMAT;
				blcnt-=20;
				memcpy(nptr,bptr,20); /*copy the rest of the SOA record*/
				slen+=20;
				if (*lcnt-blcnt!=rdlength)
					return RC_FORMAT;
				if (!rr_to_cache(cent, ttl, oname, slen, db, type,flags,queryts,serial, trusted,
						 nsdomain))
					return RC_SERVFAIL;
				/* Some nameservers obviously choose to send SOA records instead of NS ones.
				 * altough I think that this is poor behaviour, we'll have to work around that. */
				/* Don't accept possibility of poisoning nameserver entries in paranoid mode */
				if (!trusted) 
					domain_match(&rc,nsdomain, oname, tbuf);
				if (trusted ||  tbuf[0]=='\0') {
					/* add to the nameserver list. */
					if (!(*ns=DA_GROW1(*ns)))
						return RC_SERVFAIL;
					nsr=&DA_LAST(*ns);
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
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len, NULL))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				PDNSD_ASSERT(len <= sizeof(db) - 256, "T_PX: buffer limit reached");
				nptr+=len;
				slen+=len;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len, NULL))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				nptr+=len;
				slen+=len;
				if (*lcnt-blcnt!=rdlength)
					return RC_FORMAT;
				if (!rr_to_cache(cent, ttl, oname, slen, db, type,flags,queryts,serial,trusted,
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
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len, NULL))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				/*nptr+=len;*/
				slen+=len;
				if (*lcnt-blcnt!=rdlength)
					return RC_FORMAT;
				if (!rr_to_cache(cent, ttl, oname, slen, db, type,flags,queryts,serial,trusted,
						 nsdomain))
					return RC_SERVFAIL;
				break;
			case T_NXT:
				blcnt=*lcnt;
				bptr=*ptr;
				nptr=db;
				slen=0;
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len, NULL))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				tlen = len;
				nptr+=len;
				if (rdlength<blcnt-*lcnt)
					return RC_FORMAT;
				len=rdlength-(blcnt+*lcnt);
				if (tlen + len > sizeof(db) || blcnt < len)
					return RC_FORMAT;
				memcpy(nptr,bptr,len);
				slen+=len;
				blcnt-=len;
				if (*lcnt-blcnt!=rdlength)
					return RC_FORMAT;
				if (!rr_to_cache(cent, ttl, oname, slen, db, type,flags,queryts,serial,trusted,
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
				/*
				 * 3 text strings following, the maximum length* being 255 characters for each (this is
				 * ensured by the type of *bptr), plus one length byte for each, so 3 * 256 = 786 in
				 * total. In addition, the name below is up to 256 character in size, and the preference
				 * field is another 4 bytes in size, so the total length that can be taken up are
				 * are 1028 characters. This means that the whole record will always fit into db.
				 */
				for (j=0;j<3;j++) {
					if (blcnt<=0)
						return RC_FORMAT;
					PDNSD_ASSERT(bptr < db + sizeof(db) - 1, "T_NAPTR: buffer limit reached");
					k=*bptr;
					blcnt--;
					slen++;
					*nptr=k;
					nptr++;
					bptr++;
					PDNSD_ASSERT(k <= 255, "T_NAPTR: length botched");
					for (;k>0;k--) {
						PDNSD_ASSERT(bptr < db + sizeof(db) - 1, "T_NAPTR: buffer limit reached");
						if (blcnt==0)
							return RC_FORMAT;
						*nptr=*bptr;
						blcnt--;
						nptr++;
						bptr++;
						slen++;
					}
				}
				PDNSD_ASSERT(bptr <= db + sizeof(db) - 256, "T_NAPTR: buffer limit reached (name)");
				if ((rc=decompress_name(msg, nptr, &bptr, &blcnt, msgsz, &len, NULL))!=RC_OK)
					return rc==RC_TRUNC?RC_FORMAT:rc;
				/*nptr+=len;*/
				slen+=len;
				if (*lcnt-blcnt!=rdlength)
					return RC_FORMAT;
				if (!rr_to_cache(cent, ttl, oname, slen, db, type,flags,queryts,serial,trusted,
						 nsdomain))
					return RC_SERVFAIL;
				break;
#endif
			default:
				/* Validate types we use internally */
				if (type==T_A && rdlength!=4)
					return RC_FORMAT;
#ifdef DNS_NEW_RRS
				if (type==T_AAAA && rdlength!=16)
					return RC_FORMAT;
#endif
				if (!rr_to_cache(cent, ttl, oname, rdlength, *ptr, type,flags,
						 queryts,serial,trusted, nsdomain))
					return RC_SERVFAIL;
			}
		}
		*lcnt-=rdlength;
		*ptr+=rdlength;
	}
	return RC_OK;
}

/*
 * Try to bind the socket to a port in the given port range. Returns 1 on success, or 0 on failure.
 */
static int bind_socket(int s)
{
	int range = global.query_port_end-global.query_port_start+1;
	socklen_t sinl=0;  /* Initialized to inhibit compiler warning */
	union {
#ifdef ENABLE_IPV4
		struct sockaddr_in sin4;
#endif
#ifdef ENABLE_IPV6
		struct sockaddr_in6 sin6;
#endif
	} sin;
	int i,j;

	/*
	 * 0, as a special value, denotes that we let the kernel select an address when we
	 * first use the socket, which is the default.
	 */
	if (global.query_port_start > 0) {
		for (j=i=(get_rand16()%range)+global.query_port_start;;) {
#ifdef ENABLE_IPV4
			if (run_ipv4) {
				memset(&sin.sin4,0,sizeof(struct sockaddr_in));
				sin.sin4.sin_family=AF_INET;
				sin.sin4.sin_port=htons(i);
				SET_SOCKA_LEN4(sin.sin4);
				sinl=sizeof(struct sockaddr_in);
			}
#endif
#ifdef ENABLE_IPV6
			if (run_ipv6) {
				memset(&sin.sin6,0,sizeof(struct sockaddr_in6));
				sin.sin6.sin6_family=AF_INET6;
				sin.sin6.sin6_port=htons(global.port);
				sin.sin6.sin6_flowinfo=IPV6_FLOWINFO;
				SET_SOCKA_LEN6(sin.sin6);
				sinl=sizeof(struct sockaddr_in6);
			}
#endif
			if (bind(s,(struct sockaddr *)&sin,sinl)==-1) {
				if (errno!=EADDRINUSE &&
				    errno!=EADDRNOTAVAIL) { /* EADDRNOTAVAIL should not happen here... */
					log_warn("Could not bind to socket: %s\n", strerror(errno));
					return 0;
				}
				/* If the address is in use, we continue. */
			} else
				break;	/* done. */
			if (++i>global.query_port_end)
				i=global.query_port_start;
			if (i==j) {
				/* Wraparound, scanned the whole range. Give up. */
				log_warn("Out of ports in the given range, dropping query!\n");
				return 0;
			}
		}
	}
	return 1;
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

	switch (st->nstate){
		/* TCP query code */
#ifndef NO_TCP_QUERIES
	case QSN_TCPINITIAL:
		if (!(pe=getprotobyname("tcp"))) {
			DEBUG_MSG("getprotobyname failed: %s\n", strerror(errno));
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
# ifdef ENABLE_IPV4
		if (run_ipv4) {
			if ((st->sock=socket(PF_INET,SOCK_STREAM,pe->p_proto))==-1) {
				DEBUG_MSG("Could not open socket: %s\n", strerror(errno));
				st->nstate=QSN_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
			/* sin4 is intialized, hopefully. */
		}
# endif
# ifdef ENABLE_IPV6
		if (run_ipv6) {
			if ((st->sock=socket(PF_INET6,SOCK_STREAM,pe->p_proto))==-1) {
				DEBUG_MSG("Could not open socket: %s\n", strerror(errno));
				st->nstate=QSN_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
			/* sin6 is intialized, hopefully. */
		}
# endif
		/* maybe bind */
		if (!bind_socket(st->sock)) {
			close(st->sock);
			st->nstate=QSN_DONE;
			return RC_SERVFAIL;
		}

		/* transmit query by tcp*/
		/* make the socket non-blocking for connect only, so that connect will not
		 * hang */
		fcntl(st->sock,F_SETFL,O_NONBLOCK);
		if (connect(st->sock,st->sin,SIN_LEN)==-1)
		{
			if (errno==EINPROGRESS || errno==EPIPE) {
				st->nstate=QSN_TCPCONNECT;
				st->event=QEV_WRITE; /* wait for writablility; the connect is then done */
				return -1;
			} else if (errno==ECONNREFUSED) {
				st->s_errno=errno;
				close(st->sock);
				st->nstate=QSN_DONE;
				return RC_TCPREFUSED;
			} else {
				/* Since immediate connect() errors does not cost any time, we do not try to switch the
				 * server status to offline */
				close(st->sock);
				DEBUG_SOCKA_MSG("Error while connecting to %s: %s\n", SOCKA2STR(st->sin),strerror(errno));
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
		{
			uint16_t transl_net=htons(st->transl);
			if (write_all(st->sock,&transl_net,sizeof(transl_net))==-1) {
				if (errno==ECONNREFUSED || errno==EPIPE) {
					st->s_errno=errno;
					/* This error may be delayed from connect() */
					close(st->sock);
					st->nstate=QSN_DONE;
					return RC_TCPREFUSED;
				} else {
					close(st->sock);
					DEBUG_SOCKA_MSG("Error while sending data to %s: %s\n", SOCKA2STR(st->sin),strerror(errno));
					st->nstate=QSN_DONE;
					return RC_SERVFAIL; /* mock error code */
				}
			}
		}
		st->nstate=QSN_TCPLWRITTEN;
		st->event=QEV_WRITE;
		return -1;
	case QSN_TCPLWRITTEN:
		if (write_all(st->sock,st->hdr,st->transl)==-1) {
			st->s_errno=errno;
			close(st->sock);
			DEBUG_SOCKA_MSG("Error while sending data to %s: %s\n", SOCKA2STR(st->sin),strerror(errno));
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
		st->nstate=QSN_TCPQWRITTEN;
		st->event=QEV_READ;
		return -1;
	case QSN_TCPQWRITTEN:
	        {
			uint16_t recvl_net;
			if ((rv=read(st->sock,&recvl_net,sizeof(recvl_net)))!=sizeof(recvl_net)) {
				if(rv==-1) st->s_errno=errno;
				close(st->sock);
				DEBUG_SOCKA_MSG("Error while receiving data from %s: %s\n", SOCKA2STR(st->sin),strerror(errno));
				st->nstate=QSN_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
			st->recvl=ntohs(recvl_net);
		}
		if (!(st->recvbuf=(dns_hdr_t *)pdnsd_calloc(st->recvl,1))) {
			close(st->sock);
			DEBUG_MSG("Out of memory in query.\n");
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
		st->nstate=QSN_TCPLREAD;
		st->event=QEV_READ;
		return -1;
	case QSN_TCPLREAD:
		if ((rv=read(st->sock,st->recvbuf,st->recvl))!=st->recvl) {
			if(rv==-1) st->s_errno=errno;
			close(st->sock);
			DEBUG_SOCKA_MSG("Error while receiving data from %s: %s\n", SOCKA2STR(st->sin),strerror(errno));
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
			DEBUG_MSG("getprotobyname failed: %s\n", strerror(errno));
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
# ifdef ENABLE_IPV4
		if (run_ipv4) {
			if ((st->sock=socket(PF_INET,SOCK_DGRAM,pe->p_proto))==-1) {
				DEBUG_MSG("Could not open socket: %s\n", strerror(errno));
				st->nstate=QSN_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
		}
# endif
# ifdef ENABLE_IPV6
		if (run_ipv6) {
			if ((st->sock=socket(PF_INET6,SOCK_DGRAM,pe->p_proto))==-1) {
				DEBUG_MSG("Could not open socket: %s\n", strerror(errno));
				st->nstate=QSN_DONE;
				return RC_SERVFAIL; /* mock error code */
			}
		}
# endif
		/* maybe bind */
		if (!bind_socket(st->sock)) {
			close(st->sock);
			st->nstate=QSN_DONE;
			return RC_SERVFAIL;
		}

		/* connect */
		if (connect(st->sock,st->sin,SIN_LEN)==-1) {
			st->s_errno=errno;
			close(st->sock);
			DEBUG_SOCKA_MSG("Error while connecting to %s: %s\n", SOCKA2STR(st->sin),strerror(errno));
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
		
		/* transmit query by udp*/
		/* send will hopefully not block on a freshly opened socket (the buffer
		 * must be empty) */
		if (send(st->sock,st->hdr,st->transl,0)==-1) {
			st->s_errno=errno;
			close(st->sock);
			DEBUG_SOCKA_MSG("Error while sending data to %s: %s\n", SOCKA2STR(st->sin),strerror(errno));
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
		if (!(st->recvbuf=(dns_hdr_t *)pdnsd_calloc(512,1))) {
			close(st->sock);
			DEBUG_MSG("Out of memory in query.\n");
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
		st->nstate=QSN_UDPRECEIVE;
		st->event=QEV_READ;
		return -1;
	case QSN_UDPRECEIVE:
		if ((rv=recv(st->sock,st->recvbuf,512,0))==-1) {
			st->s_errno=errno;
			close(st->sock);
			DEBUG_SOCKA_MSG("Error while receiving data from %s: %s\n", SOCKA2STR(st->sin),strerror(errno));
			st->nstate=QSN_DONE;
			return RC_SERVFAIL; /* mock error code */
		}
		st->recvl=rv;
		if (st->recvl<sizeof(dns_hdr_t) || ntohs(st->recvbuf->id)!=st->myrid) {
			DEBUG_MSG("Bad answer received. Ignoring it.\n");
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
static int p_exec_query(dns_cent_t **entp, unsigned char *rrn, unsigned char *name, int *aa, query_stat_t *st, nsr_array *ns, unsigned long serial) 
{
	dns_cent_t *ent;
	int i,j,rv;
	time_t queryts;
	long lcnt;
	unsigned char *rrp;
	unsigned char nbuf[256];

	switch (st->state){
	case QS_INITIAL:
		st->sin=SIN_ADDR(st);
		if (!st->lean_query)
			st->qt=QT_ALL;
		st->transl=sizeof(dns_hdr_t)+rhnlen(rrn)+4;
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
		{
			std_query_t temp_q;
			temp_q.qtype=htons(st->qt);
			temp_q.qclass=htons(C_IN);
			memcpy(((unsigned char *)(st->hdr+1))+rhnlen(rrn),&temp_q,4);
		}
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
				DEBUG_SOCKA_MSG("TCP connection refused by %s. Trying to use UDP.\n", SOCKA2STR(st->sin));
				return -1;
			}
			pdnsd_free(st->hdr);
			st->state=QS_DONE;
			DEBUG_SOCKA_MSG("TCP connection refused by %s\n", SOCKA2STR(st->sin));
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
				DEBUG_SOCKA_MSG("Server %s returned error code: %s\n", SOCKA2STR(st->sin),get_ename(rv));
				return rv;
			}
			DEBUG_SOCKA_MSG("Server %s returned invalid answer\n", SOCKA2STR(st->sin));
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
				DEBUG_SOCKA_MSG("Server %s does not support recursive query. Querying nonrecursive.\n", SOCKA2STR(st->sin));
				return -1;
			} else {
				/* pdnsd_free(st->hdr); */
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
		DEBUG_MSG("Bad number of query records in answer.\n");
		rv=RC_SERVFAIL;
		goto free_recvbuf_return;
	}
	/* check & skip the query record. We can ignore undersocres here, because they will be
	 * detected in the name comparison */
	{
		int dummy;
		if ((rv=decompress_name((unsigned char *)st->recvbuf, nbuf, &rrp, &lcnt, st->recvl, &i, &dummy))!=RC_OK) {
			if(rv==RC_TRUNC) rv=RC_FORMAT;
			goto free_recvbuf_return;
		}
	}

	i=0;
	while(1) {
		j=nbuf[i];
		if (nbuf[i]!=rrn[i]) {
			DEBUG_MSG("Answer does not match query.\n");
			rv=RC_SERVFAIL;
			goto free_recvbuf_return;
		}
		if (!j) 
			break;
		i++;
		for (;j>0;j--) {
			if (tolower(nbuf[i])!=tolower(rrn[i])) {
				DEBUG_MSG("Answer does not match query.\n");
				rv=RC_SERVFAIL;
				goto free_recvbuf_return;
			}
			i++;
		}
	}
	
	if (lcnt<4) {
		rv=RC_SERVFAIL; /* mock error code */
		goto free_recvbuf_return;
	}
	rrp+=4; /* two shorts (qtype and qclass);*/
	lcnt-=4;
	/* second: evaluate the results (by putting them in a dns_cent_t */
	ent=(dns_cent_t *)pdnsd_malloc(sizeof(dns_cent_t));
	if (!ent) {
		rv=RC_SERVFAIL; /* mock error code */
		goto free_recvbuf_return;
	}

	/* negative cacheing for domains */
	if (st->recvbuf->rcode==RC_NAMEERR) {
		DEBUG_SOCKA_MSG("Server %s returned error code: %s\n", SOCKA2STR(st->sin),get_ename(st->recvbuf->rcode));
		/* We did not get what we wanted. Cache according to policy */
		if (global.neg_domain_pol==C_ON || (global.neg_domain_pol==C_AUTH && st->recvbuf->aa)) {
			DEBUG_MSG("Cacheing domain %s negative\n",name);
			if (!init_cent(ent,name, DF_NEGATIVE, queryts, global.neg_ttl  DBG1)) {
				rv=RC_SERVFAIL; /* mock error code */
				goto free_ent_recvbuf_return;
			}
			goto cleanup_return_OK;
		} else {
			rv=RC_NAMEERR;
			goto free_ent_recvbuf_return;
		}
	}

	if (!init_cent(ent,name, 0, queryts, 0  DBG1)) {
		rv=RC_SERVFAIL; /* mock error code */
		goto free_ent_recvbuf_return;
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
		rv=RC_SERVFAIL;
		goto free_ns_ent_recvbuf_return;
	}

	if (ntohs(st->recvbuf->nscount)>0) {
		if (rrs2cent(ent,&rrp,&lcnt,ntohs(st->recvbuf->nscount), (unsigned char *)st->recvbuf,st->recvl,
			     st->flags|CF_ADDITIONAL,ns,queryts,serial, st->trusted, st->nsdomain, st->recvbuf->tc)!=RC_OK) {
			rv=RC_SERVFAIL;
			goto free_ns_ent_recvbuf_return;
		}
	}
	
	if (ntohs(st->recvbuf->arcount)>0) {
		if (rrs2cent(ent,&rrp,&lcnt,ntohs(st->recvbuf->arcount), (unsigned char *)st->recvbuf,st->recvl,
			     st->flags|CF_ADDITIONAL,ns,queryts,serial, st->trusted, st->nsdomain, st->recvbuf->tc)!=RC_OK) {
			rv=RC_SERVFAIL;
			goto free_ns_ent_recvbuf_return;
		}
	}

	/* Negative cacheing of rr sets */
	if (st->qt>=T_MIN && st->qt<=T_MAX && !ent->rr[st->qt-T_MIN]) {
		/* We did not get what we wanted. Cache according to policy */
		if (global.neg_rrs_pol==C_ON || (global.neg_rrs_pol==C_AUTH && st->recvbuf->aa)) {
			time_t ttl=global.neg_ttl;
			rr_set_t *rrset=ent->rr[T_SOA-T_MIN];
			/* If we received a SOA, we should take the ttl of that record. */
			if (rrset && rrset->rrs) {
#ifdef notdef
				unsigned char *soa;
				soa_r_t soa_r;

				soa=(char *)(rrset->rrs+1);
				/* Skip owner and maintainer. Lengths are validated in cache */
				while (*soa)
					soa+=*soa+1;
				soa++;
				while (*soa)
					soa+=*soa+1;
				soa++;
				memcpy(soa_r,soa,sizeof(soa_r));
				ttl=ntohl(soa_r.expire);
#endif
				ttl=rrset->ttl+rrset->ts-time(NULL);
				if(ttl<0) ttl=0;
			}
			if(ttl<global.min_ttl)
				ttl=global.min_ttl;
			else if(ttl>global.max_ttl)
				ttl=global.max_ttl;
			DEBUG_MSG("Cacheing type %s for domain %s negative with ttl %li\n",get_tname(st->qt),name,(long)ttl);
			if (!add_cent_rrset(ent, st->qt, global.neg_ttl, queryts, CF_NEGATIVE|st->flags, serial  DBG1)) {
				rv=RC_SERVFAIL;
				goto free_ns_ent_recvbuf_return;
			}
		}
	}
 cleanup_return_OK:
	*entp=ent;
	rv=RC_OK;
	goto free_recvbuf_return;

 free_ns_ent_recvbuf_return:
	da_free(*ns); *ns=NULL;
	free_cent(ent  DBG1);
 free_ent_recvbuf_return:
	pdnsd_free(ent);
 free_recvbuf_return:
	pdnsd_free(st->recvbuf);
	return rv;
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
inline static void init_qserv(query_stat_array *q)
{
	*q=NULL;
}

/*
 * Add a server entry to a query_serv_t
 */
static int add_qserv(query_stat_array *q, pdnsd_a *a, int port, time_t timeout, char auth_s, int flags, int nocache, int thint, char lean_query, char trusted,
    unsigned char *nsdomain)
{
	query_stat_t *qs;
	
	if ((*q=DA_GROW1(*q))==NULL)
		return 0;
	
	qs=&DA_LAST(*q);
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		memset(&qs->a.sin4,0,sizeof(qs->a.sin4));
		qs->a.sin4.sin_family=AF_INET;
		qs->a.sin4.sin_port=htons(port);
		qs->a.sin4.sin_addr=a->ipv4;
		SET_SOCKA_LEN4(qs->a.sin4);
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
	}
#endif
	qs->sin=NULL;
	qs->timeout=timeout;
	qs->flags=flags;
	qs->nocache=nocache;
	qs->qt=thint;
	qs->lean_query=lean_query;
	qs->trusted=trusted;
	qs->auth_serv=auth_s;
	rhncpy(qs->nsdomain,nsdomain);
	qs->state=QS_INITIAL;
	qs->qm=query_method;
	qs->s_errno=0;
	return 1;
}

/*
 * Free resources used by a query_serv_t
 * There for historical reasons only.
 */
inline static void del_qserv(query_stat_array q)
{
	da_free(q);
}

/*
 * Performs a semi-parallel query on the servers in q. PAR_QUERIES are executed parall at a time.
 * name is the query name in dotted notation, rrn the same in dns protocol format (number.string etc),
 * ent is the dns_cent_t that will be filled.
 * hops is the number of recursions left.
 * thint is a hint on the requested query type used to decide whether an aa record must be fetched
 * or a non-authoritative answer will be enough.
 *
 * nocache is needed because we add AA records to the cache. If the nocache flag is set, we do not
 * take the original values for the record, but flags=0 and ttl=0 (but only if we do not already have
 * a cached record for that set). This settings cause the record be purged on the next cache addition.
 * It will also not be used again.
 */
static int p_recursive_query(query_stat_array q, unsigned char *rrn, unsigned char *name, dns_cent_t **entp, int *nocache, int hops, int thint)
{
	dns_cent_t *ent;
	int aa=0;
	int i,j,k,ad,auth_sv=0;  /* Initialized to inhibit compiler warning */
	int rv=RC_SERVFAIL;
	query_stat_t *qse=NULL;  /* Initialized to inhibit compiler warning */
	unsigned long serial=get_serial();
	nsr_array ns=NULL;
	time_t ts;
#ifndef NO_POLL
	struct pollfd *polls=pdnsd_calloc(global.par_queries,sizeof(struct pollfd));

	if (!polls) {
		log_warn("Out of memory in p_recursive_query!");
		return RC_SERVFAIL;
	}
#endif

	ad=(DA_NEL(q)+(global.par_queries-1))/global.par_queries;
	for (j=0;j<ad;j++) {
		int qo,mc=DA_NEL(q)-j*global.par_queries;
		if (mc>global.par_queries)
			mc=global.par_queries;
		/* First, call p_exec_query once for each parallel set to initialize.
		 * Then, as long as not all have the state QS_DONE or we have a timeout,
		 * build a poll/select set for all active queries and call them accordingly. */
		qo=1;
		for (i=0;i<mc;i++) {
			/* The below should not happen any more, but may once again
			 * (immediate success) */
			query_stat_t *qs=&DA_INDEX(q,global.par_queries*j+i);
			rv=p_exec_query(&ent, rrn, name, &aa, qs,&ns,serial);
			if (rv==RC_OK || rv==RC_NAMEERR) {
				for (k=0;k<mc;k++) {
					p_cancel_query(&DA_INDEX(q,global.par_queries*j+k));
				}
				if (rv==RC_OK) {
					qse=qs;
					auth_sv=qs->auth_serv;
					*nocache=qs->nocache;
					DEBUG_SOCKA_MSG("Query to %s succeeded.\n",SOCKA2STR(qs->sin));
				}
				goto done;
			}
			if (qs->state!=QS_DONE)
				qo=0;
		}
		if (!qo) {
			/* we do time keeping by hand, because poll/select might be interrupted and
			 * the returned times are not always to be trusted upon */
			ts=time(NULL);
			do {
				int pc,srv;
				long maxto;
#ifdef NO_POLL
				fd_set              reads;
				fd_set              writes;
				struct timeval      tv;
				int                 maxfd;
#endif
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
				maxfd=0;
				for (i=0;i<mc;i++) {
					query_stat_t *qs=&DA_INDEX(q,global.par_queries*j+i);
					if (qs->state!=QS_DONE) {
						if (qs->timeout>maxto)
							maxto=qs->timeout;
						if (qs->sock>maxfd)
							maxfd=qs->sock;
						switch (qs->event) {
						case QEV_READ:
							FD_SET(qs->sock,&reads);
							break;
						case QEV_WRITE:
							FD_SET(qs->sock,&writes);
							break;
						}
						pc++;
					}
				}
				if (pc==0) {
					/* In this case, ALL are done and we do not need to cancel any
					 * query. */
					break;
				}
				maxto-=time(NULL)-ts;
				tv.tv_sec=(maxto>0)?maxto:0;
				tv.tv_usec=0;
				srv=select(maxfd+1,&reads,&writes,NULL,&tv);
# else
				for (i=0;i<mc;i++) {
					query_stat_t *qs=&DA_INDEX(q,global.par_queries*j+i);
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
					break;
				}
				maxto-=time(NULL)-ts;
				srv=poll(polls,pc,(maxto>0)?(maxto*1000):0);
# endif
				if (srv<0) {
					log_warn("poll/select failed: %s",strerror(errno));
					for (k=0;k<mc;k++)
						p_cancel_query(&DA_INDEX(q,global.par_queries*j+k));
					rv=RC_SERVFAIL;
					goto done;
				}
				
				qo=1;
				for (i=0;i<mc;i++) {
					query_stat_t *qs=&DA_INDEX(q,global.par_queries*j+i);
					/* Check if we got a poll/select event, or whether we are timed out */
					if (qs->state!=QS_DONE) {
						if (srv==0 || time(NULL)-ts>=qs->timeout) {
							/* We have timed out. cancel this, and see whether we need to mark
							 * a server down. */
							p_cancel_query(qs);
							mark_server_down(SOCK_PDNSD_A(qs->a),1);
							/* set rv, we might be the last! */
							rv=RC_SERVFAIL;
						} else {
							int srv_event=0;
							/* This detection may seem subobtimal, but normally, we have at most 2-3 parallel
							 * queries, and anything else would be higher overhead, */
#ifdef NO_POLL
							switch (qs->event) {
							case QEV_READ:
								srv_event=FD_ISSET(qs->sock,&reads);
								break;
							case QEV_WRITE:
								srv_event=FD_ISSET(qs->sock,&writes);
								break;
							}
#else
							for (k=0;k<pc;k++) {
								if (polls[k].fd==qs->sock) {
									/*
									 * In case of an error, reenter the state machine
									 * to catch it.
									 */
									switch (qs->event) {
									case QEV_READ:
										srv_event=polls[k].revents&(POLLIN|POLLERR|POLLHUP|POLLNVAL);
										break;
									case QEV_WRITE:
										srv_event=polls[k].revents&(POLLOUT|POLLERR|POLLHUP|POLLNVAL);
										break;
									}
									break;
								}
							}
#endif
							if (srv_event) {
								rv=p_exec_query(&ent, rrn, name, &aa, qs,&ns,serial);
								if (rv==RC_OK || rv==RC_NAMEERR) {
									for (k=0;k<mc;k++) {
										p_cancel_query(&DA_INDEX(q,global.par_queries*j+k));
									}
									if (rv==RC_OK) {
										qse=qs;
										auth_sv=qs->auth_serv;
										*nocache=qs->nocache;
										DEBUG_SOCKA_MSG("Query to %s succeeded.\n",
										    SOCKA2STR(qs->sin));
									}
									goto done;
								}
								else if(rv==RC_SERVFAIL && qs->s_errno==ECONNREFUSED)
								  mark_server_down(SOCK_PDNSD_A(qs->a),0);
							}
							/* recheck, this might have changed after the last p_exec_query */
							if (qs->state!=QS_DONE) {
								qo=0;
							}
						} 
					}
				}
			} while (!qo);
		}
	}
 done:
#ifndef NO_POLL
	pdnsd_free(polls);
#endif
	if (rv!=RC_OK) {
		DEBUG_MSG("No query succeeded. Returning error code \"%s\"\n",get_ename(rv));
		return rv;
	}
	
	/*
	 * Look into the query type hint. If it is a wildcard (QT_*), we need an authoritative answer.
	 * Same if there is no record that answers the query. Mark the cache record if it is not an aa.
	 */

	/* This test will also succeed if we have a negative cached record. This is purposely. */
#define aa_needed ((thint>=QT_MIN && thint<=QT_MAX) || \
	           ((thint>=T_MIN && thint<=T_MAX) && (!ent->rr[thint-T_MIN] && !ent->rr[T_CNAME-T_MIN])))

	if (DA_NEL(ns)>0 && !aa && auth_sv && aa_needed) {
		query_stat_array serv;
		init_qserv(&serv);
		/* Authority records present. Ask them, because the answer was non-authoritative. To do so, we first put 
		 * the Authority and the additional section into a dns_cent_t and look for name servers in the Authority 
		 * section and their addresses in the Answer and additional sections. If none are found, we also need to 
		 * resolve the name servers.*/
		if (hops>=0) {
			for (j=0;j<DA_NEL(ns);j++) {
				pdnsd_a serva;
				unsigned char nsbuf[256],nsname[256];
				nsr_t *nsr=&DA_INDEX(ns,j);
				
				if (global.paranoid) {
					/* paranoia mode: don't query name servers that are not responsible */
					/* rhn2str(nsr->nsdomain,nsname); */
					domain_match(&i,nsr->nsdomain,rrn,nsname);
					if (nsname[0]!='\0')
						continue;
				}
				strncpy(nsname,nsr->name,sizeof(nsname));
				nsname[sizeof(nsname)-1]='\0';
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
				{
					dns_cent_t *servent;

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
									struct in_addr ina;
									/* XXX: memcpy for alpha (unaligned access) */
									memcpy(&ina,servent->rr[T_A-T_MIN]->rrs+1,sizeof(ina));
									IPV6_MAPIPV4(&ina,&serva.ipv6);
								}
						
						}
#endif
						free_cent(servent  DBG1);
						pdnsd_free(servent);
					}
				}
				
				if (!is_inaddr_any(&serva)) {
					/* We've got an address. Add it to the list if it wasn't one of the servers we queried. */
					/* The given address may not be ours!!! */
					/* in netdev.c */
					int nons= !is_local_addr(&serva);

					if (nons) {
						for (i=0;i<DA_NEL(q);i++) {
							/* q->qs[i].sin is initialized in p_exec_query, and may thus not be
							   initialized */
							query_stat_t *qs=&DA_INDEX(q,i);
							if (qs->sin && ADDR_EQUIV(SOCKA_A(qs->sin),&serva)) {
								nons=0;
								break;
							}
						}
					}
					if (nons) {
						/* lean query mode is inherited. CF_NOAUTH and CF_ADDITIONAL are not (as specified
						 * in CFF_NOINHERIT). */
						if (!add_qserv(&serv, &serva, 53, qse->timeout, 1, qse->flags&~CFF_NOINHERIT, 0,thint,
						    qse->lean_query,!global.paranoid,nsr->nsdomain)) {
							rv=RC_SERVFAIL;
							free_cent(ent  DBG1);
							pdnsd_free(ent);
							goto free_ns_return;
						}
					}
				}
			}
			if (DA_NEL(serv)>0) {
				free_cent(ent  DBG1);
				pdnsd_free(ent);
				rv=p_dns_cached_resolve(serv,  name, rrn, &ent,hops-1,thint,time(NULL));
				/* return the answer in any case. */
				goto free_qserv_ns_return;
			}
		}
		/*
		 * If we didn't get rrs from any of the authoritative servers, take the one we had. However, set its ttl to 0,
		 * so that it won't be used again unless it is necessary.
		 */
		for (j=0;j<T_NUM;j++) {
			if (ent->rr[j])
				ent->rr[j]->ttl=0;
		}
	free_qserv_ns_return:
		del_qserv(serv);
	}
 free_ns_return:
	da_free(ns);

	if(rv==RC_OK) *entp=ent;
	return rv;
#undef  aa_needed
}

/* 
 * following the resolvers. Some take a list of servers for parallel query. The others query the servers supplied by the user.
 */
inline static int p_dns_resolve_from(query_stat_array q, unsigned char *name, unsigned char *rrn , dns_cent_t **cached, int hops, int thint)
{
	int dummy;

	return p_recursive_query(q, rrn, name,cached, &dummy, hops, thint);
} 

/*
 * This checks the given name to resolve against the access list given for the server using the
 * include=, exclude= and policy= parameters.
 */
static int use_server(servparm_t *s, const unsigned char *name)
{
	int i;

	if (s->alist) {
		for (i=0;i<DA_NEL(s->alist);i++) {
			slist_t *sl=&DA_INDEX(s->alist,i);
			if (sl->domain[0]=='.') {
				int strlen_diff = strlen(name)-strlen(sl->domain);
				/* match this domain and all subdomains */
				if ((strlen_diff==-1 && stricomp(name,sl->domain+1)) ||
				    (strlen_diff>=0 && stricomp(name+strlen_diff,sl->domain)))
					return sl->rule==C_INCLUDED;
			} else {
				/* match this domain exactly */
				if (stricomp(name,sl->domain))
					return sl->rule==C_INCLUDED;
			}

		}
	}

	if (s->policy==C_SIMPLE_ONLY || s->policy==C_FQDN_ONLY) {
                const char *dot=strchr(name,'.');
                if(!dot || !*(dot+1)) return s->policy==C_SIMPLE_ONLY;
                else return s->policy==C_FQDN_ONLY;
        }

	return s->policy==C_INCLUDED;
}


static int p_dns_resolve(unsigned char *name, unsigned char *rrn , dns_cent_t **cachedp, int hops, int thint)
{
	dns_cent_t *cached;
	int i,rc,nocache;
	int one_up=0;
	query_stat_array serv;
	
	/* try the servers in the order of their definition */
	init_qserv(&serv);
	lock_server_data();
	for (i=0;i<DA_NEL(servers);i++) {
		servparm_t *sp=&DA_INDEX(servers,i);
		if(use_server(sp,name)) {
			int j;
			for(j=0;j<DA_NEL(sp->atup_a);++j) {
				atup_t *at=&DA_INDEX(sp->atup_a,j);
				if (at->is_up) {
					one_up=add_qserv(&serv, &at->a, sp->port, sp->timeout, !sp->is_proxy, mk_flag_val(sp),sp->nocache,thint,sp->lean_query,1,"");
					if(!one_up)
						goto done;
				}
			}
		}
	}
 done:
	unlock_server_data();
	if (one_up) {
		rc=p_recursive_query(serv, rrn, name,&cached,&nocache, hops, thint);
		if (rc==RC_OK) {
			if (!nocache) {
				dns_cent_t *tc;
				add_cache(cached);
				if ((tc=lookup_cache(name))) {
					/* The cache may hold more information  than the recent query yielded.
					 * try to get the merged record. If that fails, revert to the new one. */
					free_cent(cached  DBG1);
					pdnsd_free(cached);
					cached=tc;
				} else
					DEBUG_MSG("p_dns_resolve: using local cent copy.\n");
			} else
				DEBUG_MSG("p_dns_resolve: nocache\n");

			*cachedp=cached;
		}
	}
	else {
		DEBUG_MSG("No server is marked up and allowed for this domain.\n");
		rc=RC_SERVFAIL; /* No server up */
	}
	del_qserv(serv);
	return rc;
} 

static int set_flags_ttl(short *flags, time_t *ttl, dns_cent_t *cached, int i)
{
	rr_set_t *rrset=cached->rr[i-T_MIN];
	if (rrset) {
		time_t t;
		*flags|=rrset->flags;
		t=rrset->ts+rrset->ttl;
		if (*ttl<t)
			*ttl=t;
		return 1;
	}
	return 0;
}

/*
 * Resolve records for name/rrn into dns_cent_t, type thint
 * q is the set of servers to query from. Set q to NULL if you want to ask the servers registered with pdnsd.
 */
int p_dns_cached_resolve(query_stat_array q, unsigned char *name, unsigned char *rrn , dns_cent_t **cachedp, int hops, int thint, time_t queryts)
{
	dns_cent_t *cached;
	int rc;
	int need_req=0;
	int timed=0;
	int neg=0;
	int i,nopurge=0;
	short flags=0;

	DEBUG_MSG("Starting cached resolve for: %s, query %s\n",name,get_tname(thint));
	if ((cached=lookup_cache(name))) {
		time_t ttl=0;
		int auth=0;

		DEBUG_MSG("Record found in cache.\n");
		if (cached->flags&DF_NEGATIVE) {
			if (cached->ts+cached->ttl+CACHE_LAT>=queryts)
				neg=1;
			else
				need_req=1;
		} else {
			for (i=0;i<T_NUM;i++) {
				rr_set_t *rrset=cached->rr[i];
				if (rrset) {
					if (!(rrset->flags&CF_NOAUTH) && !(rrset->flags&CF_ADDITIONAL)) {
						auth=1;
					}
					if (rrset->flags&CF_NOPURGE) {
						nopurge=1;
				}
					if (auth && nopurge)
						break;
				}
			}
			if (!set_flags_ttl(&flags, &ttl, cached, T_CNAME)) {
				if (thint==QT_ALL) {
					for (i=T_MIN;i<=T_MAX;i++)
						set_flags_ttl(&flags, &ttl, cached, i);
				} else if (thint==QT_MAILA) {
					set_flags_ttl(&flags, &ttl, cached, T_MD);
					set_flags_ttl(&flags, &ttl, cached, T_MF);
				} else if (thint==QT_MAILB) {
					set_flags_ttl(&flags, &ttl, cached, T_MG);
					set_flags_ttl(&flags, &ttl, cached, T_MB);
					set_flags_ttl(&flags, &ttl, cached, T_MR);
				} else if (thint>=T_MIN && thint<=T_MAX) {
					if (set_flags_ttl(&flags, &ttl, cached, thint))
						neg=cached->rr[thint-T_MIN]->flags&CF_NEGATIVE && ttl-queryts+CACHE_LAT>=0;
				}
			}
			if (thint>=QT_MIN && thint<=QT_MAX  && !auth)
				need_req=!(flags&CF_LOCAL);
			else {
				if (ttl-queryts+CACHE_LAT<0)
					timed=1;
			}
		}
		DEBUG_MSG("Requery decision: req=%i, neg=%i, timed=%i, flags=%i, ttl=%li\n",need_req!=0,
			   neg,timed,flags,(long)(ttl-queryts));
	}
	/* update server records set onquery */
	if(global.onquery) test_onquery();
	if (global.lndown_kluge && !(flags&CF_LOCAL)) {
		int linkdown=1;
		lock_server_data();
		for(i=0;i<DA_NEL(servers);++i) {
			servparm_t *sp=&DA_INDEX(servers,i);
			int j;
			for(j=0; j<DA_NEL(sp->atup_a);++j) {
				if (DA_INDEX(sp->atup_a,j).is_up) {
					linkdown=0;
					goto done;
				}
			}
		}
	done:
		unlock_server_data();
		if (linkdown) {
			DEBUG_MSG("Link is down.\n");
			rc=RC_SERVFAIL;
			goto cleanup_return;
		}
	}
	if (!cached || (!(cached->flags&DF_LOCAL) && !neg && (need_req || (timed && !(flags&CF_LOCAL))))) {
		dns_cent_t *ent;
		DEBUG_MSG("Trying name servers.\n");
		if (q) 
			rc=p_dns_resolve_from(q,name, rrn, &ent,hops,thint);
		else
			rc=p_dns_resolve(name, rrn, &ent,hops,thint);
		if (rc!=RC_OK) {
			if (rc==RC_SERVFAIL && cached && nopurge) {
				/* We could not get a new record, but we have a timed-out cached one
				   with the nopurge flag set. This means that we shall use it even
				   if timed out when no new one is available*/
				DEBUG_MSG("Falling back to cached record.\n");
			} else {
				goto cleanup_return;
			}
		} else {
			if (cached) {
				free_cent(cached  DBG1);
				pdnsd_free(cached);
			}
			cached=ent;
		}
	} else {
		DEBUG_MSG("Using cached record.\n");
	}
	if (cached && cached->flags&DF_NEGATIVE) {
		rc=RC_NAMEERR;
		goto free_cached_return;
	}
	*cachedp=cached;
	return RC_OK;

 cleanup_return:
	if(cached)
 free_cached_return: {
		free_cent(cached  DBG1);
		pdnsd_free(cached);
	}
	return rc;
}
