/* cache.h - Definitions for the dns cache

   Copyright (C) 2000 Thomas Moestl
   Copyright (C) 2003, 2004, 2005 Paul A. Rombouts

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

/* $Id: cache.h,v 1.11 2001/05/09 17:51:52 tmm Exp $ */

#ifndef _CACHE_H_
#define _CACHE_H_

#include <config.h>
#include "ipvers.h" 
#include <stdio.h>
#include "list.h"
#include "dns.h"
#include "conff.h"

struct rr_lent_s;

/*
 * These values are converted to host byte order. the data is _not_.
 */
typedef struct rr_b_s  {
	struct rr_b_s    *next;                   /* this is the next pointer in the dns_cent_t list. */
	unsigned short   rdlen;
} rr_bucket_t;

typedef struct {
	struct rr_lent_s *lent;                   /* this points to the list entry */
	time_t           ttl;
	time_t           ts;
	unsigned short   flags;
	rr_bucket_t      *rrs;
} rr_set_t;


typedef struct {
	unsigned short   rdlen;
/*	data (with length rdlen) follows here;*/
} rr_fbucket_t;

typedef struct {
	unsigned char    tp;
	unsigned char    num_rr;
	time_t           ttl;
	time_t           ts;
	unsigned short   flags;
}  __attribute__((packed))
rr_fset_t;


typedef struct {
	unsigned char    *qname;                  /* Name of the query in length byte - string notation. */
	size_t           cs;                      /* size of the rrs*/
	short            num_rrs;                 /* The number of rrs. When this decreases to 0, the cent is deleted. */
	unsigned short   flags;                   /* Flags for the whole cent */
	time_t           ts;                      /* Timestamp (only for negative cached records) */
	time_t           ttl;                     /* TTL       (  "   "     "       "       "   ) */ 
	struct rr_lent_s *lent;                   /* lent for the whole cent, only for neg. cached recs */
	rr_set_t         *(rr[T_NUM]);            /* The records. Use the type id-T_MIN as index, */
	unsigned char    c_ns,c_soa;              /* Number of trailing name elements in qname to use to find NS or SOA
						     records to add to the authority section of a response. */
} dns_cent_t;

/* This value is used to represent an undefined c_ns or c_soa field. */
#define cundef 0xff

typedef struct {
	unsigned char    qlen;
	unsigned char    num_rrs;
	unsigned short   flags;                   /* Flags for the whole cent */
	time_t           ts;                      /* Timestamp (only for negative cached records) */
	time_t           ttl;                     /* TTL       (  "   "     "       "       "   ) */ 
	unsigned char    c_ns,c_soa;              /* Number of trailing name elements in qname to use to find NS or SOA
						     records to add to the authority section of a response. */
/*      qname (with length qlen) follows here */
}  __attribute__((packed))
dns_file_t;

/*
 * This has two modes: Normally, we have rrset, cent and tp filled in;
 * for negatively cached cents, we have rrset set to NULL and tp set to -1
 */
typedef struct rr_lent_s {
	rr_set_t         *rrset;
	dns_cent_t       *cent;
	int              tp;
	struct rr_lent_s *next;
	struct rr_lent_s *prev;
} rr_lent_t;

/*
 * the flag values for RR sets in the cache
 */
#define CF_NEGATIVE    1       /* this one is for per-RRset negative caching*/
#define CF_LOCAL       2       /* Local zone entry */
#define CF_AUTH        4       /* authoritative record */
#define CF_NOCACHE     8       /* Only hold for the cache latency time period, then purge. Not really written 
				* to cache records, but used by add_cent_rrset */
#define CF_ADDITIONAL 16       /* This was fetched as an additional or "off-topic" record. */
#define CF_NOPURGE    32       /* Do not purge this record */
#define CF_ROOTSERV   64       /* This record was directly obtained from a root server */

#define CFF_NOINHERIT (CF_LOCAL|CF_AUTH|CF_ADDITIONAL|CF_ROOTSERV) /* not to be inherited on requery */

/*
 * the flag values for whole domains in the cache
 */
#define DF_NEGATIVE    1       /* this one is for whole-domain negative caching (created on NXDOMAIN)*/
#define DF_LOCAL       2       /* local record (in conj. with DF_NEGATIVE) */
#define DF_AUTH        4       /* authoritative record */
#define DF_WILD        8       /* subdomains of this domain have wildcard records */

/* #define DFF_NOINHERIT (DF_NEGATIVE) */ /* not to be inherited on requery */

enum {w_wild=1, w_neg, w_locnerr};  /* Used to distinguish different types of wildcard records. */

#if DEBUG>0
#define NCFLAGS 7
#define NDFLAGS 4
#define CFLAGSTRLEN (NCFLAGS*4)
#define DFLAGSTRLEN (NDFLAGS*4)
extern const char cflgnames[];
extern const char dflgnames[];
char *flags2str(unsigned flags,char *buf,int nflags,const char *flgnames);
#define cflags2str(flags,buf) flags2str(flags,buf,NCFLAGS,cflgnames)
#define dflags2str(flags,buf) flags2str(flags,buf,NDFLAGS,dflgnames)
#endif

/*
 * This is the time in secs any record remains at least in the cache before it is purged.
 * (exception is that the cache is full)
 */
#define CACHE_LAT 120
#define CLAT_ADJ(ttl) ((ttl)<CACHE_LAT?CACHE_LAT:(ttl))
/* This is used internally to check if a cache entry or rrset has timed out. */
#define timedout(ent) ((ent)->ts+CLAT_ADJ((ent)->ttl)<time(NULL))

extern volatile short int use_cache_lock;


#ifdef ALLOC_DEBUG
#define DBGPARAM ,int dbg
#define DBGARG ,dbg
#define DBG0 ,0
#define DBG1 ,1
#else
#define DBGPARAM
#define DBGARG
#define DBG0
#define DBG1
#endif


/* Initialize the cache. Call only once. */
#define init_cache mk_dns_hash

/* Initialize the cache lock. Call only once. */
inline static void init_cache_lock()
{
	use_cache_lock=1;
}

int empty_cache(slist_array sla);
void destroy_cache(void);
void read_disk_cache(void);
void write_disk_cache(void);

int report_cache_stat(int f);
int dump_cache(int fd, const unsigned char *name, int exact);

/*
 *  add_cache expects the dns_cent_t to be filled.
 */
void add_cache(dns_cent_t *cent);
int add_reverse_cache(dns_cent_t * cent);
void del_cache(const unsigned char *name);
void invalidate_record(const unsigned char *name);
int set_cent_flags(const unsigned char *name, unsigned flags);
unsigned char *getlocalowner(unsigned char *name,int tp);
dns_cent_t *lookup_cache(const unsigned char *name, int *wild);
/* int add_cache_rr_add(const unsigned char *name, int tp, time_t ttl, time_t ts, unsigned flags, unsigned dlen, void *data, unsigned long serial); */

inline static unsigned int mk_flag_val(servparm_t *server)
{
	unsigned int fl=0;
	if (!server->purge_cache)
		fl|=CF_NOPURGE;
	if (server->nocache)
		fl|=CF_NOCACHE;
	if (server->rootserver)
		fl|=CF_ROOTSERV;
	return fl;
}

int init_cent(dns_cent_t *cent, const unsigned char *qname, time_t ttl, time_t ts, unsigned flags  DBGPARAM);
int add_cent_rrset(dns_cent_t *cent,  int tp, time_t ttl, time_t ts, unsigned flags  DBGPARAM);
int add_cent_rr(dns_cent_t *cent, int tp, time_t ttl, time_t ts, unsigned flags,unsigned dlen, void *data  DBGPARAM);
void free_cent(dns_cent_t *cent  DBGPARAM);
void free_cent0(void *ptr);
void negate_cent(dns_cent_t *cent);
void del_cent(dns_cent_t *cent);

/* Because this is empty by now, it is defined as an empty macro to save overhead.*/
/*void free_rr(rr_bucket_t cent);*/
#define free_rr(x)

dns_cent_t *copy_cent(dns_cent_t *cent  DBGPARAM);

/* unsigned long get_serial(void); */

inline static int have_rr(dns_cent_t *cent, int tp)
{
	rr_set_t *rrset=cent->rr[tp-T_MIN];
	return rrset && rrset->rrs;
}

#endif
