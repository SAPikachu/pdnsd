/* cache.h - Definitions for the dns cache
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

/* $Id: cache.h,v 1.7 2000/06/22 11:34:52 thomas Exp $ */

#ifndef _CACHE_H_
#define _CACHE_H_

#include "config.h"
#include "ipvers.h" 
#include <stdio.h>
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
	short            flags;
	unsigned long    serial;                  /* we use the serial to determine whether additional records belonged to one answer */
	rr_bucket_t      *rrs;
} rr_set_t;


typedef struct {
	unsigned short   rdlen;
/*	data (with length rdlen) follows here;*/
} rr_fbucket_t;

typedef struct {
	time_t           ttl;
	time_t           ts;
	short            flags;
} rr_fset_t;


typedef struct {
	unsigned char    *qname;                  /*Name of the query in dotted notation*/
	int              num_rr;                  /*The number of rrs. When this decreases to 0, the cent is deleted. */
	unsigned long    cs;                      /*size of the rrs*/
	rr_set_t         *(rr[T_NUM]);            /*The records. Use the type id-T_MIN as index, */
} dns_cent_t;

typedef struct {
	unsigned char    qlen;
/*      qname (with length qlen) follows here */
} dns_file_t;

typedef struct rr_lent_s {
	rr_set_t         *rrset;
	dns_cent_t       *cent;
	int              tp;
	struct rr_lent_s *next;
	struct rr_lent_s *prev;
} rr_lent_t;

/*
 * the flag values
 */
#define CF_NOPURGE     1       /* Do not purge this record */
#define CF_LOCAL       2       /* Local zone entry */
#define CF_NOAUTH      4       /* Non-authoritative record */
#define CF_NOCACHE     8       /* Only hold for the cache latency time period, then purge. Not really written to cache records, but used
			          by add_cent_rr */
#define CF_ADDITIONAL 16       /* This was fetched as an additional or "off-topic" record. */

#define CFF_NOINHERIT (CF_LOCAL | CF_NOAUTH | CF_ADDITIONAL) /* not to be inherited on requery */

/*
 * This is the time in secs any record remains at least in the cache before it is purged.
 * (exception is that the cache is full)
 */
#define CACHE_LAT 120

void init_cache(void);
void destroy_cache(void);
void read_disk_cache(void);
void write_disk_cache(void);

void report_cache_stat(FILE *f);

/*
 *  add_cache expects the dns_cent_t to be filled.
 */
void add_cache(dns_cent_t ent);
int have_cached(unsigned char *name);
dns_cent_t *lookup_cache(unsigned char *name);
void read_hosts(char *fn, unsigned char *rns, time_t ttl, int aliases);
int add_cache_rr_add(unsigned char *name, time_t ttl, time_t ts, short flags, int dlen, void *data, int tp, unsigned long serial);

int mk_flag_val(servparm_t *server);
int init_cent(dns_cent_t *cent, unsigned char *qname);
int add_cent_rr(dns_cent_t *cent, time_t ttl, time_t ts, short flags,int dlen, void *data, int tp);
void free_cent(dns_cent_t cent);

/* Because this is empty by now, it is defined as an empty macro to save overhead.*/
/*void free_rr(rr_bucket_t cent);*/
#define free_rr(x)

dns_cent_t *copy_cent(dns_cent_t *cent);
rr_bucket_t *copy_rr(rr_bucket_t *rr);

unsigned long get_serial(void);

#endif
