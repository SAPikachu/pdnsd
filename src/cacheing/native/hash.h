/* hash.h - Manage hashes for cached dns records
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

/* $Id: hash.h,v 1.2 2001/04/30 15:34:32 tmm Exp $ */

#ifndef _HASH_H_
#define _HASH_H_
#include <config.h>
#include "../cache.h"

typedef struct {
	void          *next;
	unsigned long rhash; /* this is a better hash */
	dns_cent_t    *data;
} dns_hash_ent_t;

/* Redefine this if you want another hash size. Should work ;-). The number of hash buckets is computed as power of two;
 * so, eg HASH_SZ set to 10 yields 1024 hash rows (2^10 or 1<<10). Only powers of two are possible conveniently. 
 * If you modify HASH_NUM_BUCKETS, also change HASH_SZ! HASH_SZ may not be bigger than 32 (if you set it even close to
 * that value, you are nuts.)*/ 
#define HASH_NUM_BUCKETS 1024
#define HASH_SZ            10

#define HASH_BITMASK     (HASH_NUM_BUCKETS-1)

/*
 * The hash structures are the same for an ip and an dns hash, so we use
 * an additional element in debug mode to report misuse.
 */
typedef struct {
	dns_hash_ent_t *(buckets[HASH_NUM_BUCKETS]);
} dns_hash_t;

/* A type for position specification for fetch_first and fetch_next */
typedef struct {
	int            bucket;     /* bucket chain we are in */
	dns_hash_ent_t *ent;       /* entry */
} dns_hash_pos_t;

void mk_hash_ctable(void);
void mk_dns_hash(dns_hash_t *hash);
void add_dns_hash(dns_hash_t *hash,unsigned char *key, dns_cent_t *data);
dns_cent_t *del_dns_hash(dns_hash_t *hash, unsigned char *key);
dns_cent_t *dns_lookup(dns_hash_t *hash, unsigned char *key);
void free_dns_hash(dns_hash_t *hash);

dns_cent_t *fetch_first(dns_hash_t *hash, dns_hash_pos_t *pos);
dns_cent_t *fetch_next(dns_hash_t *hash, dns_hash_pos_t *pos);

#ifdef DBGHASH
void dumphash(dns_hash_t *hash);
#endif

#endif
