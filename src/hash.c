/* hash.c - Manage hashes for cached dns records
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
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "hash.h"
#include "cache.h"
#include "error.h"
#include "helpers.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: hash.c,v 1.11 2001/05/22 18:05:02 tmm Exp $";
#endif

/* This is not a perfect hash, but I hope it holds. It is designed for 1024 hash
 * buckets, and hashes only strings with the allowed dns characters
 * [a-zA-Z0-9\-\.] = 64, but with case-insensitivity = 38
 * It is position-aware in a limited way. 
 * It is exactly seen a two-way hash: because I do not want to exaggerate
 * the hash buckets (i do have 1024), but I hash strings and string-comparisons
 * are expensive, I save another 32 bit hash in each hash element that is checked
 * before the string 
 * I hope not to have all too much collision concentration.
 *
 * The ip hash was removed. I don't think it concentrated the collisions too much.
 * If it does, the hash algorithm needs to be changed, rather than using another
 * hash.
 * Some measurements seem to indicate that the hash algorithm is doing reasonable well.
 */

unsigned char *posval=(unsigned char *)"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
#ifdef UNDERSCORE
"_"
#endif
;
unsigned char values[256];

/*
 * Make the conversion table for the dns hashes (character-to-number mapping).
 * Call this once before you use the hashes
 */
void mk_hash_ctable ()
{
	unsigned int i;
	memset(values,strlen((char *)posval),sizeof((char *)values));
	for (i=0;i<strlen((char *)posval);i++) {
		values[tolower(posval[i])]=i;
		values[toupper(posval[i])]=i;
	}
}

/*
 * Hash a dns name (dotted) to HASH_SZ bit.
 */
static long dns_shash(unsigned char *str)
{
	unsigned long acc,i;
	acc=0;
	for (i=0;i<strlen((char *)str);i++) {
		acc+=values[str[i]]<<(i%(HASH_SZ-5));
	}
	acc=(acc&HASH_BITMASK)+((acc&(~HASH_BITMASK))>>HASH_SZ);
	acc=(acc&HASH_BITMASK)+((acc&(~HASH_BITMASK))>>HASH_SZ);
#ifdef DEBUG_HASH
	printf("Diagnostic: dns hash for %s: %03lx\n",str,acc&HASH_BITMASK);
#endif
	return acc&HASH_BITMASK;
}

/*
 * Hash a dns name (dotted) to 32 bit.
 */
static unsigned long dns_rhash(unsigned char *str)
{
	unsigned long acc,i;
	acc=0;
	for (i=0;i<strlen((char *)str);i++) {
		acc+=values[str[i]]<<(i%25);
	}
#ifdef DEBUG_HASH
	printf("Diagnostic: dns rhash for %s: %04lx\n",str,acc);
#endif
	return acc;
}

/*
 * Initialize hash to hold a dns hash table
 */
void mk_dns_hash(dns_hash_t *hash)
{
	int i;
	for(i=0;i<HASH_NUM_BUCKETS;i++) 
		hash->buckets[i]=NULL;
}

/*
 * Add an entry to the hash. key is your key, data will be returned
 * by dns_lookup
 */
void add_dns_hash(dns_hash_t *hash,unsigned char *key, dns_cent_t *data) 
{
	int idx=dns_shash(key);
	dns_hash_ent_t *he;
	he=calloc(sizeof(dns_hash_ent_t),1);
	if (!he) {
		log_error("Out of memory.");
		pdnsd_exit();
	}
	he->next=hash->buckets[idx];
	he->rhash=dns_rhash(key);
	he->data=data;
	hash->buckets[idx]=he;
}

/*
 * Delete the first entry indexed by key from the hash. Returns the data field or NULL.
 * Since two cents are not allowed to be for the same host name, there will be only one.
 */
dns_cent_t *del_dns_hash(dns_hash_t *hash, unsigned char *key) 
{
	int idx=dns_shash(key);
	unsigned long rh=dns_rhash(key);
	dns_hash_ent_t **he,*hen;
	dns_cent_t *data;
	he=&hash->buckets[idx];
	while (*he) {
		if ((*he)->rhash==rh) {
			if (stricomp((char *)key,(char *)(*he)->data->qname)) {
				hen=*he;
				*he=(*he)->next;
				data=hen->data;
				free(hen);
				return data;
			}
		}
		he=(dns_hash_ent_t **)&(*he)->next;
	}
	return NULL;   /* not found */
}

/*
 * Lookup in the hash table for key. If it is found, return the data pointer as given by
 * add_dns_hash. If no entry is found, return 0.
 */
dns_cent_t *dns_lookup(dns_hash_t *hash, unsigned char *key)
{
	int idx=dns_shash(key);
	unsigned long rh=dns_rhash(key);
	dns_hash_ent_t *he;
	he=hash->buckets[idx];
	while (he) {
		if ((he)->rhash==rh) {
			if (stricomp((char *)key,(char *)he->data->qname))
				return he->data;
		}
		he=(dns_hash_ent_t *)he->next;
	}
	return NULL;   /* not found */
}

/*
 * Delete the whole hash table, freeing all memory
 */
void free_dns_hash(dns_hash_t *hash)
{
	int i;
	dns_hash_ent_t *he,*hen;
	for (i=0;i<HASH_NUM_BUCKETS;i++) {
		he=hash->buckets[i];
		while (he) {
			hen=he->next;
			free(he);
			he=hen;
		}
	}
}

/*
 * The following functions are for iterating over the hash.
 * fetch_first returns the data field of the first element (or NULL if there is none), and fills pos
 * for subsequent calls of fetch_next.
 * fetch_next returns the data field of the element after the element that was returned by the last
 * call with the same position argument (or NULL if there is none)
 *
 * Note that these are designed so that you may actually delete the elementes you retrieved from the hash.
 */
dns_cent_t *fetch_first(dns_hash_t *hash, dns_hash_pos_t *pos)
{
	for (pos->bucket=0;pos->bucket<HASH_NUM_BUCKETS;pos->bucket++) {
		if (hash->buckets[pos->bucket]) {
			pos->ent=hash->buckets[pos->bucket]->next;
			return hash->buckets[pos->bucket]->data;
		}
	}
	return NULL;
}

dns_cent_t *fetch_next(dns_hash_t *hash, dns_hash_pos_t *pos)
{
	dns_hash_ent_t *he;
	if (pos->ent) {
		he=pos->ent;
		pos->ent=pos->ent->next;
		return he->data;
	}
	pos->bucket++;
	for (;pos->bucket<HASH_NUM_BUCKETS;pos->bucket++) {
		if (hash->buckets[pos->bucket]) {
			pos->ent=hash->buckets[pos->bucket]->next;
			return hash->buckets[pos->bucket]->data;
		}
	}
	return NULL;
}

#ifdef DBGHASH
void dumphash(dns_hash_t *hash)
{
	int i, j;
	dns_hash_ent_t *he;
	
	for (i=0; i<HASH_NUM_BUCKETS; i++) {
		for (j=0, he=hash->buckets[i]; he; he=he->next, j++) ;
		DEBUG_MSG("bucket %d: %d entries\n", i, j);
	}
}
#endif
