/* cache.c - Keep the dns caches.
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
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "cache.h"
#include "hash.h"
#include "conff.h"
#include "helpers.h"
#include "dns.h"
#include "error.h"
#include "debug.h"
#include "thread.h"
#include "ipvers.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: cache.c,v 1.37 2002/04/25 12:03:27 tmm Exp $";
#endif

/* CACHE STRUCTURE CHANGES IN PDNSD 1.0.0
 * Prior to version 1.0.0, the cache was managed at domain granularity (all records of a domain were handled as a unit),
 * which was suboptimal after the lean query feature and the additional record management were included.
 * From 1.0.0 on, the cache management was switched to act with RR set granularity. The API of the cache handlers was
 * slightly modified, in particular the rr_bucket_t was modified and some parameter list were changed. The cache
 * file format had to be changed and is incompatible now. This means that post-1.0.0p1 versions will not read the cache
 * files of older versions and vice versa. In addition, cache files from 1.0.0p5 on are incompatible to those of 1.0.0p1
 * to 1.0.0p4.  Better delete them before upgrading.
 * The "cent" lists common to old versions have vanished; the only access point to the cent's is the hash.
 * However, there are now double linked rrset lists. Thus, rrs can be acces through the hash or through the rrset lists.
 * The rrset list entries need some additional entries to manage the deletion from rrs lists as well as from the cents.
 *
 * Nearly all cache functions had to be changed significantly or even to be rewritten for that. Expect some beta time
 * because of that.
 * There are bonuses visible to the users resulting from this changes however: more consistent cache handling (under
 * some circumstances, rrs could be in the cache more than once) and reduced memory requirements, as no rr needs
 * to have stored its oname any more. There are more pointers however, and in some cases (CNAMES) the memory require-
 * ments for some records may increase. The total should be lower, however.
 *
 * RRSET_L LIST STRUCTURE:
 * The rrset_l rrset list is a simple double-linked list. The oldest entries are at the first positions, the list is sorted
 * by age in descending order. Search is done only on insert.
 * The rationale for this form is:
 * - the purging operation needs to be fast (this way, the first records are the oldest and can easily be purged)
 * - the append operation is common and needs to be fast (in normal operation, an appended record was just retrieved
 *   and therefore is the newest, so it can be appended at the end of the list without search. Only in the case of
 *   reading a disk cache file, searches are necessary)
 * The rrset list is excusively used for purging purposes.
 *
 * THE DISK CACHE FILES:
 * The disk cache file consists of cent's, i.e. structures for every known hostnames with a header and rrs attached to it.
 * Therefore, the rr's are not ordered by their age and a search must be performed to insert the into the rr_l in the
 * right positions. This operations has some costs (although not all too much), but the other way (rrs stored in order
 * of their age and the cent headers separated from them), the rrs would need to be attached to the cent headers, which
 * would be even more costly, also in means of disk space.
 *
 * CHANGES AFTER 1.0.0p1
 * In 1.0.0p5, the cache granularity was changed from rr level to rr set level. This was done because rfc2181 demands
 * rr set consistency constraints on rr set level and if we are doing so we can as well save space (and eliminate some
 * error-prone algorithms).
 *
 * CHANGES FOR 1.1.0p1
 * In this version, negative cacheing support was introduced. Following things were changed for that:
 * - new members ts, ttl and flags in dns_cent_t and dns_file_t
 * - new cacheing flag CF_NEGATIVE
 * - all functions must accept and deal correctly with empty cents with DF_NEGATIVE set.
 * - all functions must accept and deal correctly with empty rrsets with CF_NEGATIVE set.
 */

/*
 * This is the size the memory cache may exceed the size of the permanent cache
 */
#define MCSZ 10240

rr_lent_t *rrset_l=NULL;
rr_lent_t *rrset_l_tail=NULL;

/*
 * We do not count the hash table sizes here. Those are very small compared
 * to the cache entries.
 */
volatile long cache_size=0;
volatile long ent_num=0;

volatile int cache_w_lock=0;
volatile int cache_r_lock=0;

pthread_mutex_t lock_mutex = PTHREAD_MUTEX_INITIALIZER;
/*
 * These are condition variables for lock coordination, so that normal lock
 * routines do not need to loop. Basically, a process wanting to acquire a lock
 * tries first to lock, and if the lock is busy, sleeps on one of the conds.
 * If the r lock count has gone to zero one process sleeping on the rw cond
 * will be awankened.
 * If the rw lock is lifted, either all threads waiting on the r lock or one
 * thread waiting on the rw lock is/are awakened. This is determined by policy.
 */
pthread_cond_t  rw_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t  r_cond = PTHREAD_COND_INITIALIZER;

/* This is to suspend the r lock to avoid lock contention by reading threads */
volatile int r_pend=0;
volatile int rw_pend=0;
volatile int r_susp=0;

/* This threshold is used to temporarily suspend r locking to give rw locking
 * a chance. */
#define SUSP_THRESH(r_pend) (r_pend/2+2)

/*
 * This is set to 1 once the lock is intialized. This must happen before we get
 * multiple threads.
 */
volatile int use_cache_lock=0;


#ifdef ALLOC_DEBUG
#define cache_free(ptr)		{ if (dbg) pdnsd_free(ptr); else free(ptr); }
#define cache_malloc(sz)	((dbg)?(pdnsd_malloc(sz)):(malloc(sz)))
#define cache_calloc(n,sz)	((dbg)?(pdnsd_calloc(n,sz)):(calloc(n,sz)))
#define cache_realloc(ptr,sz)	((dbg)?(pdnsd_realloc(ptr,sz)):(realloc(ptr,sz)))
#else
#define cache_free(ptr)		{free(ptr);}
#define cache_malloc(sz)	(malloc(sz))
#define cache_calloc(n,sz)	(calloc(n,sz))
#define cache_realloc(ptr,sz)	(realloc(ptr,sz))
#endif

/*
 * Prototypes for internal use
 */
static void purge_cache(long sz, int lazy);
static void del_cache_ent(dns_cent_t *cent);
static void remove_rrl(rr_lent_t *le  DBGPARAM);

/*
 * Locking functions.
 */

/*
 * Lock/unlock cache for reading. Concurrent reads are allowed, while writes are forbidden.
 * DO NOT MIX THE LOCK TYPES UP WHEN LOCKING/UNLOCKING!
 *
 * We use a mutex to lock the access to the locks ;-).
 * This is because we do not allow read and write to interfere (for which a normal mutex would be
 * fine), but we also want to allow concurrent reads.
 * We use condition variables, and readlock contention protection.
 */
static void lock_cache_r(void)
{
	if (!use_cache_lock)
		return;
	pthread_mutex_lock(&lock_mutex);
	r_pend++;
	while(((rw_pend>SUSP_THRESH(r_pend))?(r_susp=1):r_susp) || cache_w_lock) {
		/* This will unlock the mutex while sleeping and relock it before exit */
		pthread_cond_wait(&r_cond, &lock_mutex);
	}
	cache_r_lock++;
	r_pend--;
	pthread_mutex_unlock(&lock_mutex);
}

static void unlock_cache_r(void)
{
	if (!use_cache_lock)
		return;
	pthread_mutex_lock(&lock_mutex);
	if (cache_r_lock>0)
		cache_r_lock--;
	/* wakeup threads waiting to write */
	if (!cache_r_lock)
		pthread_cond_signal(&rw_cond);
	pthread_mutex_unlock(&lock_mutex);
}

/*
 * Lock/unlock cache for reading and writing. Concurrent reads and writes are forbidden.
 * Do this only if you actually modify the cache.
 * DO NOT MIX THE LOCK TYPES UP WHEN LOCKING/UNLOCKING!
 * (cant say it often enough)
 */
static void lock_cache_rw(void)
{
	if (!use_cache_lock)
		return;
	pthread_mutex_lock(&lock_mutex);
	rw_pend++;
	while(cache_w_lock || cache_r_lock) {
		/* This will unlock the mutex while sleeping and relock it before exit */
		pthread_cond_wait(&rw_cond, &lock_mutex);
	}
	cache_w_lock=1;
	rw_pend--;
	pthread_mutex_unlock(&lock_mutex);
}

static void unlock_cache_rw(void)
{
	if (!use_cache_lock)
		return;
	pthread_mutex_lock(&lock_mutex);
	cache_w_lock=0;
	/* always reset r suspension (r locking code will set it again) */
	r_susp=0;
	/* wakeup threads waiting to read or write */
	if (r_pend==0 || rw_pend>SUSP_THRESH(r_pend))
		pthread_cond_signal(&rw_cond); /* schedule another rw proc */
	else
		pthread_cond_broadcast(&r_cond); /* let 'em all read */
	pthread_mutex_unlock(&lock_mutex);
}

/* These are a special version of the ordinary read lock functions. The lock "soft" to avoid deadlocks: they will give up
 * after a certain number of bad trials. You have to check the exit status though.
 * To avoid blocking mutexes, we cannot use condition variables here. Never mind, these are only used on
 * exit. */
static int softlock_cache_r(void)
{
	if (!use_cache_lock)
		return 0;
	{
		int lk=0,tr=0;

		for(;;) {
			if (!softlock_mutex(&lock_mutex))
				return 0;
			if(!cache_w_lock) {
				lk=1;
				cache_r_lock++;
			}
			pthread_mutex_unlock(&lock_mutex);
			if (lk) break;
			if (++tr>=SOFTLOCK_MAXTRIES)
				return 0;
			usleep_r(1000); /*give contol back to the scheduler instead of hammering the lock close*/
		}
	}
	return 1;
}

/* On unlocking, we do not wake others. We are about to exit! */
static int softunlock_cache_r(void)
{
	if (!use_cache_lock)
		return 0;
	if (!softlock_mutex(&lock_mutex))
		return 0;
	if (cache_r_lock>0)
		cache_r_lock--;
	pthread_mutex_unlock(&lock_mutex);
	return 1;
}

static int softlock_cache_rw(void)
{
	if (!use_cache_lock)
		return 0;
	{
		int lk=0,tr=0;

		for(;;) {
			if (!softlock_mutex(&lock_mutex))
				return 0;
			if (!(cache_w_lock || cache_r_lock)) {
				lk=1;
				cache_w_lock=1;
			}
			pthread_mutex_unlock(&lock_mutex);
			if(lk) break;
			if (++tr>=SOFTLOCK_MAXTRIES)
				return 0;
			usleep_r(1000); /*give contol back to the scheduler instead of hammering the lock close*/
		}
	}
	return 1;
}

static int softunlock_cache_rw(void)
{
	if (!use_cache_lock)
		return 0;
	if (!softlock_mutex(&lock_mutex))
		return 0;
	cache_w_lock=0;
	pthread_mutex_unlock(&lock_mutex);
	return 1;
}

/*
 * Serial numbers: Serial numbers are used when additional records are added to the cache: serial numbers are unique to each
 * query, so we can determine whether data was added by the query just executed (records can coexist) or not (records must
 * be replaced). A serial of 0 is special and will not be used by any query. All records added added authoritatively (as
 * chunk) or read from a file can have no query in process and therefore have serial 0, which is != any other serial.
 */

unsigned long l_serial=1;

unsigned long get_serial()
{
	unsigned long rv;
	lock_cache_rw();
	rv=l_serial++;
	unlock_cache_rw();
	return rv;
}

/*
 * Cache/cent handlers
 */

/* Initialize the cache. Call only once. */
void init_cache()
{
	mk_hash_ctable();
	mk_dns_hash();
}

/* Initialize the cache lock. Call only once. */
/* void init_cache_lock()
{

	use_cache_lock=1;
} */

/* Delete the cache. Call only once */
void destroy_cache()
{
	dns_cent_t *ce;
	dns_hash_pos_t pos;

	/* lock the cache, in case that any thread is still accessing. */
	if(!softlock_cache_rw()) {
		log_error("Lock failed; could not destroy cache on exit.");
		return;
	}
	ce=fetch_first(&pos);
	while (ce) {
		del_cache_ent(ce);
		ce=fetch_next(&pos);
	}
	free_dns_hash();

#if 0
TARGET!=TARGET_LINUX
	/* under Linux, this frees no resources but may hang on a crash */
	pthread_mutex_destroy(&lock_mutex);
	pthread_cond_destroy(&rw_cond);
	pthread_cond_destroy(&r_cond);
#endif
}

/* Make a flag value for a dns_cent_t (dns cache entry) from a server record */
int mk_flag_val(servparm_t *server)
{
	int fl=0;
	if (!server->purge_cache)
		fl|=CF_NOPURGE;
	if (server->nocache)
		fl|=CF_NOCACHE;
	return fl;
}

/* Initialize a dns cache record (dns_cent_t) with the query name (in
 * dotted notation, use rhn2str), a flag value, a timestamp indicating
 * the time the query was done, and a TTL. The timestamp and TTL
 * are only used if DF_NEGATIVE is set in the flags. Otherwise,
 * the timestamps of the individual records are used. DF_NEGATIVE
 * is used for whole-domain negative cacheing.
 * By convention, the ttl should be set to 0, and the ttl should
 * be set correctly when DF_NEGATIVE is not set. */
int init_cent(dns_cent_t *cent, unsigned char *qname, short flags, time_t ts, time_t ttl  DBGPARAM)
{
	int i;
	size_t namesz=strlen(qname)+1;
	/* This mimics strdup, which is not really portable unfortunately */
	cent->qname=cache_malloc(namesz);
	if (cent->qname == NULL)
		return 0;
	strcpy(cent->qname,qname);
	cent->num_rrs=0;
	cent->cs=sizeof(dns_cent_t)+namesz;
	cent->flags=flags;
	cent->ts=ts;
	cent->ttl=ttl;
	cent->lent=NULL;
	for(i=0;i<T_NUM;i++)
		cent->rr[i]=NULL;
	return 1;
}

/*
 * Create a cent using the given values.
 */
rr_bucket_t *create_rr(int dlen, void *data  DBGPARAM)
{
	rr_bucket_t *rrb;
	rrb=(rr_bucket_t *)cache_malloc(sizeof(rr_bucket_t)+dlen);
	if (rrb == NULL)
		return NULL;
	rrb->next=NULL;

	rrb->rdlen=dlen;
	memcpy(rrb+1,data,dlen);
	return rrb;
}

/*
 * Adds an empty rrset_t with the requested data to a cent. This is exactly what you need to
 * do to create a negatively cached cent.
 */
int add_cent_rrset(dns_cent_t *cent, int tp, time_t ttl, time_t ts, int flags, unsigned long serial  DBGPARAM)
{
	rr_set_t *rrset=cache_malloc(sizeof(rr_set_t));
	cent->rr[tp-T_MIN]=rrset;
	if (!rrset)
		return 0;
	rrset->lent=NULL;
	if (flags&CF_NOCACHE) {
		flags &= ~CF_NOCACHE;
		ttl=0;
	}
	else {
		if(ttl<global.min_ttl)
			ttl=global.min_ttl;
		else if(ttl>global.max_ttl)
			ttl=global.max_ttl;
	}

	rrset->ttl=ttl;
	rrset->ts=ts;
	rrset->flags=flags;
	rrset->serial=serial;
	rrset->rrs=NULL;
	cent->cs += sizeof(rr_set_t);
	cent->num_rrs++;
	return 1;
}

/*
 * Adds a rr record (usually prepared by create_rr) to a cent. For cache.c internal use.
 * Frees the rr if not actually used.
 */
static int add_cent_rr_int(dns_cent_t *cent, rr_bucket_t *rr, int tp, time_t ttl, time_t ts, int flags, unsigned long serial  DBGPARAM)
{
	int rv=0;
	rr_set_t *rrset;
	if ((cent->flags&DF_LOCAL) && !(flags&CF_LOCAL)) {
		/* ignore. Local has precedence. */
		rv=1;
		goto cleanup_return;
	}
	if (!cent->rr[tp-T_MIN]) {
		if (!add_cent_rrset(cent, tp, ttl, ts, flags, serial  DBGARG))
			goto cleanup_return;
	}
	/* If we add a record, this is not negative any more. */
	if (cent->flags&DF_NEGATIVE) {
		cent->flags &= ~DF_NEGATIVE;
		cent->ttl=0;
		/* need to remove the cent from the lent list. */
		if (cent->lent) {
			remove_rrl(cent->lent  DBGARG);
			cent->lent=NULL;
		}
	}

	cent->cs += sizeof(rr_bucket_t)+rr->rdlen;
	/* do the linking work */
	rrset=cent->rr[tp-T_MIN];
	rr->next=rrset->rrs;
	rrset->rrs=rr;
#if DEBUG>0
	if (rrset->flags&CF_NEGATIVE)
		DEBUG_MSG("Tried to add rr to a rrset with CF_NEGATIVE set! flags=%i\n",rrset->flags);
#endif
	return 1;
 cleanup_return:
	free_rr(*rr);
	free(rr);
	return rv;
}


/* Add an rr to a cache entry, giving the ttl, the data length, the rr type (tp)
 * and a pointer to the data. A record is allocated, and the data is copied into
 * it. Do this for all rrs in a cache entry.
 */
int add_cent_rr(dns_cent_t *cent, time_t ttl, time_t ts, short flags, int dlen, void *data, int tp  DBGPARAM)
{
	rr_bucket_t *rrb;
	/* OK, some stupid nameservers feel inclined to return the same address twice. Grmbl... */
	if (cent->rr[tp-T_MIN]) {
		rrb=cent->rr[tp-T_MIN]->rrs;
		while (rrb) {
			if (rrb->rdlen==dlen && memcmp(rrb+1,data,dlen)==0)
				return 1;
			rrb=rrb->next;
		}
	}
	if (!(rrb=create_rr(dlen,data  DBGARG)))
		return 0;
	return add_cent_rr_int(cent,rrb,tp,ttl,ts,flags,0  DBGARG);
}

/* Free a complete rrset including all memory. Returns the size of the memory freed */
static int del_rrset(rr_set_t *rrs  DBGPARAM)
{
	int rv=sizeof(rr_set_t);
	rr_bucket_t *rrb,*rrn;

	if(rrs->lent) remove_rrl(rrs->lent  DBGARG);
	rrb=rrs->rrs;
	while (rrb) {
		rv+=sizeof(rr_bucket_t)+rrb->rdlen;
		rrn=rrb->next;
		free_rr(*rrb);
		cache_free(rrb);
		rrb=rrn;
	}
	cache_free(rrs);
	return rv;
}

/* Remove a complete rrset from a cent, freeing the memory.
   Returns the size of the memory freed */
static int del_cent_rrset(dns_cent_t *cent, int tp  DBGPARAM)
{
	int rv=0;
	rr_set_t *rrs=cent->rr[tp-T_MIN];
	if(rrs) {
		rv= del_rrset(rrs  DBGARG);
		cent->num_rrs--;
		cent->cs -= rv;
		cent->rr[tp-T_MIN]=NULL;
	}
	return rv;
}

/* Free the pointers cointained in an rr record. If the rr record is on the heap,
 * don't forget to delete itself. This is done extra mainly for extensibility
 * -- This is not here any more. The definition is actually an empty macro in
 * cache.h.
 */
/*
void free_rr(rr_bucket_t rr)
{
}
*/

/* Free all data referred by a cache entry. */
void free_cent(dns_cent_t *cent  DBGPARAM)
{
	int i;
	cache_free(cent->qname);
	if(cent->lent)
		remove_rrl(cent->lent  DBGARG);
	for (i=0;i<T_NUM;i++) {
		rr_set_t *rrs=cent->rr[i];
		if (rrs) del_rrset(rrs  DBG0);
	}
}

inline static time_t get_rrlent_ts(rr_lent_t *le)
{
	return (le->rrset)?(le->rrset->ts):(le->cent->ts);
}

/* insert a rrset into the rr_l list. This modifies the rr_set_t if rrs is not NULL!
 * The rrset address needs to be constant afterwards.
 * Call with locks applied. */
static rr_lent_t *insert_rrl(rr_set_t *rrs, dns_cent_t *cent, int tp)
{
	time_t ts;
	rr_lent_t *le,*ne=malloc(sizeof(rr_lent_t));

	if (!ne) return NULL;
	ne->rrset=rrs;
	ne->cent=cent;
	ne->tp=tp;
	ne->next=NULL;
	ne->prev=NULL;

	/* Since the append at the and is a very common case (and we want this case to be fast), we search back-to-forth.
	 * Since rr_l is a list and we don't really have fast access to all elements, we do not perform an advanced algorithm
	 * like binary search.*/
	ts=get_rrlent_ts(ne);
	le=rrset_l_tail;
	while (le) {
		if (ts>=get_rrlent_ts(le)) goto found;
		le=le->prev;
	}
	/* not found, so it needs to be inserted at the start of the list. */
	ne->next=rrset_l;
	if (rrset_l)
		rrset_l->prev=ne;
	else
		rrset_l_tail=ne;
	rrset_l=ne;
	goto finish;
 found:
	ne->next=le->next;
	ne->prev=le;
	if (le->next)
		le->next->prev=ne;
	else
		rrset_l_tail=ne;
	le->next=ne;
 finish:
	if (rrs)
		rrs->lent=ne;
	else
		cent->lent=ne;

	return ne;
}

/* Remove a rr from the rr_l list. Call with locks applied. */
static void remove_rrl(rr_lent_t *le  DBGPARAM)
{
	rr_lent_t *next=le->next,*prev=le->prev;
	if (next)
		next->prev=prev;
	else
		rrset_l_tail=prev;
	if (prev)
		prev->next=next;
	else
		rrset_l=next;
	cache_free(le);
}

/* Copy a rr_bucket_t into newly allocated memory */
inline static rr_bucket_t *copy_rr(rr_bucket_t *rr  DBGPARAM)
{
	rr_bucket_t *rrn;
	rrn=cache_malloc(sizeof(rr_bucket_t)+rr->rdlen);
	if (rrn == NULL)
		return NULL;
	memcpy(rrn,rr,sizeof(rr_bucket_t)+rr->rdlen);
	rrn->next=NULL;
	return rrn;
}

/* Copy a cache entry into newly allocated memory */
dns_cent_t *copy_cent(dns_cent_t *cent  DBGPARAM)
{
	dns_cent_t *copy;
	int i;

	/*
	 * We do not debug cache internals with it, as mallocs seem to be
	 * "lost" when they enter the cache for a longer time.
	 */
	if (!(copy=cache_malloc(sizeof(dns_cent_t))))
		return NULL;
	*copy=*cent;

	if (!(copy->qname=cache_malloc(strlen(cent->qname)+1)))
		goto free_return_null;

	strcpy(copy->qname,cent->qname);
	copy->lent=NULL;

	for (i=0;i<T_NUM;i++)
		copy->rr[i]=NULL;

	for (i=0;i<T_NUM;i++) {
		rr_set_t *rrset=cent->rr[i];
		if (rrset) {
			rr_set_t *rrsc=cache_malloc(sizeof(rr_set_t));
			rr_bucket_t *rr,**rrp;
			copy->rr[i]=rrsc;
			if (!rrsc)
				goto free_cent_return_null;
			*rrsc=*rrset;
			rrsc->lent=NULL;
			rrp=&rrsc->rrs;
			rr=rrset->rrs;
			while(rr) {
				rr_bucket_t *rrc=copy_rr(rr  DBGARG);
				*rrp=rrc;
				if (!rrc) goto free_cent_return_null;
				rrp=&rrc->next;
				rr=rr->next;
			}
		}
	}
	return copy;

 free_cent_return_null:
	free_cent(copy  DBGARG);
 free_return_null:
	cache_free(copy);
	return NULL;
}

/*
 * Remove all timed out entries of a given rr row.
 * Follow some rules based on flags etc.
 * This will either delete the whole rrset, or will leave it as a whole (RFC2181 seems to
 * go in that direction)
 * This was pretty large once upon a time ;-), but now, since we operate in rrsets, was
 * shrinked drastically.
 * If the record is in the cache, we need rw-locks applied.
 * Substracts the size of the freed memory from cache_size.
 */
static void purge_rrset(dns_cent_t *cent, int tp)
{
	rr_set_t *rrs=cent->rr[tp-T_MIN];
	if (rrs && !(rrs->flags&CF_NOPURGE || rrs->flags&CF_LOCAL) &&
	    rrs->ts+rrs->ttl+CACHE_LAT<time(NULL)) {
		/* well, it must go. */
		cache_size -= del_cent_rrset(cent,tp  DBG0);
	}
}

/*
 * Purge a cent, deleting timed-out rrs (following the constraints noted in "purge_rrset").
 * Since the cent may actually become empty and be deleted, you may not use it after this call until
 * you refetch its address from the hash (if it is still there).
 * Substracts the size of the freed memory from cache_size.
 * Force means to delete the cent even when it's not timed out.
 * Returns 1 if the cent itself has been deleted.
 */
static int purge_cent(dns_cent_t *cent, int delete)
{
	int i;

	for (i=T_MIN;i<=T_MAX;i++)
		purge_rrset(cent,i);
	/* if the record was purged empty, delete it from the cache. */
	if (delete && cent->num_rrs==0 && (!(cent->flags&DF_NEGATIVE) ||
					   (!(cent->flags&DF_LOCAL) && (time(NULL)-cent->ts>cent->ttl+CACHE_LAT)))) {
		del_cache_ent(cent); /* this will subtract the cent's left size from cache_size */
		return 1;
	}
	return 0;
}

/*
 * Bring cache to a size below or equal the cache size limit (sz). There are two strategies:
 * - for cached sets with CF_NOPURGE not set: delete if timed out
 * - additional: delete oldest sets.
 */
static void purge_cache(long sz, int lazy)
{
	rr_lent_t *le;

	/* Walk the cache list from the oldest entries to the newest, deleting timed-out
	 * records.
	 * XXX: We walk the list a second time if this did not free up enough space - this
	 * should be done better. */
	le=rrset_l;
	while (le && (!lazy || cache_size>sz)) {
		/* Note by Paul Rombouts:
		 * If data integrity is ensured, at most one node is removed from the rrset_l
		 * per iteration, and this node is the one referenced by le. */
		rr_lent_t *next=le->next;
		if (!((le->rrset && (le->rrset->flags&CF_LOCAL)) ||
		      le->cent->flags&DF_LOCAL)) {
			dns_cent_t *ce = le->cent;
			if (le->rrset)
				purge_rrset(ce, le->tp);
			/* Side effect: if purge_rrset called del_cent_rrset then le has been freed.
			 * ce, however, is still guaranteed to be valid. */
			if (ce->num_rrs==0 && (!(ce->flags&DF_NEGATIVE) ||
					       (!(ce->flags&DF_LOCAL) && (time(NULL)-ce->ts>ce->ttl+CACHE_LAT))))
				del_cache_ent(ce);
		}
		le=next;
	}
	if (cache_size<=sz)
		return;
	/* we are still above the desired cache size. Well, delete records from the oldest to
	 * the newest. This is the case where nopurge records are deleted anyway. Only local
	 * records are kept in any case.*/
	le=rrset_l;
	while (le && cache_size>sz) {
		rr_lent_t *next=le->next;
		if (!((le->rrset && (le->rrset->flags&CF_LOCAL)) ||
		      le->cent->flags&CF_LOCAL)) {
			dns_cent_t *ce = le->cent;
			if (le->rrset)
				cache_size -= del_cent_rrset(ce, le->tp  DBG0);
			/* this will also delete negative cache entries */
			if (ce->num_rrs==0)
				del_cache_ent(ce);
		}
		le=next;
	}
}

#define log_warn_read_error \
        log_warn("%s encountered while reading disk cache file at %s, line %d", \
        ferror(f)?"Error":feof(f)?"EOF":"Incomplete item", __FILE__, __LINE__);

/*
 * Load cache from disk and rebuild the hash tables.
 */
void read_disk_cache()
{
	/* The locks are done when we add items. */
	int i;
	dns_file_t fe;
	dns_cent_t ce;
	int dtsz=512;
	rr_fset_t sh;
	rr_fbucket_t rr;
	unsigned char *data;
	unsigned char num_rr;
	long cnt;
	FILE *f;
	unsigned char nb[256];

	char path[strlen(global.cache_dir)+sizeof("/pdnsd.cache")];

	stpcpy(stpcpy(path,global.cache_dir),"/pdnsd.cache");

	if (!(f=fopen(path,"r"))) {
		log_warn("Could not open disk cache file %s: %s",path,strerror(errno));
		return;
	}

	if (!(data = malloc(dtsz))) {
		goto fclose_exit;
	}

	if (fread(&cnt,sizeof(cnt),1,f)!=1) {
		log_warn_read_error
		goto free_data_fclose;
	}

	for(;cnt>0;cnt--) {
		if (fread(&fe,sizeof(dns_file_t),1,f)!=1) {
			log_warn_read_error
			goto free_data_fclose;
		}
		if (fe.qlen) {
			if (fread(nb,fe.qlen,1,f)!=1) {
				log_warn_read_error
				goto free_data_fclose;
			}
		}
		nb[fe.qlen]='\0';
		if (!init_cent(&ce, nb, fe.flags, fe.ts, fe.ttl  DBG0)) {
			goto free_data_fclose_exit;
		}
		/* now, read the rr's */
		for (i=0;i<T_NUM;i++) {
			if (fread(&num_rr,sizeof(num_rr),1,f)!=1) {
				log_warn_read_error
				goto free_cent_data_fclose;
			}
			if (num_rr) {
				if (fread(&sh,sizeof(sh),1,f)!=1) {
					log_warn_read_error
					goto free_cent_data_fclose;
				}
				/* Add the rrset header in any case (needed for negative cacheing */
				if(!add_cent_rrset(&ce, i+T_MIN, sh.ttl, sh.ts, sh.flags, 0  DBG0)) {
					goto free_cent_data_fclose_exit;
				}
				for (;num_rr>1;num_rr--) {
					if (fread(&rr,sizeof(rr),1,f)!=1) {
						log_warn_read_error
						goto free_cent_data_fclose;
					}
					if (rr.rdlen>dtsz) {
						unsigned char *tmp;
						dtsz=rr.rdlen;
						tmp=realloc(data,dtsz);
						if (!tmp) {
							goto free_cent_data_fclose_exit;
						}
						data=tmp;
					}
					if (fread(data,rr.rdlen,1,f)!=1) {
						log_warn_read_error
						goto free_cent_data_fclose;
					}
					if (!add_cent_rr(&ce,sh.ttl,sh.ts,sh.flags,rr.rdlen,data,i+T_MIN  DBG0)) {
						goto free_cent_data_fclose_exit;
					}
				}
			}
		}
		add_cache(&ce);
		free_cent(&ce  DBG0);
	}
#ifdef DBGHASH
	free(data);
	fclose(f);
	dumphash();
	return;
#else
	goto free_data_fclose;
#endif

 free_cent_data_fclose:
	free_cent(&ce  DBG0);
 free_data_fclose:
	free(data);
	fclose(f);
	return;

 free_cent_data_fclose_exit:
	free_cent(&ce  DBG0);
 free_data_fclose_exit:
	free(data);
 fclose_exit:
	fclose(f);
	log_error("Out of memory in reading cache file. Exiting.");
	pdnsd_exit();
}

/* write an rr to the file f */
static int write_rrset(rr_set_t *rrs, FILE *f)
{
	rr_bucket_t *rr;
	rr_fset_t sh;
	rr_fbucket_t rf;
	unsigned char num_rr=0;  /* 0 means nothing, 1 means header only, 1 means header + 1 records ... */

	if(rrs && !(rrs->flags&CF_LOCAL)) {
	  rr=rrs->rrs;
	  num_rr=1;
	  while(rr && num_rr<255) {++num_rr; rr=rr->next;}
	}

	if (fwrite(&num_rr,sizeof(num_rr),1,f)!=1) {
		log_error("Error while writing disk cache: %s", strerror(errno));
		return 0;
	}

	if (!num_rr)
		return 1;

	sh.ttl=rrs->ttl;
	sh.ts=rrs->ts;
	sh.flags=rrs->flags;
	if (fwrite(&sh,sizeof(sh),1,f)!=1) {
		log_error("Error while writing disk cache: %s", strerror(errno));
		return 0;
	}
	rr=rrs->rrs;
	/* We only write a maximum of 256 of a kind (type) for one domain. This would be already overkill and probably does not happen.
	 * we want to get along with only one char, because most rr rows are empty (even more with DNS_NEW_RRS), and so the usage
	 * of greater data types would have significant impact on the cache file size. */

	for(;num_rr>1;--num_rr) {
		rf.rdlen=rr->rdlen;
		if (fwrite(&rf,sizeof(rf),1,f)!=1 || fwrite((rr+1),rf.rdlen,1,f)!=1) {
			log_error("Error while writing disk cache: %s", strerror(errno));
			return 0;
		}
		rr=rr->next;
	}

	return 1;
}


/*
 * Write cache to disk on termination. The hash table is lost and needs to be regenerated
 * on reload.
 *
 * The locks are not very fine grained here, but I don't think this needs fixing as this routine 
 * is only called on exit.
 *
 */
void write_disk_cache()
{
	int j;
	dns_cent_t *le;
	long en=0;
	dns_hash_pos_t pos;
	FILE *f;

	char path[strlen(global.cache_dir)+sizeof("/pdnsd.cache")];

	stpcpy(stpcpy(path,global.cache_dir),"/pdnsd.cache");

	DEBUG_MSGC("Writing cache to %s\n",path);

	if (!softlock_cache_rw()) {
		goto lock_failed;
	}
	/* purge cache down to allowed size*/
	purge_cache((long)global.perm_cache*1024, 0);
	if (!softunlock_cache_rw()) {
		goto lock_failed;
	}

	if (!softlock_cache_r()) {
		goto lock_failed;
	}

	if (!(f=fopen(path,"w"))) {
		log_warn("Could not open disk cache file %s: %s",path,strerror(errno));
		goto softunlock_return;
	}

	le=fetch_first(&pos);
	while (le) {
		/* count the rr's */
		for (j=0;j<T_NUM;j++) {
			if (le->rr[j] && !(le->rr[j]->flags&CF_LOCAL)) {
				++en;
				break;
			}
		}
		le=fetch_next(&pos);
	}
	if (fwrite(&en,sizeof(en),1,f)!=1) {
		log_error("Error while writing disk cache: %s", strerror(errno));
		goto fclose_unlock;
	}

	le=fetch_first(&pos);
	while (le) {
		/* now, write the rr's */
		for (j=0;j<T_NUM;j++) {
			if (le->rr[j] && !(le->rr[j]->flags&CF_LOCAL)) {
				goto write_rrs;
			}
		}
		goto next_le;
	       write_rrs:
		{
			dns_file_t df;
			df.qlen=strlen(le->qname);
			df.flags=le->flags;
			df.ts=le->ts;
			df.ttl=le->ttl;
			if (fwrite(&df,sizeof(df),1,f)!=1 ||
			    fwrite(le->qname,df.qlen,1,f)!=1) {
				log_error("Error while writing disk cache: %s", strerror(errno));
				goto fclose_unlock;
			}

			for (j=0;j<T_NUM;j++) {
				if (!write_rrset(le->rr[j],f)) {
					goto fclose_unlock;
				}
			}
		}
	       next_le:
		le=fetch_next(&pos);
	}
#if DEBUG > 0
	fclose(f);
	softunlock_cache_r();
	DEBUG_MSGC("Finished writing cache to disk.\n");
	return;
#endif
 fclose_unlock:
	fclose(f);
 softunlock_return:
	softunlock_cache_r();
	return;

 lock_failed:
	crash_msg("Lock failed; could not write disk cache.");
}

/*
 * Conflict Resolution.
 * The first function is the actual checker; the latter two are wrappers for the respective
 * function for convenience only.
 *
 * We check for conflicts by checking the new data rrset by rrset against the cent.
 * This is not bad when considering that new records are hopefully consistent; if they are not,
 * we might end up deleteing too much of the old data, which is probably added back through the
 * new query, though.
 * Having checked additions rrset by rrset, we are at least sure that the resulting record is OK.
 * cr_check_add returns 1 if the addition is OK, 0 otherwise.
 * This is for records that are already in the cache!
 */
static int cr_check_add(dns_cent_t *cent, int tp, time_t ttl, time_t ts, int flags)
{
	time_t nttl = 0;
	struct rr_infos *rri = &rr_info[tp-T_MIN];

	if (flags & CF_NEGATIVE)
		return 1;		/* no constraints here. */

	if (!(flags & CF_LOCAL)) {
		int i, ncf = 0, olda = 0;
		for (i = 0; i < T_NUM; i++) {
			rr_set_t *rrs=cent->rr[i];
			/* Should be symmetric; check both ways anyway. */
			if (rrs && !(rrs->flags & CF_NEGATIVE) &&
			    ((rri->class & rr_info[i].excludes) ||
			    (rri->excludes & rr_info[i].class))) {
				time_t rttl;
				ncf++;
				rttl = rrs->ttl + rrs->ts - time(NULL);
				nttl += rttl > 0 ? rttl : 0;
				if (rrs->flags & CF_LOCAL) {
					olda = 1;
					break;
				}
			}
		}
		if (olda)	/* old was authoritative */
			return 0;
		if (ncf == 0)	/* no conflicts */
			return 1;
		/* Medium ttl of conflicting records */
		nttl /= ncf;
	}
	if ((flags & CF_LOCAL) || ttl > nttl) {
		int i;
		/* remove the old records, so that the new one can be added */
		for (i = 0; i < T_NUM; i++) {
			rr_set_t *rrs=cent->rr[i];
			/* Should be symmetric; check both ways anyway. */
			if (rrs && !(rrs->flags & CF_NEGATIVE) &&
			    ((rri->class & rr_info[i].excludes) ||
			    (rri->excludes & rr_info[i].class))) {
				del_cent_rrset(cent,i+T_MIN  DBG0);
			}
		}
		return 1;
	}
	/* old records precede */
	return 0;
}


/*
 * Add a ready build dns_cent_t to the hashes, purge if necessary to not exceed cache size
 * limits, and add the entries to the hashes.
 * As memory is already reserved for the rrs, we only need to wrap up the dns_cent_t and
 * alloc memory for it.
 * New entries are appended, so we easiliy know the oldest for purging. For fast acces,
 * we use hashes instead of ordered storage.
 *
 * This does not free the argument, and it uses a copy of it, so the caller must do free_cent()
 * on it.
 *
 * The new entries rr sets replace the old ones, i.e. old rr sets with the same key are deleted before the
 * new ones are added.
 */
void add_cache(dns_cent_t *cent)
{
	dns_cent_t *ce;
	int i;

	lock_cache_rw();
 retry:
	if (!(ce=dns_lookup(cent->qname))) {
		if(!(ce=copy_cent(cent  DBG0))) {
			goto warn_unlock_cache_return;
		}
		/* Add the rrs to the rr list */
		for (i=0;i<T_NUM;i++) {
			if (ce->rr[i]) {
				if (!insert_rrl(ce->rr[i],ce,i+T_MIN)) {
					goto free_cent_unlock_cache_return;
				}
			}
		}
		/* If this record is negative cached, add the cent to the rr list. */
		if (cent->flags&DF_NEGATIVE) {
			if (!insert_rrl(NULL,ce,-1)) {
				goto free_cent_unlock_cache_return;
			}
		}
		add_dns_hash(cent->qname,ce);
		ent_num++;
	} else {
		if (cent->flags&DF_NEGATIVE) {
			/* the new entry is negative. So, we need to delete the whole cent,
			 * and then generate a new one. */
			for (i=0;i<T_NUM;i++) {
				if (ce->rr[i] && ce->rr[i]->flags&CF_LOCAL) {
					goto unlock_cache_return; /* Do not clobber local records */
				}
			}
			del_cache_ent(ce);
			goto retry;
		}
		purge_cent(ce, 0);
		/* We have a record; add the rrsets replacing old ones */
		cache_size-=ce->cs;
		for (i=0;i<T_NUM;i++) {
			rr_set_t *centrrs=cent->rr[i],*cerrs=ce->rr[i];
			if (centrrs && !(cerrs && cerrs->flags&CF_LOCAL)) {
				rr_bucket_t *rr;

				del_cent_rrset(ce,i+T_MIN  DBG0);

				if (!cr_check_add(ce, i+T_MIN, centrrs->ttl, centrrs->ts, centrrs->flags))
					continue;  /* the new record has been deleted as a conflict resolution measure. */

				/* pre-initialize a rrset_t for the case we have a negative cached
				 * rrset, in which case no further rrs will be added. */
				if (!add_cent_rrset(ce, i+T_MIN, centrrs->ttl, centrrs->ts, centrrs->flags, 0  DBG0)) {
					goto addsize_unlock_cache_return;
				}
				rr=centrrs->rrs;
				while (rr) {
					rr_bucket_t *rrb=create_rr(rr->rdlen, rr+1  DBG0);
					if (!rrb) {
						/* cleanup this entry */
						goto cleanup_cent_unlock_cache_return;
					}
					add_cent_rr_int(ce,rrb,i+T_MIN,centrrs->ttl, centrrs->ts, centrrs->flags,0  DBG0);
					rr=rr->next;
				}
				if (!insert_rrl(ce->rr[i],ce,i+T_MIN)) {
					goto cleanup_cent_unlock_cache_return;
				}
			}
		}
	}

	cache_size += ce->cs;
	purge_cache((long)global.perm_cache*1024+MCSZ, 1);
	goto unlock_cache_return;

 cleanup_cent_unlock_cache_return:
	del_cent_rrset(ce,i+T_MIN  DBG0);
 addsize_unlock_cache_return:
	cache_size += ce->cs;
	goto warn_unlock_cache_return;
 free_cent_unlock_cache_return:
	free_cent(ce  DBG0);
	pdnsd_free(ce);
 warn_unlock_cache_return:
	log_warn("Out of cache memory.");
 unlock_cache_return:
	unlock_cache_rw();
}

/*
 * Delete a cent from the cache. Call with write locks applied.
 */
static void del_cache_ent(dns_cent_t *cent)
{
	dns_cent_t *data;

	/* Delete from the hash */
	data=del_dns_hash(cent->qname);
	if(!data) {
		log_warn("Cache entry not found by del_dns_hash() in %s, line %d",__FILE__,__LINE__);
	}
	else if(data!=cent) {
		log_warn("pointer returned by del_dns_hash() does not match cache entry in %s, line %d",__FILE__,__LINE__);
	}
	cache_size -= cent->cs;

	/* free the data referred by the cent and the cent itself */
	free_cent(cent  DBG0);
	free(cent);

	ent_num--;
}

/* Delete a cached record. Performs locking. Call this from the outside, NOT del_cache_ent */
void del_cache(unsigned char *name)
{
	dns_cent_t *cent;

	lock_cache_rw();
	if ((cent=del_dns_hash(name))) {
		cache_size -= cent->cs;

		/* free the data referred by the cent and the cent itself */
		free_cent(cent  DBG0);
		free(cent);

		ent_num--;
	}
	unlock_cache_rw();
}


/* Invalidate a record by resetting the fetch time to 0. This means that it will be refreshed
 * if possible (and will only be served when purge_cache=off;) */
void invalidate_record(unsigned char *name)
{
	dns_cent_t *ce;
	int i;

	lock_cache_rw();
	if ((ce=dns_lookup(name))) {
		for (i=0;i<T_NUM;i++) {
			rr_set_t *rrs=ce->rr[i];
			if (rrs) {
				rrs->ts=0;
				rrs->flags &= ~CF_LOCAL;
			}
		}
		/* set the cent time to 0 (for the case that this was negative) */
		ce->ts=0;
		ce->flags &= ~DF_LOCAL;
	}
	unlock_cache_rw();
}


/*
 * See if we have an entry in the cache, whether it is negative or not.
 * Saves a copy operation compared to lookup_cache.
 */
int have_cached(unsigned char *name)
{
	dns_cent_t *ret;
	lock_cache_r();
	ret=dns_lookup(name);
	unlock_cache_r();
	return ret!=NULL;
}

/* Lookup an entry in the cache using name (in dotted notation).
 * For thread safety, a copy must be returned, so delete it after use, by first doing
 * free_cent to remove the rrs and then by freeing the returned pointer
 */
dns_cent_t *lookup_cache(unsigned char *name)
{
	dns_cent_t *ret;

	lock_cache_r();
	if ((ret=dns_lookup(name))) {
		if (purge_cent(ret, 1))
			ret = NULL;
		else
			ret=copy_cent(ret  DBG1);
	}
	unlock_cache_r();
	return ret;
}

/* Add an rr to an existing cache entry.
 * The rr is treated with the precedence of an additional or off-topic record, ie. regularly retrieved
 * have precedence.
 * You cannot add a negative additional record. Makes no sense anyway. */
int add_cache_rr_add(unsigned char *name,time_t ttl, time_t ts, short flags,int dlen, void *data, int tp, unsigned long serial)
{
	dns_cent_t *ret;
	int rv=0;

	lock_cache_rw();
	if ((ret=dns_lookup(name))) {
		rr_set_t *rrs;

		/* purge the record. */
		purge_cent(ret,0);
		cache_size-=ret->cs;
		rrs=ret->rr[tp-T_MIN];
		if (rrs &&
		    ((rrs->flags&CF_NOPURGE && rrs->ts+rrs->ttl<time(NULL)) ||
		     (rrs->flags&CF_ADDITIONAL && rrs->serial!=serial) ||
		     (rrs->serial==serial && rrs->ttl!=ttl))) {
			del_cent_rrset(ret,tp  DBG0);
			rrs=NULL;
		}
		if (rrs==NULL || rrs->serial==serial) {
			if (cr_check_add(ret,tp,ttl,ts,flags)) {
				rr_bucket_t *rrb=create_rr(dlen,data  DBG0);
				if (rrb && add_cent_rr_int(ret,rrb,tp,ttl,ts,flags,serial  DBG0)) {
					rr_set_t *rrsnew;
					if (!rrs && (rrsnew=ret->rr[tp-T_MIN]) && !insert_rrl(rrsnew,ret,tp)) {
						del_cent_rrset(ret,tp  DBG0);
					}
					else {
						cache_size+=ret->cs;
						purge_cent(ret,1);
						rv=1;
						goto unlock_return;
					}
				}
			}
		} else {
			rv=1;
		}
		cache_size+=ret->cs;
	}
 unlock_return:
	unlock_cache_rw();
	return rv;
}


/* Report the cache status to the file descriptor f, for the status fifo (see status.c) */
void report_cache_stat(int f)
{
	long mc=(long)global.perm_cache*1024+MCSZ;
	double csz=(((double)cache_size)/mc)*100;
	fsprintf(f,"\nCache status:\n=============\n");
	fsprintf(f,"%ld kB maximum disk cache size.\n",global.perm_cache);
	fsprintf(f,"%ld of %ld bytes (%.3g%%) memory cache used in %ld entries.\n",cache_size,mc,csz,ent_num);
}
