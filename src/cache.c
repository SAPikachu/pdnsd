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
static char rcsid[]="$Id: cache.c,v 1.34 2001/06/21 23:58:10 tmm Exp $";
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
 * The disk cache file constist of cent's, i.e. structures for every known hostnames with a header and rrs attached to it.
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

/* Some volatiles. Most are actually locked, but being paranoid I don't want
 * some optimization to get in the way. If they are used in locked context,
 * they are casted. */
volatile dns_hash_t dns_hash;

volatile rr_lent_t *rrset_l=NULL;
volatile rr_lent_t *rrset_l_tail=NULL;

/*
 * We do not count the hash table sizes here. Those are very small compared
 * to the cache entries.
 */
volatile long cache_size=0;
volatile long ent_num=0;

#define cache_free(ptr, dbg)		do { if (dbg) pdnsd_free(ptr); else free(ptr); } while (0)
#define cache_calloc(sz, n, dbg)	((dbg)?(pdnsd_calloc(sz,n)):(calloc(sz,n)))
#define cache_realloc(ptr, sz, dbg)	((dbg)?(pdnsd_realloc(ptr,sz)):(realloc(ptr,sz)))

volatile int cache_w_lock=0;
volatile int cache_r_lock=0;

pthread_mutex_t lock_mutex;
/* 
 * These are condition variables for lock coordination, so that normal lock
 * routines do not need to loop. Basically, a process wanting to acquire a lock
 * tries first to lock, and if the lock is busy, sleeps on one of the conds.
 * If the r lock count has gone to zero one process sleeping on the rw cond 
 * will be awankened.
 * If the rw lock is lifted, either all threads waiting on the r lock or one
 * thread waiting on the rw lock is/are awakened. This is determined by policy.
 */
pthread_cond_t  rw_cond;
pthread_cond_t  r_cond;

/* This is to suspend the r lock to avoid lock contention by reading threads */
volatile int r_pend=0;
volatile int rw_pend=0;
volatile int r_susp=0;

/* This threshold is used to temporarily suspend r locking to give rw locking
 * a chance. */
#define SUSP_THRESH(r_pend) (r_pend*0.5+2)

/*
 * This is set to 1 once the lock is intialized. This must happen before we get
 * multiple threads.
 */
volatile int use_cache_lock=0;

/*
 * Prototypes for internal use
 */
static void purge_cache(long sz, int lazy);
static void del_cache_int(dns_cent_t *cent);
static void del_cache_int_rrl(dns_cent_t *cent);
static void remove_rrl(rr_lent_t *le);

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
	do {
		if (rw_pend>SUSP_THRESH(r_pend))
			r_susp=1;
		if (!cache_w_lock && !r_susp) {
			cache_r_lock++;
			r_pend--;
			break;
		}
		/* This will unlock the mutex while sleeping and relock it before exit */
		pthread_cond_wait(&r_cond, &lock_mutex);
	} while (1);
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
	do {
		if (!(cache_w_lock || cache_r_lock)) {
			cache_w_lock=1;
			rw_pend--;
			break;
		}
		/* This will unlock the mutex while sleeping and relock it before exit */
		pthread_cond_wait(&rw_cond, &lock_mutex);
	} while (1);
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
	if (rw_pend>SUSP_THRESH(r_pend) || r_pend == 0)
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
	int lk=0;
	int tr=0;
	if (!use_cache_lock)
		return 0;
	while (!lk)  {
		if (!softlock_mutex(&lock_mutex))
			return 0;
		if (!cache_w_lock) {
			lk=1;
			cache_r_lock++;
		}
		pthread_mutex_unlock(&lock_mutex);
		if (!lk)
			usleep_r(1000); /*give contol back to the scheduler instead of hammering the lock close*/
		if (tr++>SOFTLOCK_MAXTRIES)
			return 0;
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
	int lk=0;
	int tr=0;
	if (!use_cache_lock)
		return 0;
	while (!lk)  {
		if (!softlock_mutex(&lock_mutex))
			return 0;
		if (!(cache_w_lock || cache_r_lock)) {
			lk=1;
			cache_w_lock=1;
		}
		pthread_mutex_unlock(&lock_mutex);
		if (!lk)
			usleep_r(1000); /*give contol back to the scheduler instead of hammering the lock close*/
		if (tr++>SOFTLOCK_MAXTRIES)
			return 0;
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
	mk_dns_hash((dns_hash_t *)&dns_hash);
}

/* Initialize the cache. Call only once. */
void init_cache_lock()
{
	pthread_mutex_init(&lock_mutex,NULL);
	pthread_cond_init(&rw_cond,NULL);
	pthread_cond_init(&r_cond,NULL);
	use_cache_lock=1;
}

/* Delete the cache. Call only once */
void destroy_cache()
{
	dns_cent_t *ce;
	dns_hash_pos_t pos;

	/* lock the cache, in case that any thread is still accessing. */
	softlock_cache_rw();
	ce=fetch_first((dns_hash_t *)&dns_hash, &pos);
	while (ce) {
		del_cache_int_rrl(ce);
		ce=fetch_next((dns_hash_t *)&dns_hash,&pos);
	}
	free_dns_hash((dns_hash_t *)&dns_hash);

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
int init_cent(dns_cent_t *cent, unsigned char *qname, short flags, time_t ts, time_t ttl, int dbg)
{
	int i;

	/* This mimics strdup, which is not really portable unfortunately */
	cent->qname=cache_calloc(sizeof(unsigned char),strlen((char *)qname)+1, dbg);
	if (cent->qname == NULL)
		return 0;
	strcpy((char *)cent->qname,(char *)qname);
	cent->cs=sizeof(dns_cent_t)+strlen((char *)qname)+1;
	cent->num_rrs=0;
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
rr_bucket_t *create_rr(int dlen, void *data, int dbg)
{
	rr_bucket_t *rrb;
	rrb=(rr_bucket_t *)cache_calloc(sizeof(rr_bucket_t)+dlen,1,dbg);
	if (rrb == NULL)
		return NULL;
	rrb->next=NULL;
		
	rrb->rdlen=dlen;
	memcpy(rrb+1,data,dlen);
	return rrb;
}

/*
 * Adds an empty. rrset_t with the requested data to a cent. This is exactly what you need to
 * do to create a negatively cached cent.
 */
int add_cent_rrset(dns_cent_t *cent, int tp, time_t ttl, time_t ts, int flags, unsigned long serial, int dbg)
{
	cent->rr[tp-T_MIN]=cache_calloc(sizeof(rr_set_t),1,dbg);
	if (cent->rr[tp-T_MIN]==NULL)
		return 0;
	ttl=ttl<global.min_ttl?global.min_ttl:(ttl>global.max_ttl?global.max_ttl:ttl);
	if (flags&CF_NOCACHE) {
		flags&=~CF_NOCACHE;
		ttl=0;
	}
	cent->rr[tp-T_MIN]->ttl=ttl;
	cent->rr[tp-T_MIN]->ts=ts;
	cent->rr[tp-T_MIN]->flags=flags;
	cent->rr[tp-T_MIN]->serial=serial;
	cent->cs+=sizeof(rr_set_t);
	cent->num_rrs++;
	return 1;
}

/*
 * Adds a rr record (usually prepared by create_rr) to a cent. For cache.c internal use. 
 */
static int add_cent_rr_int(dns_cent_t *cent, rr_bucket_t *rr, int tp, time_t ttl, time_t ts, int flags, unsigned long serial, int dbg)
{
	if ((cent->flags&DF_LOCAL) && !(flags&CF_LOCAL))
		return 1; /* ignore. Local has precedence. */

	if (!cent->rr[tp-T_MIN]) {
		if (!add_cent_rrset(cent, tp, ttl, ts, flags, serial, dbg))
			return 0;
	}
	/* If we add a record, this is not negative any more. */
	if (cent->flags&DF_NEGATIVE) {
		cent->flags&=~DF_NEGATIVE;
		/* need to remove the cent from the lent list. */
		if (cent->lent)
			remove_rrl(cent->lent);
		cent->ttl=0;
		cent->lent=NULL;
	}

	cent->cs+=rr->rdlen+sizeof(rr_bucket_t);
	/* do the linking work */
	rr->next=cent->rr[tp-T_MIN]->rrs;
	cent->rr[tp-T_MIN]->rrs=rr;
#if DEBUG>0
	if (cent->rr[tp-T_MIN]->flags&CF_NEGATIVE)
		DEBUG_MSG("Tried to add rr to a rrset with CF_NEGATIVE set! flags=%i\n",cent->rr[tp-T_MIN]->flags);
#endif
	return 1;
}


/* Add an rr to a cache entry, giving the ttl, the data length, the rr type (tp)
 * and a pointer to the data. A record is allocated, and the data is copied into
 * it. Do this for all rrs in a cache entry. 
 */
int add_cent_rr(dns_cent_t *cent, time_t ttl, time_t ts, short flags, int dlen, void *data, int tp, int dbg)
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
	if (!(rrb=create_rr(dlen,data,dbg)))
		return 0;
	return add_cent_rr_int(cent,rrb,tp,ttl,ts,flags,0,dbg);
}

/* Free a complete rrset including all memory. Returns the size of the memory freed */
static int del_cent_rrset(dns_cent_t *cent, int tp, int dbg)
{
	rr_bucket_t *rrb,*rrn;
	int rv=0;

	if (!cent->rr[tp-T_MIN])
		return 0;

	rrb=cent->rr[tp-T_MIN]->rrs;
	while (rrb) {
		rv+=sizeof(rr_bucket_t)+rrb->rdlen;
		rrn=rrb->next;
		free_rr(*rrb, dbg);
		cache_free(rrb,dbg);
		rrb=rrn;
	}
	cent->num_rrs--;
	rv+=sizeof(rr_set_t);
	cent->cs-=rv;
	cache_free(cent->rr[tp-T_MIN],dbg);
	cent->rr[tp-T_MIN]=NULL;
	return rv;
}

/* Free the pointers cointained in an rr record. If the rr record is on the heap,
 * don't forget to delete itself. This is done extra mainly for extensibility 
 * -- This is not here any more. The definition is actually an empty macro in
 * cache.h.
 */
/*
void free_rr(rr_bucket_t rr, int dbg)
{
}
*/

/* Free all rr records from a cache entry. */
void free_cent(dns_cent_t cent, int dbg)
{
	int i;
	for (i=0;i<T_NUM;i++) {
		del_cent_rrset(&cent, i+T_MIN, dbg);
	}
	cache_free(cent.qname,dbg);
}

static long get_rrlent_ts(rr_lent_t *le)
{
	if (le->rrset)
		return le->rrset->ts;
	return le->cent->ts;
}

/* insert a rrset into the rr_l list. This modifies the rr_set_t if rrs is not NULL! 
 * The rrset address needs to be constant afterwards.
 * Call with locks applied. */
static rr_lent_t *insert_rrl(rr_set_t *rrs, dns_cent_t *cent, int tp, time_t ts)
{
	rr_lent_t *le,*ne;
	int fnd=0;
	if (!(ne=(rr_lent_t *)calloc(sizeof(rr_lent_t),1)))
		return NULL;
	ne->next=ne->prev=NULL;
	ne->rrset=rrs;
	ne->cent=cent;
	ne->tp=tp;
	if (rrs)
		rrs->lent=ne;
	/* Since the append at the and is a very common case (and we want this case to be fast), we search back-to-forth.
	 * Since rr_l is a list and we don't really have fast access to all elements, we do no perform an advanced algorihtm
	 * like binary search.*/
	le=(rr_lent_t *)rrset_l_tail;
	while (le) {
		if (ts>=get_rrlent_ts(le) && (le->next==NULL || ts<get_rrlent_ts(le->next))) {
			if (le->next)
				le->next->prev=ne;
			ne->next=le->next;
			ne->prev=le;
			le->next=ne;
			fnd=1;
			break;
		}
		le=le->prev;
	}
	if (!fnd) {
		/* not found, so it needs to be inserted at the start of the list. */
		ne->next=(rr_lent_t *)rrset_l;
		if (rrset_l)
			rrset_l->prev=ne;
		rrset_l=ne;
	}
	if (!ne->next) {
		rrset_l_tail=ne;
	}
	return ne;
}

/* Remove a rr from the rr_l list. Call with locks applied. */
static void remove_rrl(rr_lent_t *le)
{
	if (le->next)
		le->next->prev=le->prev;
	else
		rrset_l_tail=le->prev;
	if (le->prev)
		le->prev->next=le->next;
	else
		rrset_l=le->next;
	free(le);
}

/* Copy a rr_bucket_t into newly allocated memory */
rr_bucket_t *copy_rr(rr_bucket_t *rr, int dbg)
{
	rr_bucket_t *rrn;
	rrn=cache_calloc(sizeof(rr_bucket_t)+rr->rdlen,1,dbg);
	if (rrn == NULL)
		return NULL;
	memcpy(rrn,rr,sizeof(rr_bucket_t)+rr->rdlen);
	rrn->next=NULL;
	return rrn;
}

/* Copy a cache entry into newly allocated memory */
dns_cent_t *copy_cent(dns_cent_t *cent, int dbg)
{
	dns_cent_t *ic;
	int i;
	rr_bucket_t *rr,**rri;

	/*
	 * We do not debug cache internals with it, as mallocs seem to be
	 * "lost" when they enter the cache for a longer time.
	 */
	ic=cache_calloc(sizeof(dns_cent_t),1,dbg);
	if (ic == NULL)
		return NULL;
	*ic=*cent;

	ic->qname=cache_calloc(sizeof(unsigned char),strlen((char *)cent->qname)+1,dbg);
	if (ic->qname == NULL) {
		cache_free(ic,dbg);
		return NULL;
	}
	strcpy((char *)ic->qname,(char *)cent->qname);
	ic->lent=NULL;
	
	for (i=0;i<T_NUM;i++) 
		ic->rr[i]=NULL;

	for (i=0;i<T_NUM;i++) {
		if (cent->rr[i]) {
			if (!(ic->rr[i]=(rr_set_t *)cache_calloc(sizeof(rr_set_t),1,dbg))) {
				free_cent(*ic,dbg);
				cache_free(ic,dbg);
				return NULL;
			}
			memcpy(ic->rr[i],cent->rr[i],sizeof(rr_set_t));
			ic->rr[i]->rrs=NULL;
			rri=&ic->rr[i]->rrs;
			rr=cent->rr[i]->rrs;
			while(rr) {
				if (!(*rri=copy_rr(rr,dbg))) {
					free_cent(*ic,dbg);
					cache_free(ic,dbg);
					return NULL;
				}
				rri=(rr_bucket_t **)&(*rri)->next;
				rr=rr->next;
			}
		}
	}
	return ic;
}

/* 
 * Remove all timed out entries of a given rr row.
 * Follow some rules based on flags etc.
 * This will either delete the whole rrset, or will leave it as a whole (RFC2181 seems to
 * go in that direction)
 * This was pretty large once upon a time ;-), but now, since we operate in rrsets, was
 * shrinked drastically.
 * If the record is in the cache, we need rw-locks applied.
 * Returns the size of the freed memory.
 */
static int purge_rrset(dns_cent_t *cent, int tp)
{
	if (cent->rr[tp-T_MIN] && !(cent->rr[tp-T_MIN]->flags&CF_NOPURGE || cent->rr[tp-T_MIN]->flags&CF_LOCAL) &&
	    cent->rr[tp-T_MIN]->ts+cent->rr[tp-T_MIN]->ttl+CACHE_LAT<time(NULL)) {
		/* well, it must go. */
		remove_rrl(cent->rr[tp-T_MIN]->lent);
		return del_cent_rrset(cent,tp,0);
	}
	return 0;
}

/*
 * Purge a cent, deleting timed-out rrs (following the constraints noted in "purge_rrset").
 * Since the cent may actually become empty and be deleted, you may not use it after this call until
 * you refetch its address from the hash (if it is still there).
 * returns the size of the freed memory.
 * Force means to delete the cent even when it's not timed out.
 */
static int purge_cent(dns_cent_t *cent, int delete, int *deleted)
{
	int rv=0;
	int i;
	
	for (i=T_MIN;i<=T_MAX;i++)
		rv+=purge_rrset(cent,i);
	/* if the record was purged empty, delete it from the cache. */
	if (cent->num_rrs==0 && delete && (!cent->flags&DF_NEGATIVE || 
					   ((time(NULL)-cent->ts>cent->ttl+CACHE_LAT) && !cent->flags&DF_LOCAL))) {
		del_cache_int_rrl(cent); /* this will subtract the cent's left size from cache_size */
		if (deleted != NULL)
			*deleted = 1;
	} else
		if (deleted != NULL)
			*deleted = 0;
	return rv;
}

/*
 * Bring cache to a size below or equal the cache size limit (sz). There are two strategies:
 * - for cached sets with CF_NOPURGE not set: delete if timed out
 * - additional: delete oldest sets.
 */
static void purge_cache(long sz, int lazy)
{
	dns_cent_t *ce;
	rr_lent_t **le;
	int deleted;

	/* Walk the cache list from the oldest entries to the newest, deleting timed-out
	 * records.
	 * XXX: We walk the list a second time if this did not free up enough space - this
	 * should be done better. */
	le=(rr_lent_t **)&rrset_l;
	while (*le && (!lazy || cache_size>sz)) {
		if (!(((*le)->rrset && ((*le)->rrset->flags&CF_LOCAL)) || 
		      (*le)->cent->flags&DF_LOCAL)) {
			ce = (*le)->cent;
			/* Side effect: if rv!=0, del_cent_rrset was called and *le has advanced one entry.
			 * ce, however, is still guaranteed to be valid. */
			if ((*le)->rrset) {
				deleted=purge_rrset(ce, (*le)->tp);
				cache_size-=deleted;
			}
			if (ce->num_rrs==0 && (!ce->flags&DF_NEGATIVE || 
					   ((time(NULL)-ce->ts>ce->ttl+CACHE_LAT) && !ce->flags&DF_LOCAL))) {
				del_cache_int(ce);
				if (!deleted)
					remove_rrl(*le);
			} else
				if (!deleted)
					le=&(*le)->next;
		} else
			le=&(*le)->next;
	}
	if (cache_size<=sz)
		return;
	/* we are still above the desired cache size. Well, delete records from the oldest to
	 * the newest. This is the case where nopurge records are deleted anyway. Only local
	 * records are kept in any case.*/
	le=(rr_lent_t **)&rrset_l;
	while (*le && cache_size>sz) {
		if (!(((*le)->rrset && ((*le)->rrset->flags&CF_LOCAL)) || 
		      (*le)->cent->flags&CF_LOCAL)) {
			/*next=(*le)->next;*/
			if ((*le)->rrset)
				cache_size-=del_cent_rrset((*le)->cent, (*le)->tp,0);
			/* this will also delete negative cache entries */
			if ((*le)->cent->num_rrs==0) {
				del_cache_int((*le)->cent);
			}
			remove_rrl(*le);
			/**le=next;*/ /*remove_rrl should do that. */
		} else {
			le=&(*le)->next;
		}
	}
}

/* Load an rr from f. data must be null or allocated on first call and freed after last call. dtsz must be the
 * initial size of data (or 0)*/
static int read_rr (rr_fbucket_t *rr, unsigned char **data, int *dtsz, FILE *f)
{
	if (fread(rr,sizeof(rr_fbucket_t),1,f)!=1) {
		fclose(f);
		log_warn("Error in disk cache file.");
		if (*data)
			free(*data);
		return 0;
	}
	if (rr->rdlen>*dtsz) {
		*dtsz=rr->rdlen;
		*data=realloc(*data,*dtsz);
	}
	if (!*data) {
		fclose(f);
		log_warn("Out of memory in reading cache file. Exiting.");
		pdnsd_exit();
		return 0;
	}
	if (fread(*data,rr->rdlen,1,f)!=1) {
		fclose(f);
		log_warn("Error in disk cache file.");
		free(*data);
		return 0;
	}
	return 1;
}

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
	char path[1024];
	long cnt;
	FILE *f;
	unsigned char nb[256];

	if (snprintf(path, sizeof(path), "%s/pdnsd.cache", global.cache_dir)>=sizeof(path)) {
		log_warn("Cache file path too long.");
		return;
	}

	if (!(data = calloc(dtsz,1))) {
		log_warn("Out of memory in reading cache file. Exiting.");
		pdnsd_exit();
		return;
	}

	if (!(f=fopen(path,"r"))) {
		log_warn("Could not open disk cache file %s: %s",path,strerror(errno));
		free(data);
		return;
	}

	if (fread(&cnt,sizeof(cnt),1,f)!=1) {
		fclose(f);
		log_warn("Error in disk cache file.");
		free(data);
		return;
	}
	
	for(;cnt>0;cnt--) {
		if (fread(&fe,sizeof(dns_file_t),1,f)!=1) {
			fclose(f);
			log_warn("Error in disk cache file.");
			free(data);
			return;
		}
		memset(nb,0,256);
		if (fe.qlen) {
			if (fread(nb,fe.qlen,1,f)!=1) {
				fclose(f);
				log_warn("Error in disk cache file.");
				free(data);
				return;
			}
		}
		if (!init_cent(&ce, nb, fe.flags, fe.ts, fe.ttl,0)) {
			free(data);
			fclose(f);
			log_error("Out of memory in reading cache file. Exiting.");
			pdnsd_exit();
			return;
		}
		/* now, read the rr's */
		for (i=0;i<T_NUM;i++) {
			if (fread(&num_rr,sizeof(num_rr),1,f)!=1) {
				log_warn("Error in disk cache file.");
				free(data);
				free_cent(ce,0);
				fclose(f);
				return;
			}
			if (num_rr) {
				if (fread(&sh,sizeof(sh),1,f)!=1) {
					log_warn("Error in disk cache file.");
					free(data);
					free_cent(ce,0);
					fclose(f);
					return;
				}
				/* Add the rrset header in any case (needed for negative cacheing */
				add_cent_rrset(&ce, i+T_MIN, sh.ttl, sh.ts, sh.flags, 0, 0);
				for (;num_rr>1;num_rr--) {
					if (!read_rr(&rr,&data,&dtsz,f)) {
						free_cent(ce,0);
						return;
					}
					if (!add_cent_rr(&ce,sh.ttl,sh.ts,sh.flags,rr.rdlen,data,i+T_MIN,0)) {
						log_error("Out of memory in reading cache file. Exiting.");
						pdnsd_exit();
						free(data);
						free_cent(ce,0);
						fclose(f);
						return;
					}
				}
			}
		}
		add_cache(ce);
		free_cent(ce,0);
	}
	free(data);
	fclose(f);
#ifdef DBGHASH
	dumphash(&dns_hash);
#endif
}

/* write an rr to the file f */
static int write_rrset(rr_set_t *rrs, FILE *f)
{
	rr_bucket_t *rr;
	rr_fset_t sh;
	rr_fbucket_t rf;
	unsigned char num_rr=0;  /* 0 means nothing, 1 means header only, 1 means header + 1 records ... */
	long nump,oldp;
	
 	if ((nump=ftell(f))==-1) {
		log_error("Error while writing disk cache: %s", strerror(errno));
		fclose(f);
		return 0;
	}
	/* write a dummy at first, since we do no know the number */
	if (fwrite(&num_rr,sizeof(num_rr),1,f)!=1) {
		log_error("Error while writing disk cache: %s", strerror(errno));
		fclose(f);
		return 0;
	}
	if (!rrs || rrs->flags&CF_LOCAL)
		return 1;

	sh.ttl=rrs->ttl;
	sh.ts=rrs->ts;
	sh.flags=rrs->flags;
	if (fwrite(&sh,sizeof(sh),1,f)!=1) {
		log_error("Error while writing disk cache: %s", strerror(errno));
		fclose(f);
		return 0;
	}
	rr=rrs->rrs;
	/* We only write a maximum of 256 of a kind (type) for one domain. This would be already overkill and probably does not happen.
	 * we want to get along with only one char, because most rr rows are empty (even more with DNS_NEW_RRS), and so the usage
	 * of greater data types would have significant impact on the cache file size. */
	num_rr=1;
	while (rr && num_rr<255) {
		num_rr++;
		rf.rdlen=rr->rdlen;
		if (fwrite(&rf,sizeof(rf),1,f)!=1 || fwrite((rr+1),rf.rdlen,1,f)!=1) {
			log_error("Error while writing disk cache: %s", strerror(errno));
			fclose(f);
			return 0;
		}
		rr=rr->next;
	}
	if ((oldp=ftell(f))==-1 || fseek(f,nump,SEEK_SET)==-1 || 
	    fwrite(&num_rr,sizeof(num_rr),1,f)!=1 ||  /* write the real number */
	    fseek(f,oldp,SEEK_SET)==-1) {
		log_error("Error while writing disk cache: %s", strerror(errno));
		fclose(f);
		return 0;
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
	int i,j;
	dns_cent_t *le;
	char path[1024];
	dns_file_t df;
	long en=0;
	int aloc;
	dns_hash_pos_t pos;
	FILE *f;

	if (snprintf(path, sizeof(path), "%s/pdnsd.cache", global.cache_dir)>=sizeof(path)) {
		log_warn("Cache file path too long.");
		return;
	}		

	if (!(f=fopen(path,"w"))) {
		log_warn("Could not open disk cache file %s: %s",path,strerror(errno));
		return;
	}
	
	/* purge cache down to allowed size*/
	if (!softlock_cache_rw()) {
		fclose(f);
		crash_msg("Lock failed; could not write disk cache.");
		return;
	}
	purge_cache((long)global.perm_cache*1024, 0);
	if (!softunlock_cache_rw()) {
		fclose(f);
		crash_msg("Lock failed; could not write disk cache.");
		return;
	}
	if (!softlock_cache_r()) {
		fclose(f);
		crash_msg("Lock failed; could not write disk cache.");
		return;
	}
	/* we don't know the real size by now, so write a dummy */
	if (fwrite((char *)&ent_num,sizeof(en),1,f)!=1) {
		log_error("Error while writing disk cache: %s", strerror(errno));
		fclose(f);
		softunlock_cache_r();
		return;
	}

	le=fetch_first((dns_hash_t *)&dns_hash,&pos);
	while (le) {
		/* now, write the rr's */
		aloc=1;
		for (j=0;j<T_NUM;j++) {
			if (le->rr[j] && !(le->rr[j]->flags&CF_LOCAL)) {
				aloc=0;
				break;
			}
		}
		if (!aloc) {
			en++;
			df.qlen=strlen((char *)le->qname);
			df.flags=le->flags;
			df.ts=le->ts;
			df.ttl=le->ttl;
			if (fwrite(&df,sizeof(dns_file_t),1,f)!=1 ||
			    fwrite(le->qname,df.qlen,1,f)!=1) {
				log_error("Error while writing disk cache: %s", strerror(errno));
				fclose(f);
				softunlock_cache_r();
				return;
			}
			
			for (i=0;i<T_NUM;i++) {
				if (!write_rrset(le->rr[i],f)) {
					softunlock_cache_r();
					return;
				}
			}
		}
		le=fetch_next((dns_hash_t *)&dns_hash,&pos);
	}
	/* write the real size. */
	if (fseek(f,0,SEEK_SET)==-1 || fwrite(&en,sizeof(en),1,f)!=1)
		log_error("Error while writing disk cache: %s", strerror(errno));
	fclose(f);
	softunlock_cache_r();
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
	int i, ncf = 0, olda = 0;
	time_t nttl = 0, rttl;
	struct rr_infos *rri = &rr_info[tp-T_MIN];
	
	if (flags & CF_NEGATIVE)
		return 1;		/* no constraints here. */

	if (!(flags & CF_LOCAL)) {
		for (i = 0; i < T_NUM; i++) {
			/* Should be symmetric; check both ways anyway. */
			if (cent->rr[i] && !(cent->rr[i]->flags & CF_NEGATIVE) &&
			    ((rri->class & rr_info[i].excludes) ||
			    (rri->excludes & rr_info[i].class))) {
				ncf++;
				rttl = cent->rr[i]->ttl + cent->rr[i]->ts - time(NULL);
				nttl += rttl > 0 ? rttl : 0;
				if (cent->rr[i]->flags & CF_LOCAL) {
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
		/* remove the old records, so that the new one can be added */
		for (i = 0; i < T_NUM; i++) {
			/* Should be symmetric; check both ways anyway. */
			if (cent->rr[i] && !(cent->rr[i]->flags & CF_NEGATIVE) &&
			    ((rri->class & rr_info[i].excludes) ||
			    (rri->excludes & rr_info[i].class))) {
				remove_rrl(cent->rr[i]->lent);
				del_cent_rrset(cent,i+T_MIN,0);
			}
		}
		return 1;
	}
	/* old records precede */
	return 0;
}

static int cr_add_cent_rrset(dns_cent_t *cent, int tp, time_t ttl, time_t ts, int flags, unsigned long serial, int dbg)
{
	if (!cr_check_add(cent, tp, ttl, ts, flags))
		return 0;
	if (!add_cent_rrset(cent, tp, ttl, ts, flags, serial, dbg))
		return -1;
	return 1;
}

static int cr_add_cent_rr_int(dns_cent_t *cent, rr_bucket_t *rr, int tp, time_t ttl, time_t ts, int flags, unsigned long serial, int dbg)
{
	if (!cr_check_add(cent, tp, ttl, ts, flags)) {
		/* If it was there, delete. */
		if (cent->rr[tp-T_MIN]) {
			remove_rrl(cent->rr[tp-T_MIN]->lent);
			del_cent_rrset(cent,tp,0);
		}
		return 0;
	}
	if (!add_cent_rr_int(cent, rr, tp, ttl, ts, flags, serial, dbg))
		return -1;
	return 1;
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
void add_cache(dns_cent_t cent)
{
	dns_cent_t *ce;
	int i, rv, local=0;
	rr_bucket_t *rr,*rrb;

	lock_cache_rw();

	if (!(ce=dns_lookup((dns_hash_t *)&dns_hash,cent.qname))) {
		if(!(ce=copy_cent(&cent,0))) {
			log_warn("Out of cache memory.");
			free_cent(*ce,0);
			unlock_cache_rw();
			return;
		}
		add_dns_hash((dns_hash_t *)&dns_hash,cent.qname,ce);
		/* Add the rrs to the rr list */
		for (i=0;i<T_NUM;i++) {
			if (ce->rr[i]) {
				if (!insert_rrl(ce->rr[i],ce,i+T_MIN,ce->rr[i]->ts)) {
					log_warn("Out of cache memory.");
					free_cent(*ce,0);
					unlock_cache_rw();
					return;
				}
			}
		}
		/* If this record is negative cached, add the cent to the rr list. */
		if (cent.flags&DF_NEGATIVE) {
			if (!(ce->lent=insert_rrl(NULL,ce,-1,cent.ts))) {
				log_warn("Out of cache memory.");
				free_cent(*ce,0);
				unlock_cache_rw();
				return;
			}
		}
		ent_num++;
		cache_size+=ce->cs;
	} else {
		if (cent.flags&DF_NEGATIVE) {
			/* the new entry is negative. So, we need to delete the whole cent,
			 * and then generate a new one. */
			for (i=0;i<T_MAX;i++) {
				if (ce->rr[i] && ce->rr[i]->flags&CF_LOCAL) {
					local=1;
					break;
				}
			}
			/* Do not clobber local records */
			if (!local) {
				del_cache_int_rrl(ce);
				unlock_cache_rw();
				add_cache(cent);
			} else
				unlock_cache_rw();
			return;
		}
		cache_size-=purge_cent(ce, 0, NULL);
		/* We have a record; add the rrsets replacing old ones */
		cache_size-=ce->cs;
		for (i=0;i<T_NUM;i++) {
			if (cent.rr[i] && !(ce->rr[i] && ce->rr[i]->flags&CF_LOCAL)) {
				if (ce->rr[i]) {
					remove_rrl(ce->rr[i]->lent);
					del_cent_rrset(ce,i+T_MIN,0);
				}
				rr=cent.rr[i]->rrs;
				/* pre-initialize a rrset_t for the case we have a negative cached
				 * rrset, in which case no further rrs will be added. */
				rv = cr_add_cent_rrset(ce,i+T_MIN,cent.rr[i]->ttl, cent.rr[i]->ts, cent.rr[i]->flags,0,0);
				/* In the following case, the new record has been deleted as a conflict resolution measure. */
				if (rv == 0)
					continue;
				if (rv < 0) {
					log_warn("Out of cache memory.");
					unlock_cache_rw();
					return;
				}
				while (rr) {
					if (!(rrb=create_rr(rr->rdlen, rr+1, 0))) {
						if (ce->rr[i]) /* cleanup this entry */
							del_cent_rrset(ce,i+T_MIN,0);
						log_warn("Out of cache memory.");
						unlock_cache_rw();
						return;
					}
					add_cent_rr_int(ce,rrb,i+T_MIN,cent.rr[i]->ttl, cent.rr[i]->ts, cent.rr[i]->flags,0,0);
					rr=rr->next;
				}
				if (!insert_rrl(ce->rr[i],ce,i+T_MIN,ce->rr[i]->ts)) {
					del_cent_rrset(ce,i+T_MIN,0);
					log_warn("Out of cache memory.");
					unlock_cache_rw();
					return;
				}
			}
		}
		cache_size+=ce->cs;
	}

	purge_cache((long)global.perm_cache*1024+MCSZ, 1);
	unlock_cache_rw();
}

/*
 * Delete a cent from the cache. Call with write locks applied.
 */
static void del_cache_int(dns_cent_t *cent)
{
	int i;

	/* Delete from the hash */
	del_dns_hash((dns_hash_t *)&dns_hash,cent->qname);
	/* delete rrs from the rrl */
	cache_size-=cent->cs;
	for (i=0;i<T_NUM;i++) {
		if (cent->rr[i]) {
			remove_rrl(cent->rr[i]->lent);
			del_cent_rrset(cent,i+T_MIN,0);
		}
	}
	/* free the cent ptrs and rrs */
	free_cent(*cent,0);
	free(cent);

	ent_num--;
}

/* Same as above, but delete the cent from the rr list if it was registered (for negative cacheing)*/
static void del_cache_int_rrl(dns_cent_t *cent) 
{
	/* Free the lent for negative cached records */
	if (cent->flags&DF_NEGATIVE && cent->lent) 
		remove_rrl(cent->lent);
	del_cache_int(cent);
}

/* Delete a cached record. Performs locking. Call this from the outside, NOT del_cache_int */
void del_cache(unsigned char *name)
{
	dns_cent_t *ce;
	
	lock_cache_rw();
	if ((ce=dns_lookup((dns_hash_t *)&dns_hash,name))) {
		del_cache_int_rrl(ce);
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
	if ((ce=dns_lookup((dns_hash_t *)&dns_hash,name))) {
		for (i=0;i<T_NUM;i++) {
			if (ce->rr[i]) {
				ce->rr[i]->ts=0;
				ce->rr[i]->flags&=~CF_LOCAL;
			}
		}
		/* set the cent time to 0 (for the case that this was negative) */
		ce->ts=0;
		ce->flags&=~DF_LOCAL;
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
	ret=dns_lookup((dns_hash_t *)&dns_hash,name);
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
	int deleted;
	
	lock_cache_r();
	if ((ret=dns_lookup((dns_hash_t *)&dns_hash,name))) {
		cache_size-=purge_cent(ret, 1, &deleted);
		if (deleted)
			ret = NULL;
		else
			ret=copy_cent(ret, 1);
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
	rr_bucket_t *rrb;
	int add, rv=0;
	int had=0;
	lock_cache_rw();
	if ((ret=dns_lookup((dns_hash_t *)&dns_hash,name))) {
		/* purge the record. */
		cache_size-=purge_cent(ret,0, NULL);
		cache_size-=ret->cs;
		if (ret->rr[tp-T_MIN] &&  
		    ((ret->rr[tp-T_MIN]->flags&CF_NOPURGE && ret->rr[tp-T_MIN]->ts+ret->rr[tp-T_MIN]->ttl<time(NULL)) || 
		     (ret->rr[tp-T_MIN]->flags&CF_ADDITIONAL && ret->rr[tp-T_MIN]->serial!=serial) || 
		     (ret->rr[tp-T_MIN]->serial==serial && ret->rr[tp-T_MIN]->ttl!=ttl))) {
			remove_rrl(ret->rr[tp-T_MIN]->lent);
			del_cent_rrset(ret,tp,0);
		}
		if (!ret->rr[tp-T_MIN] || ret->rr[tp-T_MIN]->serial==serial) {
			if (ret->rr[tp-T_MIN])
				had=1;
			if ((rrb=create_rr(dlen,data,0))) {
				add = cr_add_cent_rr_int(ret,rrb,tp,ttl,ts,flags,serial,0);
				if (add < 0) {
					free_rr(*rrb,0);
					free(rrb);
					cache_size+=ret->cs;
				} else if (add > 0) {
					cache_size+=ret->cs;
					if (!had) {
						if (!insert_rrl(ret->rr[tp-T_MIN],ret,tp,ret->rr[tp-T_MIN]->ts)) {
							unlock_cache_rw();
							return 0;
						}
					}
					cache_size-=purge_cent(ret,1,NULL);
					rv=1;
				}
			}
		} else {
			cache_size+=ret->cs;
			rv=1;
		}
	}
	unlock_cache_rw();
	return rv;
}


/* Report the cache status to the file descriptor f, for the status fifo (see status.c) */
void report_cache_stat(int f)
{
	long mc=(long)global.perm_cache*1024+MCSZ;
	long csz=cache_size*100/mc;
	fsprintf(f,"\nCache status:\n=============\n");
	fsprintf(f,"%li kB maximum disk cache size.\n",global.perm_cache);
	fsprintf(f,"%li of %lu bytes (%lu%%) memory cache used in %lu entries.\n",cache_size,mc,csz,ent_num);
}
