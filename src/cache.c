/* cache.c - Keep the dns caches.

   Copyright (C) 2000, 2001 Thomas Moestl
   Copyright (C) 2003, 2004 Paul A. Rombouts

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
#include <sys/time.h>
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

/* A version identifier to prevent reading incompatible cache files */
static const char cachverid[] = {'p','d','1','2'};

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
 * In this version, negative caching support was introduced. Following things were changed for that:
 * - new members ts, ttl and flags in dns_cent_t and dns_file_t
 * - new caching flag CF_NEGATIVE
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
volatile short int use_cache_lock=0;

/*
  This is set to 0 while cache is read from disk.
  This must be set to 1 before we start adding new entries.
*/
static short int insert_sort=1;


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
static void del_cache_ent(dns_cent_t *cent,dns_hash_loc_t *loc);
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

/* Lock cache for reading and writing, or time out after tm seconds. */
static int timedlock_cache_rw(int tm)
{
	int retval=0;
	struct timeval now;
	struct timespec timeout;

	if (!use_cache_lock)
		return 0;
	pthread_mutex_lock(&lock_mutex);
	gettimeofday(&now,NULL);
	timeout.tv_sec = now.tv_sec + tm;
	timeout.tv_nsec = now.tv_usec * 1000;
	rw_pend++;
	while(cache_w_lock || cache_r_lock) {
		/* This will unlock the mutex while sleeping and relock it before exit */
		if(pthread_cond_timedwait(&rw_cond, &lock_mutex, &timeout) == ETIMEDOUT)
			goto cleanup_return;
	}
	cache_w_lock=1;
	retval=1;
 cleanup_return:
	rw_pend--;
	pthread_mutex_unlock(&lock_mutex);
	return retval;
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
#if 0
unsigned long l_serial=1;

unsigned long get_serial()
{
	unsigned long rv;
	lock_cache_rw();
	rv=l_serial++;
	unlock_cache_rw();
	return rv;
}
#endif

/*
 * Cache/cent handlers
 */

/* Initialize the cache. Call only once. */
#if 0
void init_cache()
{
	mk_hash_ctable();
	mk_dns_hash();
}
#endif

/* Initialize the cache lock. Call only once. */
/* This is now defined as an inline function in cache.h */
#if 0
void init_cache_lock()
{

	use_cache_lock=1;
}
#endif

/* Empty the cache completely, freeing all entries. */ 
int empty_cache()
{
	/* Wait at most 60 seconds to obtain a lock. */
	if(!timedlock_cache_rw(60))
		return 0;
	free_dns_hash();
	unlock_cache_rw();
	return 1;
}

/* Delete the cache. Call only once */
void destroy_cache()
{
	/* lock the cache, in case that any thread is still accessing. */
	if(!softlock_cache_rw()) {
		log_error("Lock failed; could not destroy cache on exit.");
		return;
	}
	free_dns_hash();
#if DEBUG>0
	if(ent_num || cache_size) {
		DEBUG_MSG("After destroying cache, %ld entries (%ld bytes) remaining.\n",ent_num,cache_size);
	}
#endif

#if 0
#if (TARGET!=TARGET_LINUX)
	/* under Linux, this frees no resources but may hang on a crash */
	pthread_mutex_destroy(&lock_mutex);
	pthread_cond_destroy(&rw_cond);
	pthread_cond_destroy(&r_cond);
#endif
#endif
}

/* Make a flag value for a dns_cent_t (dns cache entry) from a server record */
/* Now defined as inline function in cache.h */
#if 0
unsigned int mk_flag_val(servparm_t *server)
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
#endif

/* Initialize a dns cache record (dns_cent_t) with the query name (in
 * transport format), a flag value, a timestamp indicating
 * the time the query was done, and a TTL. The timestamp and TTL
 * are only used if DF_NEGATIVE is set in the flags. Otherwise,
 * the timestamps of the individual records are used. DF_NEGATIVE
 * is used for whole-domain negative caching.
 * By convention, the ttl should be set to 0, and the ttl should
 * be set correctly when DF_NEGATIVE is not set. */
int init_cent(dns_cent_t *cent, const unsigned char *qname, time_t ttl, time_t ts, unsigned flags  DBGPARAM)
{
	int i;
	size_t namesz=rhnlen(qname);

	cent->qname=cache_malloc(namesz);
	if (cent->qname == NULL)
		return 0;
	memcpy(cent->qname,qname,namesz);
	cent->num_rrs=0;
	cent->cs=sizeof(dns_cent_t)+namesz;
	cent->flags=flags;
	cent->ts=ts;
	cent->ttl=ttl;
	cent->lent=NULL;
	for(i=0;i<T_NUM;i++)
		cent->rr[i]=NULL;
	cent->c_ns=cundef;
	cent->c_soa=cundef;
	return 1;
}

/*
 * Create a rr record holder using the given values.
 */
static rr_bucket_t *create_rr(unsigned short dlen, void *data  DBGPARAM)
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
int add_cent_rrset(dns_cent_t *cent, int tp, time_t ttl, time_t ts, unsigned flags  DBGPARAM)
{
	rr_set_t *rrset=cache_malloc(sizeof(rr_set_t));
	cent->rr[tp-T_MIN]=rrset;
	if (!rrset)
		return 0;
	rrset->lent=NULL;
	rrset->ttl=ttl;
	rrset->ts=ts;
	rrset->flags=flags;
	rrset->rrs=NULL;
	cent->cs += sizeof(rr_set_t);
	cent->num_rrs++;
	/* If we add a rrset, even a negative one, the domain is not negative any more. */
	if (cent->flags&DF_NEGATIVE) {
		cent->flags &= ~DF_NEGATIVE;
		cent->ttl=0;
		/* need to remove the cent from the lent list. */
		if (cent->lent) {
			remove_rrl(cent->lent  DBGARG);
			cent->lent=NULL;
		}
	}
	return 1;
}

/*
 * Adds a rr record to a cent. For cache.c internal use.
 */
static int add_cent_rr_int(dns_cent_t *cent, int tp, time_t ttl, time_t ts, unsigned flags,
			   unsigned dlen, void *data, rr_bucket_t **rtail  DBGPARAM)
{
	rr_bucket_t *rr;
	rr_set_t *rrset;
	if ((cent->flags&DF_LOCAL) && !(flags&CF_LOCAL)) {
		/* ignore. Local has precedence. */
		return 1;
	}
	if (!(rr=create_rr(dlen,data  DBGARG)))
		return 0;
	if(!(rtail && *rtail)) {
		if (!cent->rr[tp-T_MIN]) {
			if (!add_cent_rrset(cent, tp, ttl, ts, flags  DBGARG))
				goto cleanup_return;
		}
		/* do the linking work */
		rrset=cent->rr[tp-T_MIN];
		rr->next=rrset->rrs;
		rrset->rrs=rr;
	}
	else {
		/* append at the end */
		rr->next=(*rtail)->next;
		(*rtail)->next=rr;
	}
	if(rtail) *rtail=rr;
	cent->cs += sizeof(rr_bucket_t)+rr->rdlen;
#if DEBUG>0
	rrset=cent->rr[tp-T_MIN];
	if (rrset->flags&CF_NEGATIVE)
		DEBUG_MSG("Tried to add rr to a rrset with CF_NEGATIVE set! flags=%i\n",rrset->flags);
#endif
	return 1;
 cleanup_return:
	free_rr(*rr);
	free(rr);
	return 0;
}


/* Add an rr to a cache entry, giving the ttl, the data length, the rr type (tp)
 * and a pointer to the data. A record is allocated, and the data is copied into
 * it. Do this for all rrs in a cache entry.
 */
int add_cent_rr(dns_cent_t *cent, int tp , time_t ttl, time_t ts, unsigned flags,
		unsigned dlen, void *data  DBGPARAM)
{
	rr_bucket_t *rrb,*rtail=NULL;
	/* OK, some stupid nameservers feel inclined to return the same address twice. Grmbl... */
	if (cent->rr[tp-T_MIN]) {
		rrb=cent->rr[tp-T_MIN]->rrs;
		while (rrb) {
			if (rrb->rdlen==dlen && memcmp(rrb+1,data,dlen)==0)
				return 1;
			rtail=rrb;
			rrb=rrb->next;
		}
	}
	return add_cent_rr_int(cent,tp,ttl,ts,flags,dlen,data,&rtail  DBGARG);
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
		cent->flags &= ~DF_AUTH;
	}
	return rv;
}

/* Free the pointers contained in an rr record. If the rr record is on the heap,
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

/* Same as free_cent, but is suitable as cleanup handler */
void free_cent0(void *ptr)
{
	free_cent(ptr  DBG0);
}

/* Negate an existing cache entry and free any existing rr sets. */
void negate_cent(dns_cent_t *cent)
{
	int i;

	for (i=0;i<T_NUM;i++) {
		rr_set_t *rrs=cent->rr[i];
		if (rrs) {
			cent->cs -= del_rrset(rrs  DBG0);
			cent->rr[i]=NULL;
		}
	}
	cent->num_rrs=0;
	cent->flags |= DF_NEGATIVE;
}

inline static time_t get_rrlent_ts(rr_lent_t *le)
{
	return (le->rrset)?(le->rrset->ts):(le->cent->ts);
}

/* insert a rrset into the rr_l list. This modifies the rr_set_t if rrs is not NULL!
 * The rrset address needs to be constant afterwards.
 * Call with locks applied. */
static int insert_rrl(rr_set_t *rrs, dns_cent_t *cent, int tp)
{
	time_t ts;
	rr_lent_t *le,*ne;

	/* No need to add local records to the rr_l list, because purge_cache() ignores them anyway. */
	if((rrs && (rrs->flags&CF_LOCAL)) || (cent->flags&DF_LOCAL))
		return 1;

	if (!(ne=malloc(sizeof(rr_lent_t))))
		return 0;
	ne->rrset=rrs;
	ne->cent=cent;
	ne->tp=tp;
	ne->next=NULL;
	ne->prev=NULL;

	if(insert_sort) {
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
	finish:;
	}
	else { 
		/* simply append at the end, sorting will be done later with a more efficient algorithm. */
		ne->prev=rrset_l_tail;
		if(rrset_l_tail)
			rrset_l_tail->next=ne;
		else
			rrset_l=ne;
		rrset_l_tail=ne;
	}

	if (rrs)
		rrs->lent=ne;
	else
		cent->lent=ne;

	return 1;
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

/* Sort the rr_l list using merge sort, which can be more efficient than insertion sort used by rr_insert().
   Call with locks applied.
   Written by Paul Rombouts.
*/
static void sort_rrl()
{
	if(rrset_l) {
		unsigned int m;

		for(m=1;; m *= 2) {
			unsigned int nmerge=0,i,j;
			rr_lent_t *p,*q=rrset_l,**s= &rrset_l, **t;

			do {
				++nmerge;
				p=q;
				i=m;
				do {
					t= &q->next;
					q= *t;
				} while(--i && q);

				if(!q) break;
      
				i=j=m;
				for(;;) {
					if(get_rrlent_ts(p) <= get_rrlent_ts(q)) {
						*s= p;
						s= &p->next;
						p= *s;
						--i;
						if(!i) {
							*s= q;
							do {s= &q->next; q= *s;} while(--j && q);
							break;
						}
					}
					else { /* get_rrlent_ts(p) > get_rrlent_ts(q) */
						*s= q;
						s= &q->next;
						q= *s;
						--j;
						if(!j || !q) {
							*s= p;
							*t= q;
							s= t;
							break;
						}
					}
				}
			} while(q);

			if(nmerge<=1) break;
		}
	}

	{
		/* restore the backward links */
		rr_lent_t *p,*q=NULL;
		for(p=rrset_l; p; p=p->next) {p->prev=q; q=p;}
		rrset_l_tail=q;
	}
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
	{
		/* copy the name */
		size_t namesz=rhnlen(cent->qname);
		if (!(copy->qname=cache_malloc(namesz)))
			goto free_return_null;

		memcpy(copy->qname,cent->qname,namesz);
	}
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
 * If test is zero and the record is in the cache, we need rw-locks applied.
 * If test is nonzero, nothing will actually be deleted.
 * Substracts the size of the freed memory from cache_size (if test is zero).
 * Returns 1 if the rrset has been (or would have been) deleted.
 */
static int purge_rrset(dns_cent_t *cent, int tp, int test)
{
	rr_set_t *rrs=cent->rr[tp-T_MIN];
	if (rrs && !(rrs->flags&CF_NOPURGE || rrs->flags&CF_LOCAL) && timedout(rrs)) {
		/* well, it must go. */
		if(!test)
			cache_size -= del_cent_rrset(cent,tp  DBG0);
		return 1;
	}
	return 0;
}

/*
 * Purge a cent, deleting timed-out rrs (following the constraints noted in "purge_rrset").
 * Since the cent may actually become empty and be deleted, you may not use it after this call until
 * you refetch its address from the hash (if it is still there).
 * If test is zero and the record is in the cache, we need rw-locks applied.
 * If test is nonzero, nothing will actually be deleted.
 * Substracts the size of the freed memory from cache_size (if test is zero).
 * If delete is nonzero and the cent was purged empty and no longer needed, it is removed from the cache.
 * Returns -1 if the cent was (or would have been) completely removed,
 * otherwise returns the number of rrsets that were (or would have been) deleted.
 */
static int purge_cent(dns_cent_t *cent, int delete, int test)
{
	int i,npurge=0;

	for (i=T_MIN;i<=T_MAX;i++)
		npurge += purge_rrset(cent,i,test);

	/* if the record was purged empty, delete it from the cache. */
	if (delete && (cent->num_rrs==0 || (test && cent->num_rrs==npurge)) 
	    && (!(cent->flags&DF_NEGATIVE) ||
		(!(cent->flags&DF_LOCAL) && timedout(cent))))
	{
		if(!test)
			del_cache_ent(cent,NULL); /* this will subtract the cent's left size from cache_size */
		return -1;
	}

	if(!(cent->flags&DF_LOCAL)) {
		/* Set stale references to NS or SOA records back to undefined. */
		unsigned scnt=rhnsegcnt(cent->qname);
		if(cent->c_ns!=cundef) {
			rr_set_t *rrset=NULL;
			if(cent->c_ns==scnt)
				rrset=cent->rr[T_NS-T_MIN];
			else if(cent->c_ns<scnt) {
				dns_cent_t *ce=dns_lookup(skipsegs(cent->qname,scnt-cent->c_ns),NULL);
				if(ce) rrset=ce->rr[T_NS-T_MIN];
			}
			if(!rrset || !rrset->rrs || (!(rrset->flags&CF_LOCAL) && timedout(rrset))) {
				if(!test)
					cent->c_ns=cundef;
				++npurge;
			}
		}
		if(cent->c_soa!=cundef) {
			rr_set_t *rrset=NULL;
			if(cent->c_soa==scnt)
				rrset=cent->rr[T_SOA-T_MIN];
			else if(cent->c_soa<scnt) {
				dns_cent_t *ce=dns_lookup(skipsegs(cent->qname,scnt-cent->c_soa),NULL);
				if(ce) rrset=ce->rr[T_SOA-T_MIN];
			}
			if(!rrset || !rrset->rrs || (!(rrset->flags&CF_LOCAL) && timedout(rrset))) {
				if(!test)
					cent->c_soa=cundef;
				++npurge;
			}
		}
	}

	return npurge;
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
		      (le->cent->flags&DF_LOCAL))) {
			dns_cent_t *ce = le->cent;
			if (le->rrset)
				purge_rrset(ce, le->tp,0);
			/* Side effect: if purge_rrset called del_cent_rrset then le has been freed.
			 * ce, however, is still guaranteed to be valid. */
			if (ce->num_rrs==0 && (!(ce->flags&DF_NEGATIVE) ||
					       (!(ce->flags&DF_LOCAL) && timedout(ce))))
				del_cache_ent(ce,NULL);
		}
		le=next;
	}
	if (cache_size<=sz)
		return;

	/* we are still above the desired cache size. Well, delete records from the oldest to
	 * the newest. This is the case where nopurge records are deleted anyway. Only local
	 * records are kept in any case.*/
	if(!insert_sort) {
		sort_rrl();
		insert_sort=1; /* use insertion sort from now on */
	}

	le=rrset_l;
	while (le && cache_size>sz) {
		rr_lent_t *next=le->next;
		if (!((le->rrset && (le->rrset->flags&CF_LOCAL)) ||
		      (le->cent->flags&DF_LOCAL))) {
			dns_cent_t *ce = le->cent;
			if (le->rrset)
				cache_size -= del_cent_rrset(ce, le->tp  DBG0);
			/* this will also delete negative cache entries */
			if (ce->num_rrs==0)
				del_cache_ent(ce,NULL);
		}
		le=next;
	}
}

#define log_warn_read_error(f,item) \
        log_warn("%s encountered while reading %s from disk cache file.", \
        ferror(f)?"Error":feof(f)?"EOF":"Incomplete item",item)

/*
 * Load cache from disk and rebuild the hash tables.
 */
void read_disk_cache()
{
	/* The locks are done when we add items. */
	dns_cent_t ce;
	int dtsz=512;
	unsigned char *data;
	unsigned long cnt;
	FILE *f;

	char path[strlen(global.cache_dir)+sizeof("/pdnsd.cache")];

	stpcpy(stpcpy(path,global.cache_dir),"/pdnsd.cache");

	if (!(f=fopen(path,"r"))) {
		log_warn("Could not open disk cache file %s: %s",path,strerror(errno));
		return;
	}

	if (!(data = malloc(dtsz))) {
		goto fclose_exit;
	}

	/* Don't use insertion sort while reading caches entries from disk, because this can be
	   noticably inefficient with large cache files.
	   Entries are simply appended at the end of the rr_l list.
	   The rr_l list is sorted using a more efficient merge sort after we are done reading.
	*/
	insert_sort=0;

	{
		/* check cache version identifier */
		char buf[sizeof(cachverid)];
		if (fread(buf,sizeof(cachverid),1,f)!=1) {
			log_warn_read_error(f,"cache version identifier");
			goto free_data_fclose;
		}
		if(memcmp(buf,cachverid,sizeof(cachverid))) {
			log_warn("Cache file %s ignored because of incompatible version identifier",path);
			goto free_data_fclose;
		}
	}

	if (fread(&cnt,sizeof(cnt),1,f)!=1) {
		log_warn_read_error(f,"entry count");
		goto free_data_fclose;
	}

	for(;cnt>0;--cnt) {
		dns_file_t fe;
		unsigned char nb[256];
		unsigned num_rrs;
		unsigned char prevtp;
		if (fread(&fe,sizeof(fe),1,f)!=1) {
			log_warn_read_error(f,"cache entry header");
			goto free_data_fclose;
		}
		if (fe.qlen) {
			int i;
			if (fread(nb,fe.qlen,1,f)!=1) {
				log_warn_read_error(f,"domain name");
				goto free_data_fclose;
			}
			for(i=0;i<fe.qlen;) {
				unsigned lb=nb[i];
				if(!lb || lb>63 || (i += lb+1)>fe.qlen) {
					log_warn("Invalid domain name encountered while reading disk cache file.");
					goto free_data_fclose;
				}
			}
		}
		nb[fe.qlen]='\0';
		if (!init_cent(&ce, nb, fe.ttl, fe.ts, fe.flags  DBG0)) {
			goto free_data_fclose_exit;
		}
		ce.c_ns=fe.c_ns; ce.c_soa=fe.c_soa;

		/* now, read the rr's */
		prevtp=0;
		for (num_rrs=fe.num_rrs;num_rrs;--num_rrs) {
			rr_fset_t sh;
			unsigned num_rr;
			if (fread(&sh,sizeof(sh),1,f)!=1) {
				log_warn_read_error(f,"rr header");
				goto free_cent_data_fclose;
			}
			if(sh.tp<T_MIN || sh.tp>T_MAX) {
				log_warn("Invalid rr type encountered while reading disk cache file.");
				goto free_data_fclose;
			}
			if(sh.tp<=prevtp) {
				log_warn("Unexpected rr type encountered (smaller than the previous one) while reading disk cache file.");
				goto free_data_fclose;
			}
			prevtp=sh.tp;
			/* Add the rrset header in any case (needed for negative caching) */
			if(!add_cent_rrset(&ce, sh.tp, sh.ttl, sh.ts, sh.flags  DBG0)) {
				goto free_cent_data_fclose_exit;
			}
			for (num_rr=sh.num_rr;num_rr;--num_rr) {
				rr_fbucket_t rr;
				if (fread(&rr,sizeof(rr),1,f)!=1) {
					log_warn_read_error(f,"rr data length");
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
				if (rr.rdlen && fread(data,rr.rdlen,1,f)!=1) {
					log_warn_read_error(f,"rr data");
					goto free_cent_data_fclose;
				}
				if (!add_cent_rr(&ce,sh.tp,sh.ttl,sh.ts,sh.flags,rr.rdlen,data  DBG0)) {
					goto free_cent_data_fclose_exit;
				}
			}
		}
		add_cache(&ce);
		free_cent(&ce  DBG0);
	}
#ifdef DEBUG_HASH
	free(data);
	fclose(f);
	dumphash();
	goto sort_return;
#else
	goto free_data_fclose;
#endif

 free_cent_data_fclose:
	free_cent(&ce  DBG0);
 free_data_fclose:
	free(data);
	fclose(f);
#ifdef DEBUG_HASH
 sort_return:
#endif
	/* Do we need read/write locks to sort the rr_l list?
	   As long as at most one thread is sorting, it is OK for the other threads
	   to read the cache, providing they do not add or delete anything.
	*/
	lock_cache_r();
	if(!insert_sort) {
		sort_rrl();
		insert_sort=1;
	}
	unlock_cache_r();
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
static int write_rrset(int tp, rr_set_t *rrs, FILE *f)
{
	rr_bucket_t *rr;
	rr_fset_t sh;
	rr_fbucket_t rf;
	unsigned num_rr;

	sh.tp=tp;

	num_rr=0;
	for(rr=rrs->rrs; rr && num_rr<255; rr=rr->next) ++num_rr;
	sh.num_rr=num_rr;
	sh.ttl=rrs->ttl;
	sh.ts=rrs->ts;
	sh.flags=rrs->flags;

	if (fwrite(&sh,sizeof(sh),1,f)!=1) {
		log_error("Error while writing rr header to disk cache: %s", strerror(errno));
		return 0;
	}

	rr=rrs->rrs;
	for(; num_rr; --num_rr) {
		rf.rdlen=rr->rdlen;
		if (fwrite(&rf,sizeof(rf),1,f)!=1 || (rf.rdlen && fwrite((rr+1),rf.rdlen,1,f)!=1)) {
			log_error("Error while writing rr data to disk cache: %s", strerror(errno));
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
	unsigned long en=0;
	dns_hash_pos_t pos;
	FILE *f;
	unsigned long num_rrs_errs=0;
#	define MAX_NUM_RRS_ERRS 10

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

	/* Write the cache version identifier */
	if (fwrite(cachverid,sizeof(cachverid),1,f)!=1) {
		log_error("Error while writing cache version identifier to disk cache: %s", strerror(errno));
		goto fclose_unlock;
	}

	for (le=fetch_first(&pos); le; le=fetch_next(&pos)) {
		/* count the rr's */
		if((le->flags&DF_NEGATIVE) && !(le->flags&DF_LOCAL))
			++en;
		else {
			for (j=0;j<T_NUM;j++) {
				if (le->rr[j] && !(le->rr[j]->flags&CF_LOCAL)) {
					++en;
					break;
				}
			}
		}
	}
	if (fwrite(&en,sizeof(en),1,f)!=1) {
		log_error("Error while writing entry count to disk cache: %s", strerror(errno));
		goto fclose_unlock;
	}

	for (le=fetch_first(&pos); le; le=fetch_next(&pos)) {
		/* now, write the rr's */
		if((le->flags&DF_NEGATIVE) && !(le->flags&DF_LOCAL))
			goto write_rrs;
		for (j=0;j<T_NUM;j++) {
			if (le->rr[j] && !(le->rr[j]->flags&CF_LOCAL)) {
				goto write_rrs;
			}
		}
		continue;
	       write_rrs:
		{
			dns_file_t df;
			int num_rrs;
			df.qlen=rhnlen(le->qname)-1; /* Don't include the null byte at the end */
			df.flags=le->flags;
			df.ts=le->ts;
			df.ttl=le->ttl;
			df.c_ns=le->c_ns; df.c_soa=le->c_soa;
			df.num_rrs=0; num_rrs=0;
			for (j=0;j<T_NUM;j++) {
				rr_set_t *rrset=le->rr[j];
				if(rrset) {
					++num_rrs;
					if(!(rrset->flags&CF_LOCAL))
						++df.num_rrs;
				}
			}
			if(num_rrs!=le->num_rrs && ++num_rrs_errs<=MAX_NUM_RRS_ERRS) {
				char buf[256];
				log_warn("Counted %d rr record types for %s but cached counter=%d",
					 num_rrs,rhn2str(le->qname,buf,sizeof(buf)),le->num_rrs);
			}
			if (fwrite(&df,sizeof(df),1,f)!=1) {
				log_error("Error while writing cache entry header to disk cache: %s", strerror(errno));
				goto fclose_unlock;
			}
			if (df.qlen && fwrite(le->qname,df.qlen,1,f)!=1) {
				log_error("Error while writing domain name to disk cache: %s", strerror(errno));
				goto fclose_unlock;
			}

			for (j=0;j<T_NUM;j++) {
				rr_set_t *rrset=le->rr[j];
				if(rrset && !(rrset->flags&CF_LOCAL)) {
					if(!write_rrset(j+T_MIN,rrset,f))
						goto fclose_unlock;
				}
			}
		}
	}
	if(fclose(f)) {
		log_error("Could not close cache file %s after writing cache: %s", path,strerror(errno));
	}
	softunlock_cache_r();
	DEBUG_MSGC("Finished writing cache to disk.\n");
	return;

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
static int cr_check_add(dns_cent_t *cent, int tp, time_t ttl, time_t ts, unsigned flags)
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


inline static void adjust_ttl(rr_set_t *rrset)
{
	if (rrset->flags&CF_NOCACHE) {
		rrset->flags &= ~CF_NOCACHE;
		rrset->ttl=0;
	}
	else {
		if(rrset->ttl<global.min_ttl)
			rrset->ttl=global.min_ttl;
		else if(rrset->ttl>global.max_ttl)
			rrset->ttl=global.max_ttl;
	}
}

/*
 * Add a ready built dns_cent_t to the hashes, purge if necessary to not exceed cache size
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
	dns_hash_loc_t loc;
	int i;

	lock_cache_rw();
 retry:
	if (!(ce=dns_lookup(cent->qname,&loc))) {
		/* if the new entry doesn't contain any information,
		   don't try to add it to the cache because purge_cache() will not
		   be able to get rid of it.
		*/
		if(cent->num_rrs==0 && !(cent->flags&DF_NEGATIVE))
			goto purge_cache_return;

		if(!(ce=copy_cent(cent  DBG0))) {
			goto warn_unlock_cache_return;
		}
		/* Add the rrs to the rr list */
		for (i=0;i<T_NUM;i++) {
			if (ce->rr[i]) {
				adjust_ttl(ce->rr[i]);
				if (!insert_rrl(ce->rr[i],ce,i+T_MIN)) {
					goto free_cent_unlock_cache_return;
				}
			}
		}
		/* If this record is negatively cached, add the cent to the rr list. */
		if (ce->flags&DF_NEGATIVE) {
			if (!insert_rrl(NULL,ce,-1)) {
				goto free_cent_unlock_cache_return;
			}
		}
		add_dns_hash(ce,&loc);
		ent_num++;
	} else {
		if (cent->flags&DF_NEGATIVE) {
			/* the new entry is negative. So, we need to delete the whole cent,
			 * and then generate a new one. */
			for (i=0;i<T_NUM;i++) {
				rr_set_t *cerrs=ce->rr[i];
				if (cerrs && cerrs->flags&CF_LOCAL) {
					goto unlock_cache_return; /* Do not clobber local records */
				}
			}
			del_cache_ent(ce,&loc);
			goto retry;
		}
		purge_cent(ce, 0,0);
		/* We have a record; add the rrsets replacing old ones */
		cache_size-=ce->cs;
		for (i=0;i<T_NUM;i++) {
			rr_set_t *centrrs=cent->rr[i],*cerrs=ce->rr[i];
			/* Local records have precedence.
			   Records from answer sections have precedence over additional (off-topic) records.
			   Answers obtained from root servers have precedence over additional records
			   from other servers. */
			if (centrrs &&
			    !(cerrs &&
			      ((!(centrrs->flags&CF_LOCAL) && (cerrs->flags&CF_LOCAL)) ||
			       ((centrrs->flags&CF_ADDITIONAL) && (!(cerrs->flags&CF_ADDITIONAL) ||
								   (!(centrrs->flags&CF_ROOTSERV) &&
								    (cerrs->flags&CF_ROOTSERV))) &&
				!timedout(cerrs)))))
			{
				rr_bucket_t *rr,*rtail;

				del_cent_rrset(ce,i+T_MIN  DBG0);

				if (!cr_check_add(ce, i+T_MIN, centrrs->ttl, centrrs->ts, centrrs->flags))
					continue;  /* the new record has been deleted as a conflict resolution measure. */

				/* pre-initialize a rrset_t for the case we have a negative cached
				 * rrset, in which case no further rrs will be added. */
				if (!add_cent_rrset(ce, i+T_MIN, centrrs->ttl, centrrs->ts, centrrs->flags  DBG0)) {
					goto addsize_unlock_cache_return;
				}
				rr=centrrs->rrs; rtail=NULL;
				while (rr) {
					if (!add_cent_rr_int(ce,i+T_MIN,centrrs->ttl, centrrs->ts, centrrs->flags,
							     rr->rdlen, rr+1, &rtail  DBG0))
					{
						/* cleanup this entry */
						goto cleanup_cent_unlock_cache_return;
					}
					rr=rr->next;
				}
				adjust_ttl(ce->rr[i]);
				if (!insert_rrl(ce->rr[i],ce,i+T_MIN)) {
					goto cleanup_cent_unlock_cache_return;
				}
			}
		}
		ce->flags |= (cent->flags&(DF_AUTH|DF_WILD));
		if(cent->c_ns!=cundef && (ce->c_ns==cundef || ce->c_ns<cent->c_ns))
			ce->c_ns=cent->c_ns;
		if(cent->c_soa!=cundef && (ce->c_soa==cundef || ce->c_soa<cent->c_soa))
			ce->c_soa=cent->c_soa;
	}

	cache_size += ce->cs;
 purge_cache_return:
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
  Convert A (and AAA) records in a ready built cache entry to PTR records suitable for reverse resolving
  of numeric addresses and add them to the cache.
*/
int add_reverse_cache(dns_cent_t * cent)
{
	int tp;

	for(tp=T_A;;) {
		rr_set_t *rrset=cent->rr[tp-T_MIN];
		if(rrset) {
			rr_bucket_t *rr=rrset->rrs;
			while(rr) {
				dns_cent_t ce;
				unsigned char buf[256],rhn[256];
				if(!a2ptrstr((pdnsd_ca *)(rr+1),tp,buf) || !str2rhn(buf,rhn))
					return 0;
				if(!init_cent(&ce, rhn, cent->ttl, cent->ts, cent->flags  DBG0))
					return 0;
				if(!add_cent_rr(&ce,T_PTR,rrset->ttl,rrset->ts,rrset->flags,rhnlen(cent->qname),cent->qname  DBG0)) {
					free_cent(&ce  DBG0);
					return 0;
				}
				ce.rr[T_NS-T_MIN]=cent->rr[T_NS-T_MIN];
				ce.rr[T_SOA-T_MIN]=cent->rr[T_SOA-T_MIN];
				add_cache(&ce);
				ce.rr[T_NS-T_MIN]=NULL;
				ce.rr[T_SOA-T_MIN]=NULL;
				free_cent(&ce  DBG0);
				rr=rr->next;
			}
		}
#if defined(DNS_NEW_RRS) && defined(ENABLE_IPV6)
		if(tp==T_AAAA)
			break;
		tp=T_AAAA;
#else
		break;
#endif
	}
	return 1;
}


/* 
   Delete a cent from the cache. Call with write locks applied.
   Does not delete corresponding entry in hash table, call del_cache_ent()
   or del_cache() for that.
*/
void del_cent(dns_cent_t *cent)
{
	cache_size -= cent->cs;

	/* free the data referred by the cent and the cent itself */
	free_cent(cent  DBG0);
	free(cent);

	ent_num--;
}

/*
 * Delete a cent from the cache. Call with write locks applied.
 */
static void del_cache_ent(dns_cent_t *cent,dns_hash_loc_t *loc)
{
	dns_cent_t *data;

	/* Delete from the hash */
	if(loc)
		data=del_dns_hash_ent(loc);
	else
		data=del_dns_hash(cent->qname);
	if(!data) {
		log_warn("Cache entry not found by del_dns_hash() in %s, line %d",__FILE__,__LINE__);
	}
	else if(data!=cent) {
		log_warn("pointer returned by del_dns_hash() does not match cache entry in %s, line %d",__FILE__,__LINE__);
	}
	del_cent(cent);
}

/* Delete a cached record. Performs locking. Call this from the outside, NOT del_cache_ent */
void del_cache(const unsigned char *name)
{
	dns_cent_t *cent;

	lock_cache_rw();
	if ((cent=del_dns_hash(name))) {
		del_cent(cent);
	}
	unlock_cache_rw();
}


/* Invalidate a record by resetting the fetch time to 0. This means that it will be refreshed
 * if possible (and will only be served when purge_cache=off;) */
void invalidate_record(const unsigned char *name)
{
	dns_cent_t *ce;
	int i;

	lock_cache_rw();
	if ((ce=dns_lookup(name,NULL))) {
		for (i=0;i<T_NUM;i++) {
			rr_set_t *rrs=ce->rr[i];
			if (rrs) {
				rrs->ts=0;
				rrs->flags &= ~CF_AUTH;
			}
		}
		/* set the cent time to 0 (for the case that this was negative) */
		ce->ts=0;
		ce->flags &= ~DF_AUTH;
	}
	unlock_cache_rw();
}


/*
  Set flags of the cache entry with the specified name.
  Don't use this to set the DF_NEGATIVE flag, or you will
  risk leaving the cache in an inconsistent state.
  Returns 0 if the cache entry cannot be found, otherwise 1.
 */
int set_cent_flags(const unsigned char *name, unsigned flags)
{
	dns_cent_t *ret;
	lock_cache_rw();
	ret=dns_lookup(name,NULL);
	if (ret) {
		ret->flags |= flags;
	}
	unlock_cache_rw();
	return ret!=NULL;
}

unsigned char *getlocalowner(unsigned char *name,int tp)
{
	unsigned char *ret=NULL;
	dns_cent_t *ce;
	unsigned lb;

	lock_cache_r();
	if((lb = *name)) {
		while(name += lb+1, lb = *name) {
			if((ce=dns_lookup(name,NULL))) {
				if(!(ce->flags&DF_LOCAL))
					break;
				if(have_rr(ce,tp)) {
					ret=name;
					break;
				}
			}
		}
	}
	unlock_cache_r();

	return ret;
}


/* Lookup an entry in the cache using name (in length byte -  string notation).
 * For thread safety, a copy must be returned, so delete it after use, by first doing
 * free_cent to remove the rrs and then by freeing the returned pointer.
 * If wild is nonzero, and name can't be found in the cache, lookup_cache()
 * will search up the name hierarchy for a record with the DF_NEGATIVE or DF_WILD flag set.
 */
dns_cent_t *lookup_cache(const unsigned char *name, int *wild)
{
	int purge=0;
	dns_cent_t *ret;

	/* First try with only read access to the cache. */
	lock_cache_r();
	ret=dns_lookup(name,NULL);
	if(wild) {
		*wild=0;
		if(!ret) {
			const unsigned char *nm=name;
			unsigned lb=*nm;
			if(lb) {
				while(nm += lb+1, lb = *nm) {
					if ((ret=dns_lookup(nm,NULL))) {
						if(ret->flags&DF_NEGATIVE)
							/* use this entry */
							*wild=w_neg;
						else if(ret->flags&DF_WILD) {
							unsigned char buf[256];
							buf[0]=1; buf[1]='*';
							/* When we get here, at least element of name
							   has been removed, so assuming name is not longer
							   than 256 bytes, the remainder is guaranteed to
							   fit into 254 bytes */
							rhncpy(&buf[2],nm);
							ret=dns_lookup(buf,NULL);
							if(ret)
								*wild=w_wild;
						}
						else if(ret->flags&DF_LOCAL)
							*wild=w_locnerr;
						else
							ret=NULL;
						break;
					}
				}
			}
		}
	}
	if (ret) {
		if(!(purge=purge_cent(ret, 1,1))) /* test only, don't remove anything yet! */
			ret=copy_cent(ret  DBG1);
	}
	unlock_cache_r();

	if(purge) {
		/* we need exclusive read and write access before we delete anything. */
		lock_cache_rw();
		ret=dns_lookup(name,NULL);
		if(wild) {
			*wild=0;
			if(!ret) {
				const unsigned char *nm=name;
				unsigned lb=*nm;
				if(lb) {
					while(nm += lb+1, lb = *nm) {
						if ((ret=dns_lookup(nm,NULL))) {
							if(ret->flags&DF_NEGATIVE)
								/* use this entry */
								*wild=w_neg;
							else if(ret->flags&DF_WILD) {
								unsigned char buf[256];
								buf[0]=1; buf[1]='*';
								rhncpy(&buf[2],nm);
								ret=dns_lookup(buf,NULL);
								if(ret)
									*wild=w_wild;
							}
							else if(ret->flags&DF_LOCAL)
								*wild=w_locnerr;
							else
								ret=NULL;
							break;
						}
					}
				}
			}
		}
		if (ret) {
			if(purge_cent(ret, 1,0)<0)
				ret=NULL;
			else
				ret=copy_cent(ret  DBG1);
		}
		unlock_cache_rw();
	}

	return ret;
}

#if 0
/* Add an rr to an existing cache entry or create a new entry if necessary.
 * The rr is treated with the precedence of an additional or off-topic record, ie. regularly retrieved
 * have precedence.
 * You cannot add a negative additional record. Makes no sense anyway. */
int add_cache_rr_add(const unsigned char *name, int tp, time_t ttl, time_t ts, unsigned flags, unsigned dlen, void *data, unsigned long serial)
{
	dns_hash_loc_t loc;
	dns_cent_t *ret;
	rr_set_t *rrs;
	int rv=0;

	lock_cache_rw();
	if (!(ret=dns_lookup(name,&loc))) {
		if (!(ret=cache_malloc(sizeof(dns_cent_t))))
			goto unlock_return;
		if(!init_cent(ret, name, 0, ts, 0  DBG1)) {
			cache_free(ret);
			goto unlock_return;
		}
		add_dns_hash(ret,&loc);
		ent_num++;
	}
	else {
		/* purge the record. */
		purge_cent(ret,0,0);
		cache_size-=ret->cs;
	}
	rrs=ret->rr[tp-T_MIN];
	if (rrs &&
	    ((rrs->flags&CF_NEGATIVE && !(rrs->flags&CF_LOCAL)) ||
	     (rrs->flags&CF_NOPURGE && timedout(rrs)) ||
	     (rrs->flags&CF_ADDITIONAL && rrs->serial!=serial) ||
	     (rrs->serial==serial && rrs->ttl!=(ttl<global.min_ttl?global.min_ttl:(ttl>global.max_ttl?global.max_ttl:ttl))))) {
		del_cent_rrset(ret,tp  DBG0);
		rrs=NULL;
	}
	if (rrs==NULL || rrs->serial==serial) {
		if (cr_check_add(ret,tp,ttl,ts,flags)) {
			if (add_cent_rr(ret,tp,ttl,ts,flags,dlen,data,serial  DBG0)) {
				rr_set_t *rrsnew;
				if (!rrs && (rrsnew=ret->rr[tp-T_MIN]) && !insert_rrl(rrsnew,ret,tp)) {
					del_cent_rrset(ret,tp  DBG0);
				}
				else {
					cache_size+=ret->cs;
					purge_cent(ret,1,0);
					rv=1;
					goto unlock_return;
				}
			}
		}
	} else {
		rv=1;
	}
	cache_size+=ret->cs;

 unlock_return:
	unlock_cache_rw();
	return rv;
}
#endif

/* Report the cache status to the file descriptor f, for the status fifo (see status.c) */
int report_cache_stat(int f)
{
	long mc=(long)global.perm_cache*1024+MCSZ;
	double csz=(((double)cache_size)/mc)*100;
	fsprintf_or_return(f,"\nCache status:\n=============\n");
	fsprintf_or_return(f,"%ld kB maximum disk cache size.\n",global.perm_cache);
	fsprintf_or_return(f,"%ld of %ld bytes (%.3g%%) memory cache used in %ld entries.\n",cache_size,mc,csz,ent_num);
	return 0;
}


#define timestamp2str(ts,now,buf)								\
{												\
	struct tm tstm;										\
	if(!((ts) && localtime_r(&(ts), &tstm) &&						\
	     strftime(buf, sizeof(buf),								\
		      ((ts)<=(now) && (now)-(ts)<365*24*60*60/2)?"    %m/%d %T":"%Y/%m/%d %T",	\
		      &tstm)>0))								\
		strcpy(buf,"                  ");						\
}

/* Dump contents of a cache entry to file descriptor fd.
   Returns 1 on success, -1 if there is an IO error.
*/
static int dump_cent(int fd, dns_cent_t *cent)
{
	time_t now;
	char tstr[sizeof "2000/12/31 23:59:59"],dbuf[1024];

	fsprintf_or_return(fd,"%s\n",rhn2str(cent->qname,dbuf,sizeof(dbuf)));
	now=time(NULL);

	if(cent->flags&DF_NEGATIVE) {
		timestamp2str(cent->ts,now,tstr);
		fsprintf_or_return(fd,"%s    (domain negated)\n",tstr);
	}
	else {
		int i;
		for(i=0;i<T_NUM;++i) {
			rr_set_t *rrset=cent->rr[i];
			if (rrset) {
				timestamp2str(rrset->ts,now,tstr);
				if(rrset->flags&CF_NEGATIVE) {
					fsprintf_or_return(fd,"%s    %-7s (negated)\n",tstr,rr_info[i].name);
				}
				else {
					rr_bucket_t *rr=rrset->rrs;
					while(rr) {
						switch (i+T_MIN) {
						case T_CNAME:
						case T_MB:
						case T_MD:
						case T_MF:
						case T_MG:
						case T_MR:
						case T_NS:
						case T_PTR:
							rhn2str((unsigned char *)(rr+1),dbuf,sizeof(dbuf));
							break;
						case T_MINFO:
#ifdef DNS_NEW_RRS
						case T_RP:
#endif
						{
							unsigned char *p=(unsigned char *)(rr+1);
							int n;
							rhn2str(p,dbuf,sizeof(dbuf));
							n=strlen(dbuf);
							dbuf[n++] = ' ';
							if(n>=sizeof(dbuf))
								goto hex_dump;
							rhn2str(skiprhn(p),dbuf+n,sizeof(dbuf)-n);
						}
						break;
						case T_MX:
#ifdef DNS_NEW_RRS
						case T_AFSDB:
						case T_RT:
						case T_KX:
#endif
						{
							unsigned char *p=(unsigned char *)(rr+1);
							unsigned pref;
							int n;
							GETINT16(pref,p);
							n=sprintf(dbuf,"%u ",pref);
							if(n<0) goto hex_dump;
							rhn2str(p,dbuf+n,sizeof(dbuf)-n);
						}
						break;
						case T_SOA:
						{
							unsigned char *p=(unsigned char *)(rr+1);
							char *q;
							int n,rem;
							uint32_t serial,refresh,retry,expire,minimum;
							rhn2str(p,dbuf,sizeof(dbuf));
							n=strlen(dbuf);
							dbuf[n++] = ' ';
							if(n>=sizeof(dbuf))
								goto hex_dump;
							q=dbuf+n;
							rem=sizeof(dbuf)-n;
							p=skiprhn(p);
							rhn2str(p,q,rem);
							n=strlen(q);
							q[n++] = ' ';
							if(n>=rem)
								goto hex_dump;
							q += n;
							rem -= n;
							p=skiprhn(p);
							GETINT32(serial,p);
							GETINT32(refresh,p);
							GETINT32(retry,p);
							GETINT32(expire,p);
							GETINT32(minimum,p);
							n=snprintf(q,rem,"%lu %lu %lu %lu %lu",
								   (unsigned long)serial,(unsigned long)refresh,
								   (unsigned long)retry,(unsigned long)expire,
								   (unsigned long)minimum);
							if(n<0 || n>=rem)
								goto hex_dump;
						}
						break;
						case T_HINFO:
						case T_TXT:
						{
							/* TXT records are not necessarily validated
							   before they are stored in the cache, so
							   we need to be careful. */
							unsigned char *p=(unsigned char *)(rr+1);
							char *q=dbuf;
							int j=0,n,rem=sizeof(dbuf);
							while(j<rr->rdlen) {
								unsigned lb;
								if(rem<3)
									goto hex_dump;
								if(j) {
									*q++ = ' ';
									--rem;
								}
								*q++ = '"';
								--rem;
								lb=*p++;
								if((j += lb+1)>rr->rdlen)
									goto hex_dump;
								n=escapestr(p,lb,q,rem);
								if(n<0 || n+1>=rem)
									goto hex_dump;
								q += n;
								*q++ = '"';
								rem -= n+1;
								p += lb;
							}
							*q=0;
						}
						break;
#ifdef DNS_NEW_RRS
						case T_PX:
						{
							unsigned char *p=(unsigned char *)(rr+1);
							char *q;
							unsigned pref;
							int n,rem;
							GETINT16(pref,p);
							n=sprintf(dbuf,"%u ",pref);
							if(n<0) goto hex_dump;
							q=dbuf+n;
							rem=sizeof(dbuf)-n;
							rhn2str(p,q,rem);
							n=strlen(q);
							q[n++] = ' ';
							if(n>=rem)
								goto hex_dump;
							rhn2str(skiprhn(p),q+n,rem-n);
						}
						break;
						case T_SRV:
						{
							unsigned char *p=(unsigned char *)(rr+1);
							unsigned priority,weight,port;
							int n;
							GETINT16(priority,p);
							GETINT16(weight,p);
							GETINT16(port,p);
							n=sprintf(dbuf,"%u %u %u ",priority,weight,port);
							if(n<0) goto hex_dump;
							rhn2str(p,dbuf+n,sizeof(dbuf)-n);
						}
						break;
						case T_NXT:
						{
							unsigned char *p=(unsigned char *)(rr+1);
							int n,rlen;
							rhn2str(p,dbuf,sizeof(dbuf));
							n=strlen(dbuf);
							dbuf[n++] = ' ';
							if(n>=sizeof(dbuf))
								goto hex_dump;
							rlen=rhnlen(p);
							hexdump(p+rlen,rr->rdlen-rlen,dbuf+n,sizeof(dbuf)-n);
						}
						break;
						case T_NAPTR:
						{
							unsigned char *p=(unsigned char *)(rr+1);
							char *q;
							unsigned order,pref;
							int n,rem,j;
							GETINT16(order,p);
							GETINT16(pref,p);
							n=sprintf(dbuf,"%u %u ",order,pref);
							if(n<0) goto hex_dump;
							q=dbuf+n;
							rem=sizeof(dbuf)-n;
							for (j=0;j<3;++j) {
								unsigned lb;
								if(rem<2)
									goto hex_dump;
								*q++ = '"';
								--rem;
								lb=*p++;
								n=escapestr(p,lb,q,rem);
								if(n<0 || n+2>=rem)
									goto hex_dump;
								q += n;
								*q++ = '"';
								*q++ = ' ';
								rem -= n+2;
								p += lb;
							}
							rhn2str(p,q,rem);
						}
						break;
						case T_LOC:
						{
							/* Binary data length has not necessarily been validated */
							if(rr->rdlen!=16)
								goto hex_dump;
							if(!loc2str(rr+1,dbuf,sizeof(dbuf)))
								goto hex_dump;
						}
						break;
#endif
						case T_A:
							if (!inet_ntop(AF_INET,rr+1,dbuf,sizeof(dbuf)))
								goto hex_dump;
							break;
#if defined(DNS_NEW_RRS) && defined(AF_INET6)
						case T_AAAA:
							if (!inet_ntop(AF_INET6,rr+1,dbuf,sizeof(dbuf)))
								goto hex_dump;
							break;
#endif
						default:
						hex_dump:
							hexdump(rr+1,rr->rdlen,dbuf,sizeof(dbuf));
						}
						fsprintf_or_return(fd,"%s    %-7s %s\n",tstr,rr_info[i].name,dbuf);
						rr=rr->next;
					}
				}
			}
		}
	}
	fsprintf_or_return(fd,"\n");
	return 1;
}

/* Dump cache contents to file descriptor fd.
   If name is not null, restricts information to that name,
   otherwise dumps information about all names found in the cache.
   Returns 1 on success, 0 if the name is not found, -1 is there is an IO error.
   Mainly for debugging purposes.
*/
int dump_cache(int fd, const unsigned char *name)
{
	int rv=0;
	lock_cache_r();
	if(name) {
		dns_cent_t *cent=dns_lookup(name,NULL);
		if(cent)
			rv=dump_cent(fd,cent);
	}
	else {
		dns_cent_t *cent;
		dns_hash_pos_t pos;
		for (cent=fetch_first(&pos); cent; cent=fetch_next(&pos)) {
			if((rv=dump_cent(fd,cent))<0)
				break;
		}
	}
	unlock_cache_r();
	return rv;
}


#if DEBUG>0

/* Added by Paul Rombouts: This is only used in debug messages. */
const char cflgnames[NCFLAGS*3]={'N','E','G','L','O','C','A','U','T','N','O','C','A','D','D','N','O','P','R','T','S'};
const char dflgnames[NDFLAGS*3]={'N','E','G','L','O','C','A','U','T','W','L','D'};

char *flags2str(unsigned flags,char *buf,int nflags,const char *flgnames)
{
	char *p=buf;
	int i,nflgchars=3*nflags;
	for(i=0;i<nflgchars;i+=3) {
		if(flags&1) {
			if(p>buf) *p++='|';
			p=mempcpy(p,&flgnames[i],3);
		}
		flags >>= 1;
	}
	if(p==buf)
		*p++='0';
	*p=0;
	return buf;
}
#endif
