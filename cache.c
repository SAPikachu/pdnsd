/* cache.c - Keep the dns caches.
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
#include "ipvers.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: cache.c,v 1.9 2000/06/04 21:22:18 thomas Exp $";
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
 */

/*
 * This is the size the memory cache may exceed the size of the perm cache
 */
#define MCSZ 10240

dns_hash_t dns_hash;

rr_lent_t *rrset_l=NULL;
rr_lent_t *rrset_l_tail=NULL;

/*
 * We do not count the hash table sizes here. Those are very small compared
 * to the cache entries.
 */
unsigned long cache_size=0;
unsigned long ent_num=0;

int cache_w_lock=0;
int cache_r_lock=0;

pthread_mutex_t lock_mutex;

/*
 * Prototypes for internal use
 */
void del_cache_int(dns_cent_t *cent);

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
 * A possible danger under high load conditions is that writes are delayed a long time because the
 * read operations do not have to wait for the read lock to clear and thus stuff the readlock close.
 * Lets see.
 */
static INLINE void lock_cache_r(void)
{
	int lk=0;
	while (!lk)  {
		pthread_mutex_lock(&lock_mutex);
		if (!cache_w_lock) {
			lk=1;
			cache_r_lock++;
		}
		pthread_mutex_unlock(&lock_mutex);
		if (!lk)
			usleep(1000); /*give contol back to the scheduler instead of hammering the lock close*/
	}
}

static INLINE void unlock_cache_r(void)
{
	pthread_mutex_lock(&lock_mutex);
	if (cache_r_lock>0) 
		cache_r_lock--;
	pthread_mutex_unlock(&lock_mutex);
}

/*
 * Lock/unlock cache for reading and writing. Concurrent reads and writes are forbidden.
 * Do this only if you actually modify the cache.
 * DO NOT MIX THE LOCK TYPES UP WHEN LOCKING/UNLOCKING!
 * (cant say it often enough)
 */
static INLINE void lock_cache_rw(void)
{
	int lk=0;
	while (!lk)  {
		pthread_mutex_lock(&lock_mutex);
		if (!(cache_w_lock || cache_r_lock)) {
			lk=1;
			cache_w_lock=1;
		}
		pthread_mutex_unlock(&lock_mutex);
		if (!lk)
			usleep(1000); /*give contol back to the scheduler instead of hammering the lock close*/
	}
}

static INLINE void unlock_cache_rw(void)
{
	pthread_mutex_lock(&lock_mutex);
	cache_w_lock=0;
	pthread_mutex_unlock(&lock_mutex);
}

/*
 * Serial numbers: Serial numbers are used when additional records are added to the cache: serial numbers are unique to each
 * query, so we can determine whether data was added by the query just executed (records can coexist) or not (records must
 * be replaced). A serial of 0 is special and will not be used by any query. All records added added authoritatively (as
 * chunk) or read from a file can have no query in process and therefore have serial 0, which is != any other serial.
 */

unsigned long l_serial=1;

unsigned long get_serial ()
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
	mk_dns_hash(&dns_hash);
	pthread_mutex_init(&lock_mutex,NULL);
}

/* Delete the cache. Call only once */
void destroy_cache()
{
	free_dns_hash(&dns_hash);
	pthread_mutex_destroy(&lock_mutex);
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
 * dotted notation, use rhn2str), a flag value (use mk_flag_val) and a
 * timestamp indicating the time the query was done. */
int init_cent(dns_cent_t *cent, unsigned char *qname)
{
	int i;
	if (!(cent->qname=calloc(sizeof(unsigned char),strlen((char *)qname)+1)))
		return 0;
	strcpy((char *)cent->qname,(char *)qname);
	cent->cs=sizeof(dns_cent_t)+strlen((char *)qname)+1;
	cent->num_rr=0;
	for(i=0;i<T_NUM;i++) {
		cent->rr[i]=NULL;
	}
	return 1;
}

/*
 * Create a cent using the given values.
 */
static rr_bucket_t *create_rr(int dlen, void *data)
{
	rr_bucket_t *rrb;
	if (!(rrb=(rr_bucket_t *)calloc(sizeof(rr_bucket_t)+dlen,1)))
		return NULL;
	rrb->next=NULL;
		
	rrb->rdlen=dlen;
	memcpy(rrb+1,data,dlen);
	return rrb;
}

/*
 * Adds a rr record (usually prepared by rr_create) to a cent. For cache.c internal use. 
 */
static int add_cent_rr_int(dns_cent_t *cent, rr_bucket_t *rr, int tp, time_t ttl, time_t ts, int flags, unsigned long serial)
{
	if (!cent->rr[tp-T_MIN]) {
		if (!(cent->rr[tp-T_MIN]=calloc(sizeof(rr_set_t),1)))
			return 0;
		if (flags&CF_NOCACHE) {
			flags&=~CF_NOCACHE;
			ttl=0;
		}
		cent->rr[tp-T_MIN]->ttl=ttl;
		cent->rr[tp-T_MIN]->ts=ts;
		cent->rr[tp-T_MIN]->flags=flags;
		cent->rr[tp-T_MIN]->serial=serial;
		cent->cs+=sizeof(rr_set_t);
	}
	cent->cs+=rr->rdlen+sizeof(rr_bucket_t);
	/* do the linking work */
	rr->next=cent->rr[tp-T_MIN]->rrs;
	cent->rr[tp-T_MIN]->rrs=rr;
	cent->num_rr++;
	return 1;
}


/* Add an rr to a cache entry, giving the ttl, the data length, the rr type (tp)
 * and a pointer to the data. A record is allocated, and the data is copied into
 * it. Do this for all rrs in a cache entry. 
 */
int add_cent_rr(dns_cent_t *cent, time_t ttl, time_t ts, short flags, int dlen, void *data, int tp)
{
	rr_bucket_t *rrb;
	if (!(rrb=create_rr(dlen,data)))
		return 0;
	return add_cent_rr_int(cent,rrb,tp,ttl,ts,flags,0);
}

/* Free a complete rrset including all memory. Returns the size of the memory freed */
int del_cent_rrset(dns_cent_t *cent, int tp)
{
	rr_bucket_t *rrb,*rrn;
	int rv=0;

	if (!cent->rr[tp-T_MIN])
		return 0;

	rrb=cent->rr[tp-T_MIN]->rrs;
	while (rrb) {
		cent->num_rr--;
		rv+=sizeof(rr_bucket_t)+rrb->rdlen;
		rrn=rrb->next;
		free_rr(*rrb);
		free(rrb);
		rrb=rrn;
	}
	rv+=sizeof(rr_set_t);
	cent->cs-=rv;
	free(cent->rr[tp-T_MIN]);
	cent->rr[tp-T_MIN]=NULL;
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

/* Free all rr records from a cache entry. */
void free_cent(dns_cent_t cent)
{
	int i;
	for (i=0;i<T_NUM;i++) {
		del_cent_rrset(&cent, i+T_MIN);
	}
	free (cent.qname);
}

/* insert a rrset into the rr_l list. This modifies the rr_set_t! The rrset address needs to be constant afterwards 
 * call with locks applied*/
static rr_lent_t *insert_rrl(rr_set_t *rrs, dns_cent_t *cent, int tp)
{
	rr_lent_t *le,*ne;
	int fnd=0;
	if (!(ne=(rr_lent_t *)calloc(sizeof(rr_lent_t),1)))
		return NULL;
	ne->next=ne->prev=NULL;
	ne->rrset=rrs;
	ne->cent=cent;
	ne->tp=tp;
	rrs->lent=ne;
	/* Since the append at the and is a very common case (and we want this case to be fast), we search back-to-forth.
	 * Since rr_l is a list and we don't really have fast access to all elements, we do no perform an advanced algorihtm
	 * like binary search.*/
	le=rrset_l_tail;
	while (le) {
		if (rrs->ts>=le->rrset->ts && (le->next==NULL || rrs->ts<le->next->rrset->ts)) {
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
		ne->next=rrset_l;
		if (rrset_l)
			rrset_l->prev=ne;
		rrset_l=ne;
	}
	if (!ne->next) {
		rrset_l_tail=ne;
	}
	return ne;
}

/* remove a rr into the rr_l list.call with locks applied*/
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
rr_bucket_t *copy_rr(rr_bucket_t *rr)
{
	rr_bucket_t *rrn;
	if (!(rrn=calloc(sizeof(rr_bucket_t)+rr->rdlen,1))) {
		return NULL;
	}
	memcpy(rrn,rr,sizeof(rr_bucket_t)+rr->rdlen);
	rrn->next=NULL;
	return rrn;
}

/* Copy a cache entry into newly allocated memory */
dns_cent_t *copy_cent(dns_cent_t *cent)
{
	dns_cent_t *ic;
	int i;
	rr_bucket_t *rr,**rri,*lrr;
	
	if (!(ic=calloc(sizeof(dns_cent_t),1)))
		return NULL;
	*ic=*cent;
	
	if (!(ic->qname=calloc(sizeof(unsigned char),strlen((char *)cent->qname)+1))) {
		free(ic);
		return NULL;
	}
	strcpy((char *)ic->qname,(char *)cent->qname);
	
	for (i=0;i<T_NUM;i++) 
		ic->rr[i]=NULL;

	for (i=0;i<T_NUM;i++) {
		if (cent->rr[i]) {
			if (!(ic->rr[i]=(rr_set_t *)calloc(sizeof(rr_set_t),1))) {
				free_cent(*ic);
				free(ic);
				return NULL;
			}
			memcpy(ic->rr[i],cent->rr[i],sizeof(rr_set_t));
			ic->rr[i]->rrs=NULL;
			rri=&ic->rr[i]->rrs;
			rr=cent->rr[i]->rrs;
			lrr=NULL;
			while(rr) {
				if (!(*rri=copy_rr(rr))) {
					free_cent(*ic);
					free(ic);
				return NULL;
				}
				lrr=*rri;
				rri=(rr_bucket_t **)&(*rri)->next;
				rr=rr->next;
			}
		}
	}
	return ic;
}

#if 0 /* FIXME: this will die... at least modifications!!*/
/*
 * See if an rr with that data is present in the dns_cent_t
 * if the cent is in the cache, this must be called with rw-locks applied 
 * If the record is present, it is "touched" with the timestamp information
 * and new ttl.
 */
int have_cent_rr(dns_cent_t *cent, int tp, void *data, int dlen, time_t ttl, time_t ts, short flags)
{
	rr_bucket_t *rr;
	/* Checking is done the easy way here, by comparing rlen and the data section 
	 * (bytewise). oname MUST actually be the same on call. 
	 * All domain names were converted to lower case here.
	 * this does not include the ttls and other changing data.
	 * However, a record-aware compare would be nice, but this method should
	 * hold unless we are sent complete crap (in which case we would probably not
	 * be able to return anything actually useful anyway).
	 */
	rr=cent->rr[tp-T_MIN];
	while (rr) {
		if (rr->rdlen==dlen && memcmp((char *)(rr+1),data,dlen)==0) {
			if (rr->ttl+rr->ts<ts+ttl && !(rr->flags&CF_LOCAL)) {
				rr->ttl=ttl;
				rr->ts=ts;
				rr->flags=flags;
			}
			return 1;
		}
		rr=rr->next;
	}
	return 0;
}
#endif

/* 
 * Remove all timed out entries of a given rr row.
 * Follow some rules based on flags etc.
 * This will either delete the whole rrset, or will leave it as a whole (RFC2181 seems to
 * go in that direction)
 * This was pretty large once upon a time ;-), but now, since we operate in rrsets, was
 * shrinked drastically.
 * If the record is in the cache, we need rw-locks applied.
 * returns the size of the freed memory.
 */
static INLINE int purge_rrset(dns_cent_t *cent, int tp)
{
	if (cent->rr[tp-T_MIN] && !(cent->rr[tp-T_MIN]->flags&CF_NOPURGE || cent->rr[tp-T_MIN]->flags&CF_LOCAL) &&
	    cent->rr[tp-T_MIN]->ts+cent->rr[tp-T_MIN]->ttl<time(NULL)) {
		/* well, it must go. */
		return del_cent_rrset(cent,tp);
	}
	return 0;
}

/*
 * Purge a cent, deleting timed-out rrs (following the constraints noted in "purge_rrset").
 * Since the cent may actually become empty and be deleted, you may not use it after this call until
 * you refetch its address from the hash (if it is still there).
 * returns the size of the freed memory.
 */
static int purge_cent(dns_cent_t *cent)
{
	int rv=0;
	int i;
	for (i=T_MIN;i<=T_MAX;i++) {
		rv+=purge_rrset(cent,i);
	}
	/* if the record was purged empty, delete it from the cache. */
	if (cent->num_rr==0) {
		del_cache_int(cent);
	}
	return rv;
}

/*
 * Bring cache to a size below or equal the cache size limit (sz). There are two strategies:
 * - for cached sets with CF_NOPURGE not set: delete if timed out
 * - additional: delete oldest sets.
 */
static void purge_cache(unsigned long sz)
{
	dns_cent_t *ce;
	dns_hash_pos_t pos;
	rr_lent_t **le/*,*next*/;

	/* first, purge all rrs row-wise. This only affects timed-out records. */
	ce=fetch_first(&dns_hash, &pos);
	while (ce) {
		cache_size-=purge_cent(ce);
		ce=fetch_next(&dns_hash,&pos);
	}
	if (cache_size>sz) {
		/* we are still above the desired cache size. Well, delete records from the oldest to
		 * the newest. This is the case where nopurge records are deleted anyway. Only local
		 * records are kept in any case.*/
		le=&rrset_l;
		while (*le && cache_size>sz) {
			if (!((*le)->rrset->flags&CF_LOCAL)) {
				/*next=(*le)->next;*/
				cache_size-=del_cent_rrset((*le)->cent, (*le)->tp);
				if ((*le)->cent->num_rr==0) {
					del_cache_int((*le)->cent);
				}
				remove_rrl(*le);
				/**le=next;*/ /*remove_rrl should do that. */
			} else {
				le=&(*le)->next;
			}
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
	unsigned char *data=calloc(dtsz,1);
	unsigned char num_rr;
	char path[1024];
	unsigned long cnt;
	FILE *f;
	unsigned char nb[256];

	if (!data) {
		log_warn("Out of memory in reading cache file. Exiting.");
		pdnsd_exit();
		free(data);
		return;
	}

	strncpy(path,global.cache_dir,1023);
	path[1023]='\0';
	strncat(path,"/pdnsd.cache",1023-strlen(path));
	path[1023]='\0';

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
		if (fread(nb,fe.qlen,1,f)!=1) {
			fclose(f);
			log_warn("Error in disk cache file.");
			free(data);
			return;
		}
		if (!init_cent(&ce, nb)) {
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
				fclose(f);
				return;
			}
			if (num_rr) {
				if (fread(&sh,sizeof(sh),1,f)!=1) {
					log_warn("Error in disk cache file.");
					free(data);
					fclose(f);
					return;
				}
				for (;num_rr>0;num_rr--) {
					if (!read_rr(&rr,&data,&dtsz,f))
						return;
					if (!add_cent_rr(&ce,sh.ttl,sh.ts,sh.flags,rr.rdlen,data,i+T_MIN)) {
						log_error("Out of memory in reading cache file. Exiting.");
						pdnsd_exit();
						free(data);
						fclose(f);
						return;
					}
				}
			}
		}
		add_cache(ce);
	}
	free(data);
	fclose(f);
}

/* write an rr to the file f */
static void write_rrset(rr_set_t *rrs, FILE *f)
{
	rr_bucket_t *rr;
	rr_fset_t sh;
	rr_fbucket_t rf;
	unsigned char num_rr=0;
	long nump,oldp;
	
	nump=ftell(f);
	fwrite(&num_rr,sizeof(num_rr),1,f); /* write a dummy at first, since we do no know the number */
	if (rrs->flags&CF_LOCAL)
		return;

	sh.ttl=rrs->ttl;
	sh.ts=rrs->ts;
	sh.flags=rrs->flags;
	fwrite(&sh,sizeof(sh),1,f);
	rr=rrs->rrs;
	/* We only write a maximum of 256 of a kind (type) for one domain. This would be already overkill and probably does not happen.
	 * we want to get along with only one char, because most rr rows are empty (even more with DNS_NEW_RRS), and so the usage
	 * of greater data types would have significant impact on the cache file size. */
	while (rr && num_rr<255) {
		num_rr++;
		rf.rdlen=rr->rdlen;
		fwrite(&rf,sizeof(rf),1,f);
		fwrite((rr+1),rf.rdlen,1,f);
		rr=rr->next;
	}
	oldp=ftell(f);
	fseek(f,nump,SEEK_SET);
	fwrite(&num_rr,sizeof(num_rr),1,f);  /* write the real number */
	fseek(f,oldp,SEEK_SET);
}


/*
 * Write cache to disk on termination. The hash table is lost and needs to be regenerated
 * on reload.
 *
 * The locks are not very fine grained here, but I don't think this needs fixing as this routine 
 * is only called on exit.
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

	strncpy(path,global.cache_dir,1023);
	path[1023]='\0';
	strncat(path,"/pdnsd.cache",1023-strlen(path));
	path[1023]='\0';

	if (!(f=fopen(path,"w"))) {
		log_warn("Could not open disk cache file %s: %s",path,strerror(errno));
		return;
	}
	
	/* purge cache down to allowed size*/
	lock_cache_rw();
	purge_cache((long)global.perm_cache*1024);
	unlock_cache_rw();

	lock_cache_r();
	fwrite(&ent_num,sizeof(en),1,f); /*we don't know the real size by now, so write a dummy*/

	le=fetch_first(&dns_hash,&pos);
	while (le) {
/*		fwrite(&le->cent,sizeof(dns_file_t),1,f); */
		/* now, write the rr's */
		aloc=1;
		for (j=0;j<T_NUM;j++) {
			if (!(le->rr[j]->flags&CF_LOCAL)) {
				aloc=0;
				break;
			}
		}
		if (!aloc) {
			en++;
			df.qlen=strlen((char *)le->qname);
			fwrite(&df,sizeof(dns_file_t),1,f);
			fwrite(le->qname,df.qlen,1,f);

			for (i=0;i<T_NUM;i++) {
				write_rrset(le->rr[i],f);
			}
		}
		le=fetch_next(&dns_hash,&pos);
	}
	fseek(f,0,SEEK_SET);
	fwrite(&en,sizeof(en),1,f); /*write the real size.*/
	fclose(f);
	unlock_cache_r();
}

/*
 * Add a ready build dns_cent_t to the hashes, purge if necessary to no exceed cache size
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
	int i;
	rr_bucket_t *rr,*rrb;

	lock_cache_rw();

	if (!(ce=dns_lookup(&dns_hash,cent.qname))) {
		if(!(ce=(dns_cent_t *)copy_cent(&cent))) {
			log_warn("Out of cache memory.");
			free_cent(cent);
			unlock_cache_rw();
			return;
		}
		add_dns_hash(&dns_hash,cent.qname,ce);
		ent_num++;
		cache_size+=cent.cs;
	} else {
		/* We have a record; add the rrsets replacing old ones */
		cache_size-=ce->cs;
		for (i=0;i<T_NUM;i++) {
			if (cent.rr[i]) {
				if (ce->rr[i])
					del_cent_rrset(ce,i);
				rr=cent.rr[i]->rrs;
				while (rr) {
					if (!(rrb=create_rr(rr->rdlen, rr+1))) {
						log_warn("Out of cache memory.");
						unlock_cache_rw();
						return;
					} else {
						add_cent_rr_int(ce,rrb,i+T_MIN,ce->rr[i]->ttl, ce->rr[i]->ts, ce->rr[i]->flags,0);
					}
					rr=rr->next;
				}
			}
		}
		cache_size+=ce->cs;
	}

	/* Add the rrs to the rr list */
	for (i=0;i<T_MAX;i++) {
		if (ce->rr[i]) 
			if (!insert_rrl(ce->rr[i],ce,i+T_MIN)) {
				log_warn("Out of cache memory.");
				free_cent(cent);
				unlock_cache_rw();
				return;
			}
				
	}

	purge_cache((long)global.perm_cache*1024+MCSZ);
	unlock_cache_rw();
}

/*
 * Delete a cent from the cache. Call with write locks applied.
 */
void del_cache_int(dns_cent_t *cent)
{
	int i;
	rr_bucket_t *rr;

	/* Delete from the hash */
	del_dns_hash(&dns_hash,cent->qname);
	/* delete rrs from the rrl */
	for (i=0;i<T_MAX;i++) {
		remove_rrl(cent->rr[i]->lent);
		rr=rr->next;
	}
	/* free the cent ptrs and rrs */
	cache_size-=cent->cs;
	free_cent(*cent);
	free(cent);

	ent_num--;
}

/*
 * See if we have an entry in the cache.
 * Saves a copy operation compared to lookup_cache.
 */
int have_cached(unsigned char *name)
{
	dns_cent_t *ret;
	lock_cache_r();
	ret=dns_lookup(&dns_hash,name);
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
	if ((ret=dns_lookup(&dns_hash,name))) {
		ret=copy_cent(ret);  /* this may return NULL, check for it! */
	}
	unlock_cache_r();
	return ret;
}

/* Add an rr to an existing cache entry.
 * The rr is treaded with the precedence of an additional or off-topic record, ie. regularly retrieved
 * have precedence */
int add_cache_rr_add(unsigned char *name,time_t ttl, time_t ts, short flags,int dlen, void *data, int tp, unsigned long serial)
{
	dns_cent_t *ret;
	rr_bucket_t *rrb;
	int rv;
	lock_cache_rw();
	if ((ret=dns_lookup(&dns_hash,name))) {
		/* purge the record. */
		purge_cent(ret);
		if (ret->rr[tp-T_MIN] &&  
		    ((ret->rr[tp-T_MIN]->flags&CF_NOPURGE && ret->rr[tp-T_MIN]->ts+ret->rr[tp-T_MIN]->ttl<time(NULL)) || 
		     (ret->rr[tp-T_MIN]->flags&CF_ADDITIONAL && !ret->rr[tp-T_MIN]->serial==serial) || 
		     (ret->rr[tp-T_MIN]->serial==serial && ret->rr[tp-T_MIN]->ttl!=ttl)))
			del_cent_rrset(ret,tp);
		if (!ret->rr[tp-T_MIN] || ret->rr[tp-T_MIN]->serial==serial) {
			if (!(rrb=create_rr(dlen,data)))
				rv=0;
			else {
				if (!add_cent_rr_int(ret,rrb,tp,ttl,ts,flags,serial)) {
					free_rr(*rrb);
					free(rrb);
					rv=0;
				} else {
					if (!insert_rrl(ret->rr[tp-T_MIN],ret,tp))
						rv=0;
					else {
						purge_cent(ret);
						rv=1;
					}
				}
			}
		} else
			rv=1;
	} else
		rv=0;
	unlock_cache_rw();
	return rv;
}

/*
 * Add records for a host as read from a hosts-style file
 */
static int add_host(unsigned char *pn, unsigned char *rns, unsigned char *b3, pdnsd_a *a, int a_sz, time_t ttl, int tp, int reverse)
{
	dns_cent_t ce;
	unsigned char b2[256],rhn[256];
#if defined(DNS_NEW_RRS) && defined(ENABLE_IPV6)
	unsigned char b4[5];
	int i;
#endif

	if (!init_cent(&ce, pn))
		return 0;
#ifdef ENABLE_IPV4
	if (tp==T_A) {
		if (!add_cent_rr(&ce,ttl,0,CF_LOCAL,a_sz,&a->ipv4,tp))
			return 0;
	}
#endif
#if defined(DNS_NEW_RRS) && defined(ENABLE_IPV6)
	if (tp==T_AAAA) {
		if (!add_cent_rr(&ce,ttl,0,CF_LOCAL,a_sz,&a->ipv6,tp))
			return 0;
	}
#endif
	if (!add_cent_rr(&ce,ttl,0,CF_LOCAL,strlen((char *)rns)+1,rns,T_NS)) {
		free_cent(ce);
		return 0;
	}
	add_cache(ce);
	free_cent(ce);
	if (reverse) {
#ifdef ENABLE_IPV4
		if (tp==T_A) 
# if TARGET==TARGET_BSD
			snprintf((char *)b2,256,"%li.%li.%li.%li.in-addr.arpa.",ntohl(a->ipv4.s_addr)&0xff,(ntohl(a->ipv4.s_addr)>>8)&0xff,
				 (ntohl(a->ipv4.s_addr)>>16)&0xff, (ntohl(a->ipv4.s_addr)>>24)&0xff);
# else
			snprintf((char *)b2,256,"%i.%i.%i.%i.in-addr.arpa.",ntohl(a->ipv4.s_addr)&0xff,(ntohl(a->ipv4.s_addr)>>8)&0xff,
				 (ntohl(a->ipv4.s_addr)>>16)&0xff, (ntohl(a->ipv4.s_addr)>>24)&0xff);
# endif
#endif
#if defined(DNS_NEW_RRS) && defined(ENABLE_IPV6)
		if (tp==T_AAAA) {/* means T_AAAA*/
			b2[0]='\0';
			for (i=15;i>=0;i--) {
				sprintf((char *)b4,"%x.%x.",((unsigned char *)&a->ipv6)[i]&&0xf,(((unsigned char *)&a->ipv6)[i]&&0xf0)>>4);
				strcat((char *)b2,(char *)b4);
			}
			strcat((char *)b2,"ip6.int.");
		}
#endif
		if (!str2rhn(b2,rhn))
			return 0;
		if (!init_cent(&ce, b2))
			return 0;
		if (!add_cent_rr(&ce,ttl,0,CF_LOCAL,strlen((char *)b3)+1,b3,T_PTR))
			return 0;
		if (!add_cent_rr(&ce,ttl,0,CF_LOCAL,strlen((char *)rns)+1,rns,T_NS)) {
			free_cent(ce);
			return 0;
		}
		add_cache(ce);
		free_cent(ce);
	}
	return 1;
}

/*
 * Read a file in /etc/hosts-format and add generate rrs for it.
 */
void read_hosts(char *fn, unsigned char *rns, time_t ttl, int aliases)
{
	FILE *f;
	unsigned char buf[1025];
	unsigned char b3[256];
	unsigned char *p,*pn,*pi;
	struct in_addr ina4;
	int tp;
	int sz;
	pdnsd_a a;

	buf[1023]='\0';
	if (!(f=fopen(fn,"r"))) {
		fprintf(stderr, "Failed to source %s: %s\n", fn, strerror(errno));
		return;
	}
	while (!feof(f)) {
		fgets((char *)buf,1023,f);
		buf[1023]='\0';
/*		printf("read: %s\n", buf);*/
		p=buf;
		while (*p) {
			if (*p=='#') {
				*p='\0';
				break;
			}
			p++;
		}
		pi=buf;
		while (*pi==' ' || *pi=='\t') pi++;
		if (!*pi)
			continue;
		pn=pi;
		while (*pn=='.' || *pn==':' || isxdigit(*pn)) pn++;  /* this includes IPv6 (':') */
		if (!*pn)
			continue;
		*pn='\0';
		pn++;
		while (*pn==' ' || *pn=='\t') pn++;
		if (!*pn)
			continue;
		p=pn;
		while (isdchar(*p) || *p=='.') p++;
		if (*(p-1)!='.') 
			*p++='.';
		*p='\0';
/*		printf("i: %s, n: %s--\n",pi,pn);*/
		if (!str2rhn(pn,b3))
			continue;
		if (!inet_aton((char *)pi,&ina4)) {
#if defined(DNS_NEW_RRS) && defined(ENABLE_IPV6) /* We don't read them otherwise, as the C library may not be able to to that.*/
			if (inet_pton(AF_INET6,(char *)pi,&a.ipv6)) {
				tp=T_AAAA;
				sz=sizeof(struct in6_addr);
			} else
				continue;
#else
			continue;
#endif
		} else {
#ifndef ENABLE_IPV4
			continue;
#else
			a.ipv4=ina4;
			tp=T_A;
			sz=sizeof(struct in_addr);
#endif
		}
		if (!add_host(pn, rns, b3, &a, sz, ttl, tp,1))
			continue;
		if (aliases) {
			pn=++p;
			while (*pn==' ' || *pn=='\t') pn++;
			if (!*pn)
				continue;
			p=pn;
			while (isdchar(*p) || *p=='.') p++;
			if (*(p-1)!='.') 
				*p++='.';
			*p='\0';
			if (!str2rhn(pn,b3))
				continue;
			add_host(pn, rns, b3, &a, sz, ttl, tp,0);
		}
	}
	fclose(f);
}

/* Report the cache status to the file descriptor f, for the status fifo (see status.c) */
void report_cache_stat(FILE *f)
{
	unsigned long mc=(long)global.perm_cache*1024+MCSZ;
	unsigned long csz=cache_size*100/mc;
	fprintf(f,"\nCache status:\n=============\n");
	fprintf(f,"%li kB maximum disk cache size.\n",global.perm_cache);
	fprintf(f,"%li of %lu bytes (%lu%%) memory cache used in %lu entries.\n",cache_size,mc,csz,ent_num);
}
