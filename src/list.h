/* list.h - Dynamic array and list handling
  
   Copyright (C) 2001 Thomas Moestl
   Copyright (C) 2002, 2003, 2007 Paul A. Rombouts

  This file is part of the pdnsd package.

  pdnsd is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 3 of the License, or
  (at your option) any later version.

  pdnsd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with pdnsd; see the file COPYING. If not, see
  <http://www.gnu.org/licenses/>.
*/


/* $Id: list.h,v 1.3 2001/06/21 23:58:43 tmm Exp $ */

#ifndef LIST_H
#define LIST_H

#include <stdlib.h>
#include <string.h>
#include "pdnsd_assert.h"

#if 0
/*
 * The size of this should always be a multiple of 4 on all supported architectures.
 * Otherwise, we need further glue.
 */
struct _dynamic_array_dummy_head {
	unsigned long int nel;	/* number of elements in array */
	void *elem[0];	/* dummy for alignment */
};
#endif

typedef struct {size_t nel;} *darray;

/* used in type declarations */
#define DYNAMIC_ARRAY(typ)  struct {size_t nel; typ elem[0];} 
#define DA_OFFSET(a) ((size_t)((typeof (a))0)->elem)

/* #define DA_CREATE(typ) ((struct {size_t nel; typ elem[0];} *)(da_create(sizeof(typ)))) */
#define DA_INDEX(a,i) ((a)->elem[i])
/* Used often, so make special-case macro here */
#define DA_LAST(a) ((a)->elem[(a)->nel-1])

#define DA_GROW1(a) ((typeof (a))da_grow1((darray)(a),DA_OFFSET(a),sizeof((a)->elem[0]),NULL))
#define DA_GROW1_F(a,cleanup) ((typeof (a))da_grow1((darray)(a),DA_OFFSET(a),sizeof((a)->elem[0]),cleanup))
#define DA_RESIZE(a,n) ((typeof (a))da_resize((darray)(a),DA_OFFSET(a),sizeof((a)->elem[0]),n,NULL))
#define DA_NEL(a) da_nel((darray)(a))

/*
 * Some or all of these should be inline.
 * They aren't macros for type safety.
 */
#if 0
inline static darray Dda_create(size_t sz)
{
  darray a;

  a=(darray)malloc(sizeof(struct _dynamic_array_dummy_head)+sz*8);
  if(a) a->nel=0;
  return a;
}
#endif

darray da_grow1(darray a, size_t headsz, size_t elemsz, void (*cleanuproutine) (void *));
darray da_resize(darray a, size_t headsz, size_t elemsz, size_t n, void (*cleanuproutine) (void *));

inline static unsigned int da_nel(darray a)
{
  if (a==NULL)
    return 0;
  return a->nel;
}

/* alloc/free debug code.*/
#ifdef ALLOC_DEBUG
/* darray DBGda_create(size_t sz, char *file, int line); */
void   DBGda_free(darray a, size_t headsz, size_t elemsz, char *file, int line);

/* #define da_create(sz)	DBGda_create(sz, __FILE__, __LINE__) */
#define da_free(a)	DBGda_free((darray)(a),DA_OFFSET(a),sizeof((a)->elem[0]), __FILE__, __LINE__)
#else
/* #define da_create	Dda_create */
#define da_free		free
#endif


/* This dynamic "list" structure is useful if the items are not all the same size.
   The elements can only be read back in sequential order, not indexed as with the dynamic arrays.
*/
struct _dynamic_list_head {
	size_t last,lastsz;
	char data[0];
};

typedef struct _dynamic_list_head  *dlist;

inline static void *dlist_first(dlist a)
{
  return a?&a->data[sizeof(size_t)]:NULL;
}

/* dlist_next() returns a reference to the next item in the list, or NULL is there is no next item.
   ref should be properly aligned.
   If the dlist was grown with dlist_grow(), this should be OK.
*/
inline static void *dlist_next(void *ref)
{
  size_t incr= *(((size_t *)ref)-1);
  return incr?((char *)ref)+incr:NULL;
}

/* dlist_last() returns a reference to the last item. */
inline static void *dlist_last(dlist a)
{
  return a?&a->data[a->last+sizeof(size_t)]:NULL;
}

dlist dlist_grow(dlist a, size_t len);

#define dlist_free free

#endif /* def LIST_H */
