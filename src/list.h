/* list.h - Dynamic array and list handling
 * Copyright (C) 2001 Thomas Moestl
 *
 * This file is part of the pdnsd package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* $Id: list.h,v 1.3 2001/06/21 23:58:43 tmm Exp $ */

#ifndef LIST_H
#define LIST_H

#include <stdlib.h>
#include "pdnsd_assert.h"

/*
 * The size of this should always be a multiple of 4 on all supported architectures.
 * Otherwise, we need further glue.
 */
struct _dynamic_array_dummy_head {
	unsigned long int nel;	/* number of elements in array */
	double elem[0];	/* dummy for alignment */
};

typedef struct _dynamic_array_dummy_head  *darray;

/* used in type declarations */
#define DYNAMIC_ARRAY(typ) \
        struct _dynamic_array_of_ ## typ {unsigned long int nel; typ elem[0]; } 

#define DA_CREATE(typ) ((struct _dynamic_array_of_ ## typ *)(da_create(sizeof(typ))))
#define DA_INDEX(a,i) ((a)->elem[i])
/* Used often, so make special-case macro here */
#define DA_LAST(a) ((a)->elem[(a)->nel-1])

#define DA_GROW1(a) ((typeof (a))da_grow1((darray)(a),sizeof((a)->elem[0])))
#define DA_RESIZE(a,n) ((typeof (a))da_resize((darray)(a),sizeof((a)->elem[0]),n))
#define DA_NEL(a) da_nel((darray)(a))
/*
 * Some or all of these should be inline.
 * They aren't macros for type safety.
 */
inline static darray Dda_create(size_t sz)
{
  darray a;

  a=(darray)malloc(sizeof(struct _dynamic_array_dummy_head)+sz*8);
  if(a) a->nel=0;
  return a;
}

darray da_grow1(darray a, size_t sz);
darray da_resize(darray a, size_t sz, unsigned int n);

inline static unsigned int da_nel(darray a)
{
  if (a==NULL)
    return 0;
  return a->nel;
}

/* alloc/free debug code.*/
#ifdef ALLOC_DEBUG
darray DBGda_create(size_t sz, char *file, int line);
void   DBGda_free(darray a, size_t sz, char *file, int line);

#define da_create(sz)	DBGda_create(sz, __FILE__, __LINE__)
#define da_free(a)	DBGda_free((darray)(a),sizeof((a)->elem[0]), __FILE__, __LINE__)
#else
#define da_create	Dda_create
#define da_free		free
#endif


#endif /* def LIST_H */
