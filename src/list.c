/* list.c - Dynamic array and list handling
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

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "helpers.h"
#include "error.h"
#include "list.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: list.c,v 1.5 2001/05/19 14:57:30 tmm Exp $";
#endif

#ifdef ALLOC_DEBUG
darray DBGda_create(int sz, char *file, int line)
{
	DEBUG_MSG("+ da_create, %s:%d, %d bytes\n", file, line, sz);
	return Dda_create(sz);
}
#endif

/* darray Dda_create(int sz)
{
	darray a;

	a=(darray)malloc(sizeof(struct _dynamic_array_dummy_head)+sz*8);
	if(a) a->nel=0;
	return a;
} */

darray da_grow1(darray a, int sz)
{
  PDNSD_ASSERT(a!=NULL, "Access to uninitialized array.");
  {
    int k = a->nel++;
    if(k!=0 && (k&7)==0) {
      darray tmp=(darray)realloc(a, sizeof(struct _dynamic_array_dummy_head)+sz*(k+8));
      if (tmp==NULL)
	free(a);
      return tmp;
    }
    else
      return a;
  }
}

inline static int alloc_nel(int n)
{
  return n==0 ? 8 : (n+7)&(~7);
}

darray da_resize(darray a, int sz, int n)
{
  PDNSD_ASSERT(a!=NULL, "Access to uninitialized array.");
  PDNSD_ASSERT(n>=0, "da_resize to negative size");
  {
    int ael = alloc_nel(a->nel);
    int new_ael = alloc_nel(n);
    a->nel=n;
    if(new_ael != ael) {
      /* adjust alloced space. */
      darray tmp=(darray)realloc(a, sizeof(struct _dynamic_array_dummy_head)+sz*new_ael);
      if (tmp==NULL)
	free(a);
      return tmp;
    }
    else
      return a;
  }
}

#ifdef ALLOC_DEBUG
darray DBGda_free(darray a, char *file, int line)
{
	if (a==NULL)
		DEBUG_MSG("- da_free, %s:%d, not initialized\n", file, line);
	else
		DEBUG_MSG("- da_free, %s:%d, %d bytes\n", file, line, a->tpsz);
	free(a);
	return;
}
#endif

