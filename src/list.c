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

#include "../config.h"
#include <stdlib.h>
#include "helpers.h"
#include "error.h"
#include "list.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: list.c,v 1.1 2001/04/10 22:31:39 tmm Exp $";
#endif

darray da_create(int sz)
{
	darray a;
	int tpsz = DA_ALIGNSZ(sz); /* Round up sizes for aligned access */

	if (!(a=(darray)malloc(sizeof(struct darray_head)+DA_PREALLOC*tpsz)))
		return a;
	a->tpsz=tpsz;
	a->nel=0;
	a->ael=DA_PREALLOC;
	return a;
}

darray da_grow(darray a, int n)
{
	PDNSD_ASSERT(a!=NULL, "Access to uninitialized array.");
	return da_resize(a, a->nel+n);
}

darray da_resize(darray a, int n)
{
	PDNSD_ASSERT(a!=NULL, "Access to uninitialized array.");
	PDNSD_ASSERT(n>=0, "da_resize to negative size");
	a->nel=n;
	if (a->nel>a->ael || a->nel<a->ael-2*DA_PREALLOC) {
		/* adjust alloced space. */
		a->ael=a->nel+DA_PREALLOC;
		return realloc(a, sizeof(struct darray_head)+a->tpsz*a->ael);
	} else
		return a;
}

char *da_index(darray a, int i)
{
	PDNSD_ASSERT(a!=NULL, "Access to uninitialized array.");
	PDNSD_ASSERT(i>=0&&i<a->nel,"Internal error: dynamic array access out of bounds");
	return ((char *)a)+sizeof(struct darray_head)+i*a->tpsz;
}

int da_nel(darray a)
{
	PDNSD_ASSERT(a!=NULL, "Access to uninitialized array.");
	return a->nel;
}

void da_free(darray a)
{
	free(a);
}
