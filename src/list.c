/* list.c - Dynamic array and list handling
  
   Copyright (C) 2001 Thomas Moestl
   Copyright (C) 2002, 2003 Paul A. Rombouts
  
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
#include <string.h>
#include "helpers.h"
#include "error.h"
#include "list.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: list.c,v 1.5 2001/05/19 14:57:30 tmm Exp $";
#endif

#ifdef ALLOC_DEBUG
darray DBGda_create(size_t sz, char *file, int line)
{
	DEBUG_MSG("+ da_create, %s:%d, %u bytes\n", file, line,
		  (unsigned int)(sizeof(struct _dynamic_array_dummy_head)+sz*8));
	return Dda_create(sz);
}
#endif

#if 0
darray Dda_create(size_t sz)
{
	darray a;

	a=(darray)malloc(sizeof(struct _dynamic_array_dummy_head)+sz*8);
	if(a) a->nel=0;
	return a;
}
#endif

darray da_grow1(darray a, size_t sz, void (*cleanuproutine) (void *))
{
	unsigned int k = (a?a->nel:0);
	if(!a || (k!=0 && (k&7)==0)) {
		darray tmp=(darray)realloc(a, sizeof(struct _dynamic_array_dummy_head)+sz*(k+8));
		if (!tmp && a) {
			if(cleanuproutine) {
				unsigned int i;
				for(i=0;i<k;++i)
					cleanuproutine(((char *)a->elem)+sz*i);
			}
			free(a);
		}
		a=tmp;
	}
	if(a) a->nel=k+1;
	return a;
}

inline static unsigned int alloc_nel(unsigned int n)
{
  return n==0 ? 8 : (n+7)&(~7);
}

darray da_resize(darray a, size_t sz, unsigned int n, void (*cleanuproutine) (void *))
{
	unsigned int ael = (a?alloc_nel(a->nel):0);
	unsigned int new_ael = alloc_nel(n);
	if(new_ael != ael) {
		/* adjust alloced space. */
		darray tmp=(darray)realloc(a, sizeof(struct _dynamic_array_dummy_head)+sz*new_ael);
		if (!tmp && a) {
			if(cleanuproutine) {
				unsigned int i,k=a->nel;
				for(i=0;i<k;++i)
					cleanuproutine(((char *)a->elem)+sz*i);
			}
			free(a);
		}
		a=tmp;
	}
	if(a) a->nel=n;
	return a;
}

#ifdef ALLOC_DEBUG
void DBGda_free(darray a, size_t sz, char *file, int line)
{
	if (a==NULL)
		{DEBUG_MSG("- da_free, %s:%d, not initialized\n", file, line);}
	else
		{DEBUG_MSG("- da_free, %s:%d, %u bytes\n", file, line,
			   (unsigned int)(sizeof(struct _dynamic_array_dummy_head)+sz*alloc_nel(a->nel)));}
	free(a);
}
#endif

#define DLISTALIGN(len) (((len) + (sizeof(size_t)-1)) & ~(sizeof(size_t)-1))
#define DLISTCHUNKSIZEMASK 0x3ff

/* Add space for a new item of size len to the list a. */
dlist dlist_grow(dlist a, size_t len)
{
	size_t szincr=DLISTALIGN(len+sizeof(size_t)), sz=0, allocsz=0, newsz;
	if(a) {
		sz=a->last+a->lastsz;
		allocsz = (sz+DLISTCHUNKSIZEMASK)&(~DLISTCHUNKSIZEMASK);
		*((size_t *)&a->data[a->last])=a->lastsz;
	}
	newsz=sz+szincr;
	if(!a || newsz>allocsz) {
		dlist tmp;
		allocsz = (newsz+DLISTCHUNKSIZEMASK)&(~DLISTCHUNKSIZEMASK);
		tmp=realloc(a, sizeof(struct _dynamic_list_head)+allocsz);
		if (!tmp)
			free(a);
		a=tmp;
	}
	if(a) {
		a->last=sz;
		a->lastsz=szincr;
		*((size_t *)&a->data[sz])=0;
	}
	return a;
}

