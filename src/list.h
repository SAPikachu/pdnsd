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

/*
 * The size of this should always be a multiple of 4 on all supported architectures.
 * Otherwise, we need further glue.
 */
struct darray_head {
	int tpsz;	/* size of the type we hold (including padding) */
	int nel;	/* number of elements in array */
	int ael;	/* number of allocated elements */
	int dummy;	/* dummy for alignment */
};

typedef struct darray_head *darray;

/*
 * This will work for i386 and alpha. If someday we support and architecture
 * with different alignment needs, this needs to be fixed.
 */
#define DA_ALIGNSZ(sz) (((((sz)-1)/8)+1)*8)

#define DA_CREATE(tp) (da_create(sizeof(tp)))
#define DA_INDEX(a,i,tp) ((tp *)(da_index(a,i)))
/* Used often, so make special-case macro here */
#define DA_LAST(a, tp) ((tp *)(da_index(a, (a)->nel-1)))

/*
 * Some or all of these should be inline.
 * They aren't macros for type safety.
 */
darray Dda_create(int sz);
darray da_grow(darray a, int n);
darray da_resize(darray a, int n);
char *da_index(darray a, int i);
int da_nel(darray a);
void Dda_free(darray a);

/* Number of elements to over-allocate by default */
#define DA_PREALLOC	5

/* alloc/free debug code.*/
#ifdef ALLOC_DEBUG
darray DBGda_create(int sz, char *file, int line);
darray DBGda_free(darray a, char *file, int line);

#define da_create(sz)	DBGda_create(sz, __FILE__, __LINE__)
#define da_free(a)	DBGda_free(a, __FILE__, __LINE__)
#else
#define da_create	Dda_create
#define da_free		Dda_free
#endif

/* List macros. */
#define PLIST_STRUCT(type)						\
	struct {							\
		struct type *next;					\
		struct type *prev;					\
	} _list

#define PLIST_HEAD(name, type)						\
	struct {							\
		struct type *head;					\
		struct type *tail;					\
	} name

#define PLIST_FIRST(name)	((name)->head)
#define PLIST_NEXT(el)		(*(el)->_list.next)
#define PLIST_PREV(el)		(*(el)->_list.prev)
#define PLIST_DELETE(el, type)	(*(el)->prev = (el)->next)

#define PLIST_INSERT_HEAD(el, head)					\
	do {								\
		el->next = head->head;					\
		el->prev = NULL;					\
		head->head = el;					\
		if (el->next == NULL)					\
			head->tail = el;				\
	} while (0);

#define PLIST_INSERT_TAIL(el, head)					\
	do {								\
		el->prev = head->tail;					\
		el->next = NULL;					\
		head->tail = el;					\
		if (el->prev == NULL)					\
			head->head = el;				\
	} while (0);

#define PLIST_INSERT_AFTER(el, after)					\
	do {								\
		el->next = after->next;					\
		el->prev = after;					\
		after->next = el;					\
		if (el->next == NULL)					\
			head->tail = el;				\
		else							\
			el->next->prev = el;				\
	} while (0);

#define PLIST_INSERT_BEFORE(el, before)					\
	do {								\
		el->prev = before->prev;				\
		el->next = before;					\
		before->prev = el;					\
		if (el->prev == NULL)					\
			head->head = el;				\
		else							\
			el->prev->next = el;				\
	} while (0);

#endif /* def LIST_H */
