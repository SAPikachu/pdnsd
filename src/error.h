/* error.h - Error handling
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

/* $Id: error.h,v 1.13 2001/06/02 23:08:13 tmm Exp $ */

#ifndef ERROR_H
#define ERROR_H

#include <config.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include <signal.h>

#include "thread.h"
#include "helpers.h"

/* --- from error.c */
volatile extern int waiting;
/* --- */

void crash_msg(char *msg);
void init_log(void);
void log_error(char *s,...) printfunc(1, 2);
void log_warn(char *s, ...) printfunc(1, 2);
void log_info(int level, char *s, ...) printfunc(2, 3);

/* Following are some ugly macros for debug messages that
 * should inhibit any code generation when DEBUG is not defined.
 * Of course, those messages could be done in a function, but I
 * want to save the overhead when DEBUG is not defined. 
 * debug_p needs to be defined (by including conff.h), or you
 * will get strange errors.
 * Dont forget your semicolon after the macro call, or you
 * will get other strange errors ;-)
 * The arguments are normal printfs, so you know how to use the args
 */
#if DEBUG>0
/* from main.c */
extern FILE *dbg_file;

/* XXX: The timestamp generation makes this a little heavy-weight */
#define DEBUG_MSG_(c,...)								\
	do {										\
		if (debug_p) {								\
			char DM_ts[32];							\
			time_t DM_tt = time(NULL);					\
			struct tm DM_tm;						\
			int *DM_id;							\
			localtime_r(&DM_tt, &DM_tm);					\
			if (!c && strftime(DM_ts, sizeof(DM_ts), "%m/%d %T",		\
			    &DM_tm) > 0 &&						\
			    (DM_id = (int *)pthread_getspecific(thrid_key)) != NULL)	\
				fprintf(dbg_file,"%d %s| ", *DM_id, DM_ts);		\
			fprintf(dbg_file,__VA_ARGS__);					\
			fflush(dbg_file);						\
		}									\
	} while (0)

#define DEBUG_MSG(...)	DEBUG_MSG_(0,__VA_ARGS__)
#define DEBUG_MSGC(...)	DEBUG_MSG_(1,__VA_ARGS__)
#else
#define DEBUG_MSG(...)
#define DEBUG_MSGC(...)
#endif

/*
 * This is a macro so that it can be made empty after sufficient testing if !defined(DEBUG)
 */
#define PDNSD_ASSERT(cond, msg)						\
	do { if (!(cond)) {						\
		log_error("%s:%d: %s", __FILE__, __LINE__, msg);	\
		pdnsd_exit();						\
 	} } while (0)
#endif
