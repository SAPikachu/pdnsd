/* error.c - Error handling

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
#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include "error.h"
#include "helpers.h"
#include "conff.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: error.c,v 1.7 2001/06/03 11:00:54 tmm Exp $";
#endif

pthread_mutex_t loglock = PTHREAD_MUTEX_INITIALIZER;
volatile short int use_log_lock=0;

/*
 * Initialize a mutex for io-locking in order not to produce gibberish on
 * multiple simultaneous errors.
 */
/* This is now defined as an inline function in error.h */
/* void init_log_lock(void)
{
	use_log_lock=1;
} */

/* We crashed? Ooops... */
void crash_msg(char *msg)
{
	log_error("%s", msg);
	log_error("pdnsd probably crashed due to a bug. Please consider sending a bug");
	log_error("report to p.a.rombouts@home.nl or tmoestl@gmx.net");
}

/* Log a warning or error message.
 * If we are a daemon, use the syslog. s is a format string like in printf,
 * the optional following arguments are the arguments like in printf */
void log_message(int prior, const char *s, ...)
{
	int ul=0;
	va_list va;
	if (use_log_lock)
		ul=softlock_mutex(&loglock);
	va_start(va,s);
	if (global.daemon) {
		openlog("pdnsd",LOG_PID,LOG_DAEMON);
		vsyslog(prior,s,va);
		closelog();
	} else {
		fprintf(stderr,"pdnsd: %s: ",
			prior<=LOG_CRIT?"critical":
			prior==LOG_ERR?"error":
			prior==LOG_WARNING?"warning":
			"info");
		vfprintf(stderr,s,va);
		fprintf(stderr,"\n");
	}
	va_end(va);
	if (ul)
		pthread_mutex_unlock(&loglock);
}

/* Log an info if level is <= the current verbosity level.
 * If we are a daemon, use the syslog. s is a format string like
 * in printf, the optional following arguments are the arguments like in printf */
void log_info(int level, const char *s, ...)
{
	if (level<=global.verbosity) {
		va_list va;
		if (use_log_lock)
			if (!softlock_mutex(&loglock)) {
				return;
			}
		va_start(va,s);
		if (global.daemon) {
			openlog("pdnsd",LOG_PID,LOG_DAEMON);
			vsyslog(LOG_INFO,s,va);
			closelog();
		} else {
			fprintf(stderr,"pdnsd: info: ");
			vfprintf(stderr,s,va);
			fprintf(stderr,"\n");
		}
		va_end(va);
		if (use_log_lock)
			pthread_mutex_unlock(&loglock);
	}
}

#if DEBUG > 0
/* XXX: The timestamp generation makes this a little heavy-weight */
void debug_msg(int c, const char *fmt, ...)
{
	va_list va;

	if (!c) {
		char DM_ts[sizeof "12/31 23:59:59"];
		time_t DM_tt = time(NULL);
		struct tm DM_tm;
		int *DM_id;
		localtime_r(&DM_tt, &DM_tm);
		if(strftime(DM_ts, sizeof(DM_ts), "%m/%d %T", &DM_tm) > 0) {
			if((DM_id = (int *)pthread_getspecific(thrid_key)))
				fprintf(dbg_file,"%d %s| ", *DM_id, DM_ts);
			else
				fprintf(dbg_file,"- %s| ", DM_ts);
		}
	}
	va_start(va,fmt);
	vfprintf(dbg_file,fmt,va);
	va_end(va);
	fflush(dbg_file);
}
#endif /* DEBUG */
