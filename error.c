/* error.c - Error handling
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
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/types.h>
#include <signal.h>
#include "error.h"
#include "helpers.h"
#include "conff.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: error.c,v 1.7 2000/06/22 09:57:34 thomas Exp $";
#endif

pthread_mutex_t loglock;

/*
 * Initialize a mutex for io-locking in order not to produce gibberish on
 * multiple simultaneous errors.
 */
void init_log(void)
{
	pthread_mutex_init(&loglock,NULL);
}

/* This is a handler for signals to the threads. We just hand the sigs on to the main thread.
 * Note that this may result in blocked locks. We have no means to resolve the logs here, because in LinuxThreads
 * the mutex functions are not async-signal safe. So, locks may still be active. We account for this by using
 * softlocks in any functions called after sigwait from main(). */
#if TARGET==TARGET_LINUX
void fatal_sig(int sig)
{
	if (waiting) {
		if (sig==SIGSEGV || sig==SIGILL || sig==SIGBUS)
			crash_msg("A fatal signal occured.");
		pthread_kill(main_thread,SIGTERM);
	} else {
		crash_msg("An error occured at startup.");
		_exit(0);
	}
}
#endif

/* We crashed? Ooops... */
void crash_msg(char *msg)
{
	log_error(msg);
	log_error("pdnsd probably crashed due to a bug. Please consider sending a bug");
	log_error("report to tmoestl@gmx.net");
}

/* Log an error. If we are a daemon, use the syslog. s is a format string like
 * in printf, the optional following arguments are the arguments like in printf */
void log_error(char *s,...)
{
	int ul;
	va_list va;
	va_start(va,s);
	ul=softlock_mutex(&loglock);
	if (daemon_p) {
		openlog("pdnsd",LOG_PID,LOG_DAEMON);
		vsyslog(LOG_ERR,s,va);
		closelog();
	} else {
		fprintf(stderr,"pdnsd: error: ");
		vfprintf(stderr,s,va);
		fprintf(stderr,"\n");
	}
	if (ul)
		pthread_mutex_unlock(&loglock);
	va_end(va);
}

/* Log a warning. If we are a daemon, use the syslog. s is a format string like
 * in printf, the optional following arguments are the arguments like in printf */
void log_warn(char *s, ...)
{
	int ul;
	va_list va;
	va_start(va,s);
	ul=softlock_mutex(&loglock);
	if (daemon_p) {
		openlog("pdnsd",LOG_PID,LOG_DAEMON);
		vsyslog(LOG_ERR,s,va);
		closelog();
	} else {
		fprintf(stderr,"pdnsd: warning: ");
		vfprintf(stderr,s,va);
		fprintf(stderr,"\n");
	}
	if (ul)
		pthread_mutex_unlock(&loglock);
	va_end(va);
}

/* Log an info if level is <= the current verbosity level.
 * If we are a daemon, use the syslog. s is a format string like
 * in printf, the optional following arguments are the arguments like in printf */
void log_info(int level, char *s, ...)
{
	va_list va;
	va_start(va,s);
	if (level<=verbosity) {
		if (!softlock_mutex(&loglock))
			return;
		if (daemon_p) {
			openlog("pdnsd",LOG_PID,LOG_DAEMON);
			vsyslog(LOG_INFO,s,va);
			closelog();
		} else {
			fprintf(stderr,"pdnsd: info: ");
			vfprintf(stderr,s,va);
			fprintf(stderr,"\n");
		}
		pthread_mutex_unlock(&loglock);
	}
	va_end(va);
}
