/* thread.c - Threading helpers

   Copyright (C) 2000 Thomas Moestl
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
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include "thread.h"
#include "error.h"
#include "helpers.h"
#include "conff.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: thread.c,v 1.5 2001/05/19 14:57:30 tmm Exp $";
#endif

volatile short int waiting=0; /* Has the main thread already done sigwait() ? */
pthread_attr_t attr_detached;
pthread_key_t thrid_key;

/* This is a handler for signals to the threads. We just hand the sigs on to the main thread.
 * Note that this may result in blocked locks. We have no means to open the locks here, because in LinuxThreads
 * the mutex functions are not async-signal safe. So, locks may still be active. We account for this by using
 * softlocks (see below) in any functions called after sigwait from main(). */
#if (TARGET==TARGET_LINUX) && !defined(THREADLIB_NPTL)
void thread_sig(int sig)
{
	if (sig==SIGTSTP || sig==SIGTTOU || sig==SIGTTIN) {
		/* nonfatal signal. Ignore, because proper handling is very difficult. */
		return;
	}
	if (waiting) {
		log_warn("Caught signal %i.",sig);
		if (sig==SIGSEGV || sig==SIGILL || sig==SIGBUS)
			crash_msg("A fatal signal occured.");
		pthread_kill(main_thread,SIGTERM);
		pthread_exit(NULL);
	} else {
		crash_msg("An error occured at startup.");
		_exit(1);
	}
}
#endif

/* This is now defined as an inline function in thread.h */
#if 0
void usleep_r(unsigned long usec)
{
#if ((TARGET==TARGET_LINUX) || (TARGET==TARGET_BSD) || (TARGET==TARGET_CYGWIN)) && defined(HAVE_USLEEP)
	usleep(usec);
#else
	struct timeval tv;

	tv.tv_sec=usec/1000000;
	tv.tv_usec=usec%1000000;
	select(0, NULL, NULL, NULL, tv);
#endif
}
#endif

