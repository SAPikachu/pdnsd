/* status.c - Make server status information accessible through a named pipe
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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "status.h"
#include "hash.h"
#include "cache.h"
#include "error.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: status.c,v 1.6 2000/06/22 09:57:34 thomas Exp $";
#endif

char fifo_path[1024];

pthread_t st;

/*
 * Give out server status information on the fifo "status" in the cache directory.
 * Inquire it by doing "cat <your-server-dir>/status"
 */
void *status_thread (void *p)
{
	FILE *f;
	struct utsname nm;

	THREAD_SIGINIT;

	uname(&nm);
	(void)p; /* To inhibit "unused variable" warning */
	do {
		if ((f=fopen(fifo_path,"w"))) {
			fprintf(f,"pdnsd-%s running on %s.\n",VERSION,nm.nodename);
			report_cache_stat(f);
			report_conf_stat(f);
			fclose(f);
			usleep(100000); /* sleep some time. I do not want the query frequence to be too high. */
		} else {
			if (errno!=EINTR)
				log_warn("Failed to open fifo: %s. Status readback will be impossible",strerror(errno));
			return NULL;
		}
	} while(1);
	return NULL;
}

/*
 * Start the fifo thread (see above)
 */
void init_stat_fifo()
{
	pthread_attr_t attr;

	strncpy(fifo_path,global.cache_dir,1023);
	fifo_path[1023]='\0';
	strncat(fifo_path,"/status",1023-strlen(fifo_path));
	fifo_path[1023]='\0';
	mkfifo(fifo_path,0600);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
	if (pthread_create(&st,&attr,status_thread,NULL))
		log_warn("Failed to start status thread. The status fifo will be unusable");
	else
		log_info(2,"Status pipe thread started.");
}
