/* status.c - Allow control of a running server using a pipe
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
#include <sys/socket.h>
#include <sys/un.h>
#include "status.h"
#include "cacheing/cache.h"
#include "error.h"
#include "helpers.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: status.c,v 1.2 2000/07/21 20:04:37 thomas Exp $";
#endif

char fifo_path[1024]="/tmp/.pdnsd-status";

pthread_t st;

/*
 * Give out server status information on the fifo "status" in the cache directory.
 * Inquire it by doing "cat <your-server-dir>/status"
 */
void *status_thread (void *p)
{
	int sock,rs;
	socklen_t res;
	struct utsname nm;
	short cmd;
	struct sockaddr_un a,ra;

	THREAD_SIGINIT;

	if (!global.strict_suid) {
		if (!run_as(global.run_as)) {
			log_error("Could not change user and group id to those of run_as user %s",global.run_as);
			pdnsd_exit();
		}
	}

	uname(&nm);
	(void)p; /* To inhibit "unused variable" warning */
	unlink(fifo_path); /* Delete the socket */
	if ((sock=socket(PF_UNIX,SOCK_STREAM,0))==-1) {
		if (errno!=EINTR)
			log_warn("Failed to open socket: %s. Status readback will be impossible",strerror(errno));
	}
	a.sun_family=AF_UNIX;
	strncpy(a.sun_path,fifo_path,99);
	if (bind(sock,(struct sockaddr *)&a,sizeof(a))==-1) {
		log_warn("Error: could not bind socket: %s.\nStatus readback will be impossible",strerror(errno));
		close(sock);
		return NULL;
	}
	chmod(fifo_path,global.ctl_perms);
	if (listen(sock,5)==-1) {
		log_warn("Error: could not listen onsocket: %s.\nStatus readback will be impossible",strerror(errno));
		close(sock);
		return NULL;
	}
	do {
		res=sizeof(ra);
		if ((rs=accept(sock,&ra,&res))!=-1) {
/*			write(rs,fifo_path,strlen(fifo_path)+1);*/
/*			if (!(f=fdopen(rs,"rw"))) {
				log_warn("Error: could not get FILE: %s\n. Status readback will be impossible",strerror(errno));
				close(rs);
				return NULL;
				}*/
			DEBUG_MSG1("Pipe query pending.\n");
			read(rs,&cmd,sizeof(cmd));
			switch(ntohs(cmd)) {
			case CTL_STATS:
				DEBUG_MSG1("Received STATUS query.\n");
				fsprintf(rs,"pdnsd-%s running on %s.\n",VERSION,nm.nodename);
				report_cache_stat(rs);
				report_conf_stat(rs);
				break;
			case CTL_SERVER:
				break;
			}
			close(rs);
			usleep(100000); /* sleep some time. I do not want the query frequency to be too high. */
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

/*	strncpy(fifo_path,global.cache_dir,1023);
	fifo_path[1023]='\0';
	strncat(fifo_path,"/status",1023-strlen(fifo_path));
	fifo_path[1023]='\0';*/
//	mkfifo(fifo_path,0600);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
	if (pthread_create(&st,&attr,status_thread,NULL))
		log_warn("Failed to start status thread. The status fifo will be unuseable");
	else
		log_info(2,"Status pipe thread started.");
}
