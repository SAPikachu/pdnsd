/* servers.c - manage a set of dns servers
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <string.h>
#include "thread.h"
#include "error.h"
#include "servers.h"
#include "conff.h"
#include "consts.h"
#include "icmp.h"
#include "netdev.h"
#include "helpers.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: servers.c,v 1.19 2002/07/19 21:14:19 tmm Exp $";
#endif

/*
 * We may be a little over-strict with locks here. Never mind...
 * Also, there may be some code-redundancy regarding uptests. It saves some locks, though.
 */

pthread_t stt;
pthread_mutex_t servers_lock;
static char schm[32];

/*
 * Execute an uptest.
 */
int uptest (servparm_t serv)
{
	int ret, i;
	pid_t rv, pid;
	struct rlimit rl;

	if (serv.scheme[0]) {
		if (!schm[0]) {
		  	int nschm;
			int sc = open(global.scheme_file, O_RDONLY);
			char *s;
			if (sc<0) 
				return 0;
			nschm = read(sc, schm, sizeof(schm)-1);
			close(sc);
			if (nschm < 0) 
				return 0;
			schm[nschm] = '\0';
			s = strchr(schm, '\n');
			if (s) 
				*s='\0';
		}
		if (fnmatch(serv.scheme, schm, 0))
		  	return 0;
	}
	switch (serv.uptest) {
	case C_NONE:
		/* Don't change */
		ret=serv.is_up;
		break;
	case C_PING:
		ret=ping(&serv.ping_a,serv.ping_timeout,2)!=-1;
		break;
	case C_IF:
 	case C_DEV:
	case C_DIALD:
 		ret=if_up(serv.interface);
#if TARGET==TARGET_LINUX
 		if (ret!=0 && serv.uptest==C_DEV) {
 			ret=dev_up(serv.interface,serv.device);
 		}
 		if (ret!=0 && serv.uptest==C_DIALD) {
 			ret=dev_up("diald",serv.device);
 		}
#endif
		break;
	case C_EXEC:
		if ((pid=fork())==-1) {
			ret=0;
			break;
		} else if (pid==0) {
			/*
			 * If we ran as setuid or setgid, do not inherit this to the
			 * command. This is just a last guard. Running pdnsd as setuid()
			 * or setgid() is a no-no.
			 */
			if (setgid(getgid()) == -1 || setuid(getuid()) == -1) {
				log_error("Could not reset uid or gid: %s",strerror(errno));
				_exit(1);
			}
			/* Try to setuid() to a different user as specified. Good when you
			   don't want the test command to run as root */
			if (!run_as(serv.uptest_usr)) {
				log_error("Unable to get uid for %s: %s",serv.uptest_usr,strerror(errno));
				_exit(1);
			}
			/*
			 * Mark all open fd's FD_CLOEXEC for paranoia reasons.
			 */
			if (getrlimit(RLIMIT_NOFILE, &rl) == -1) {
				log_error("getrlimit() failed: %s",strerror(errno));
				_exit(1);
			}
			for (i = 0; i <= rl.rlim_max; i++) {
				if (fcntl(i, F_SETFD, FD_CLOEXEC) == -1 && errno != EBADF) {
					log_error("fcntl(F_SETFD) failed: %s",strerror(errno));
					_exit(1);
				}
			}
			execl("/bin/sh", "uptest_sh","-c",serv.uptest_cmd,NULL);
			_exit(1); /* failed execl */
		} else {
			while (1) {
				if ((rv = waitpid(pid,&ret,0))==-1) {
					ret=0;
					break;
				}
				if (rv == pid && WIFEXITED(ret)) {
					ret=(WEXITSTATUS(ret)==0);
					break;
				}
			}
		}
	}
	return ret;
}

/* Internal server test. Call with locks applied */
static void retest(int i)
{
	int j;
	time_t s_ts;
	servparm_t srv;

        /* Unlock the mutex because some of the tests may take a while. */
	srv=*DA_INDEX(servers,i,servparm_t);
	pthread_mutex_unlock(&servers_lock);
	s_ts=time(NULL);
	j=uptest(srv);
	pthread_mutex_lock(&servers_lock);
	DA_INDEX(servers,i,servparm_t)->is_up=j;
	DA_INDEX(servers,i,servparm_t)->i_ts=s_ts;
}

/*
 * Refresh the server status by pinging or testing the interface in the given interval.
 * Note that you may get inaccuracies in the dimension of the ping timeout or the runtime
 * of your uptest command if you have uptest=ping or uptest=exec for at least one server.
 * This happens when all the uptests for the first n servers take more time than the inteval
 * of n+1 (or 0 when n+1>servnum). I do not think that these delays are critical, so I did
 * not to anything about that (because that may also be costly).
 */
void *servstat_thread(void *p)
{
	int i,all_none=1;
	servparm_t *sp;

	(void)p; /* To inhibit "unused variable" warning */

	THREAD_SIGINIT;

	pthread_mutex_lock(&servers_lock);
	for (i=0;i<da_nel(servers);i++) {
		sp=DA_INDEX(servers,i,servparm_t);
		if (sp->uptest!=C_NONE || sp->scheme[0]) {
			all_none=0;
		}
		retest(i);
	}
	pthread_mutex_unlock(&servers_lock);
	if (all_none)
		return NULL; /* we need no server status thread. */
	while (1) {
		schm[0] = '\0';
		pthread_mutex_lock(&servers_lock);
		for (i=0;i<da_nel(servers);i++) {
			sp=DA_INDEX(servers,i,servparm_t);
			if (sp->interval>0 && (time(NULL)-sp->i_ts>sp->interval ||
			    sp->i_ts>time(NULL))) { /* kluge for clock skew */
				retest(i);
			}
		}
		pthread_mutex_unlock(&servers_lock);
		usleep_r(500000);
	}
	return NULL;
}

/*
 * Start the server status thread.
 */
void start_servstat_thread()
{
	pthread_attr_t attr;
	pthread_mutex_init(&servers_lock,NULL);
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
	if (pthread_create(&stt,&attr,servstat_thread,NULL))
		log_warn("Failed to start server status thread. Assuming all servers to be up all time.");
	else
		log_info(2,"Server status thread started.");
}

/*
 * If a connect() to a server failed, try to mark it as down (only for uptest=ping servers)
 */ 
void mark_server_down(int idx)
{
	servparm_t *sp;
	
	if (idx>=da_nel(servers)) {
#if DEBUG>0
		log_warn("Internal: server index out of range.");
#endif
		return;
	}
	sp=DA_INDEX(servers,idx,servparm_t);
	pthread_mutex_lock(&servers_lock);
	if (sp->uptest==C_PING) {
		sp->is_up=0;
		sp->i_ts=time(NULL);
	} else if (sp->uptest!=C_NONE) {
		retest(idx);
	}
	pthread_mutex_unlock(&servers_lock);
}

/* Put a server up or down */
void mark_server(int idx, int up)
{
	pthread_mutex_lock(&servers_lock);
	DA_INDEX(servers,idx,servparm_t)->is_up=up;
	DA_INDEX(servers,idx,servparm_t)->i_ts=time(NULL);
	pthread_mutex_unlock(&servers_lock);
}

void perform_uptest(int idx)
{
	pthread_mutex_lock(&servers_lock);
	schm[0] = '\0';
	retest(idx);
	pthread_mutex_unlock(&servers_lock);
}

/*
 * Test called by the dns query handlers to handle interval=onquery cases.
 */
void test_onquery()
{
	int i;
	
	pthread_mutex_lock(&servers_lock);
	schm[0] = '\0';
	for (i=0;i<da_nel(servers);i++) {
		if (DA_INDEX(servers,i,servparm_t)->interval<0) {
			retest(i);
		}
	}
	pthread_mutex_unlock(&servers_lock);
}

