/* servers.c - manage a set of dns servers
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
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include "error.h"
#include "servers.h"
#include "conff.h"
#include "consts.h"
#include "icmp.h"
#include "netdev.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: servers.c,v 1.7 2000/06/22 09:57:34 thomas Exp $";
#endif

pthread_t stt;
pthread_mutex_t servers_lock;
int fexecerr=1;

/*
 * Execute an uptest.
 */
int uptest (servparm_t serv)
{
	int ret/*=serv.is_up*/;
	struct passwd *pwd;
	pid_t pid;
	switch (serv.uptest) {
	case C_NONE:
		ret=1;
		break;
	case C_PING:
		ret=ping(&serv.ping_a,serv.ping_timeout,2)!=-1;
		break;
	case C_IF:
		ret=if_up(serv.interface);
		break;
	case C_EXEC:
		if ((pid=fork())==-1) {
			ret=0;
			break;
		} else if (pid==0) {
			if (geteuid()!=getuid()) {
				/* We ran as setuid. This is not inherited to the command for security reasons! */
				seteuid(getuid());
			}
			if (getegid()!=getgid()) {
				/* We ran as setgid. This is not inherited to the command! */			
				setegid(getgid());
			}
			if (serv.uptest_usr[0]!='\0') {
				/* Try to setuid() to a different user as specified. Good when you
				   don't want the test command to run as root */
				if (!(pwd=getpwnam(serv.uptest_usr))) {
					if (fexecerr) {
						log_error("Unable to get uid for %s: %s",serv.uptest_usr,strerror(errno));
						fexecerr=0;
					}
					/*exit(42);*/ /*no success */
					ret=0;
					break;
				}
				/* setgid first, because we may not allowed to do it anymore after setuid */
				if (setgid(pwd->pw_gid)!=0) {
					if (fexecerr) {
						log_error("Unable to do setgid for user %s: %s",serv.uptest_usr,strerror(errno));
						fexecerr=0;
					}
					/*exit(44);*/
					ret=0;
					break;
				}
				if (setuid(pwd->pw_uid)!=0) {
					if (fexecerr) {
						log_error("Unable to do setuid for user %s: %s",serv.uptest_usr,strerror(errno));
						fexecerr=0;
					}
					/*exit(43);*/
					ret=0;
					break;
				}
			}
			execl("/bin/sh", "uptest_sh","-c",serv.uptest_cmd,NULL);
			_exit(1); /* failed execl */
		} else {
			waitpid(pid,&ret,0);
			ret=(WEXITSTATUS(ret)==0);
		}
		/*fexecerr=0;*/
	}
	return ret;
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
	int i,j,all_none=1;
	long s_ts;
	servparm_t srv;

	(void)p; /* To inhibit "unused variable" warning */

	THREAD_SIGINIT;

	for (i=0;i<serv_num;i++) {
		s_ts=time(NULL);
		j=uptest(servers[i]);
		if (servers[i].uptest!=C_NONE) {
			all_none=0;
		}
		pthread_mutex_lock(&servers_lock);
		servers[i].is_up=j;
		servers[i].i_ts=s_ts;
		pthread_mutex_unlock(&servers_lock);
	}
	if (all_none)
		return NULL; /* we need no server status thread. */
	while (1) {
		for (i=0;i<serv_num;i++) {
			pthread_mutex_lock(&servers_lock);
			if (servers[i].interval>0 && (time(NULL)-servers[i].i_ts>servers[i].interval ||
						      servers[i].i_ts>time(NULL))) { /* kluge for clock skew */
				/* Unlock the mutex because some of the tests may take a while. */
				srv=servers[i];
				pthread_mutex_unlock(&servers_lock);
				s_ts=time(NULL);
				j=uptest(srv);
				pthread_mutex_lock(&servers_lock);
				servers[i].is_up=j;
				servers[i].i_ts=s_ts;
			}
			pthread_mutex_unlock(&servers_lock);
		}
		usleep(500000);
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
	int j;
	long s_ts;
	servparm_t srv;
	if (idx>=serv_num) {
#if DEBUG>0
		log_warn("Internal: server index out of range.");
#endif
		return;
	}
	pthread_mutex_lock(&servers_lock);
	if (servers[idx].uptest==C_PING) {
		servers[idx].is_up=0;
		servers[idx].i_ts=time(NULL);
	} else if (servers[idx].uptest!=C_NONE) {
		srv=servers[idx];
		s_ts=time(NULL);
		pthread_mutex_unlock(&servers_lock);
		j=uptest(srv); /* retest */
		pthread_mutex_lock(&servers_lock);
		servers[idx].is_up=j;
		servers[idx].i_ts=s_ts;
	}
	pthread_mutex_unlock(&servers_lock);
}

/*
 * Test called by the dns query handlers to handle interval=onquery cases.
 */
void test_onquery()
{
	int i,j;
	long s_ts;
	for (i=0;i<serv_num;i++) {
		if (servers[i].interval<0) {
			s_ts=time(NULL);
			j=uptest(servers[i]);
			pthread_mutex_lock(&servers_lock);
			servers[i].is_up=j;
			servers[i].i_ts=s_ts;
			pthread_mutex_unlock(&servers_lock);
		}
	}
}
