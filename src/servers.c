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
#include "status.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: servers.c,v 1.19 2002/07/19 21:14:19 tmm Exp $";
#endif

/*
 * We may be a little over-strict with locks here. Never mind...
 * Also, there may be some code-redundancy regarding uptests. It saves some locks, though.
 */

pthread_t stt;
pthread_mutex_t servers_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t server_data_cond = PTHREAD_COND_INITIALIZER;
int server_data_users = 0;
static char schm[32];

/*
 * Execute an individual uptest.Call with locks applied 
 */
static int uptest (servparm_t *serv, int j)
{
	int ret=0;

	/* Unlock the mutex because some of the tests may take a while. */
	++server_data_users;
	pthread_mutex_unlock(&servers_lock);

	switch (serv->uptest) {
	case C_NONE:
		/* Don't change */
		ret=DA_INDEX(serv->atup_a,j).is_up;
		break;
	case C_PING:
		ret=ping(is_inaddr_any(&serv->ping_a) ? &DA_INDEX(serv->atup_a,j).a : &serv->ping_a, serv->ping_timeout,2)!=-1;
		break;
	case C_IF:
 	case C_DEV:
	case C_DIALD:
 		ret=if_up(serv->interface);
#if TARGET==TARGET_LINUX
 		if (ret!=0 && serv->uptest==C_DEV) {
 			ret=dev_up(serv->interface,serv->device);
 		}
 		if (ret!=0 && serv->uptest==C_DIALD) {
 			ret=dev_up("diald",serv->device);
 		}
#endif
		break;
	case C_EXEC:
	  {
	  	pid_t pid;

		if ((pid=fork())==-1) {
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
			if (!run_as(serv->uptest_usr)) {
				log_error("Unable to get uid for %s: %s",serv->uptest_usr,strerror(errno));
				_exit(1);
			}
			{
			    struct rlimit rl; int i;
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
			}
			execl("/bin/sh", "uptest_sh","-c",serv->uptest_cmd,NULL);
			_exit(1); /* failed execl */
		} else {
			int status;
			if (waitpid(pid,&status,0)==pid && WIFEXITED(status)) {
				ret=(WEXITSTATUS(status)==0);
			}
		}
	  }
	}

	pthread_mutex_lock(&servers_lock);
	PDNSD_ASSERT(server_data_users>0, "server_data_users non-positive before attempt to decrement it");
	if (--server_data_users==0) pthread_cond_broadcast(&server_data_cond);

	return ret;
}

inline static int scheme_ok(servparm_t *serv)
{
	if (serv->scheme[0]) {
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
		if (fnmatch(serv->scheme, schm, 0))
		  	return 0;
	}
	return 1;
}

/* Internal server test. Call with locks applied.
   May test a single server ip or several collectively.
 */
static void retest(int i, int j)
{
  time_t s_ts;
  servparm_t *srv=&DA_INDEX(servers,i);
  int nsrvs;

  if(j>=0)
    nsrvs=j+1;  /* test just one */
  else {
    j=0;        /* test a range of servers */
    nsrvs=DA_NEL(srv->atup_a);
  }

  if(!scheme_ok(srv)) {
    s_ts=time(NULL);

    for(;j<nsrvs;++j) {
      DA_INDEX(srv->atup_a,j).is_up=0;
      DA_INDEX(srv->atup_a,j).i_ts=s_ts;
    }
  }
  else if(srv->uptest==C_NONE) {
    s_ts=time(NULL);

    for(;j<nsrvs;++j) {
	DA_INDEX(srv->atup_a,j).i_ts=s_ts;
    }
  }
  else if(srv->uptest==C_PING && is_inaddr_any(&srv->ping_a)) {  /* test each ip address seperately */
    for(;j<nsrvs;++j) {
	s_ts=time(NULL);
	DA_INDEX(srv->atup_a,j).is_up=uptest(srv,j);
	DA_INDEX(srv->atup_a,j).i_ts=s_ts;
    }
  }
  else {  /* test ip addresses collectively */
    int res;

    s_ts=time(NULL);
    res=uptest(srv,j);
    for(;j<nsrvs;++j) {
      DA_INDEX(srv->atup_a,j).is_up=res;
      DA_INDEX(srv->atup_a,j).i_ts=s_ts;
    }
  }
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
	for (i=0;i<DA_NEL(servers);++i) {
		sp=&DA_INDEX(servers,i);
		if (sp->interval>0 && (sp->uptest!=C_NONE || sp->scheme[0])) {
			all_none=0;
		}
		retest(i,-1);
	}
	if (all_none) {
	  pthread_mutex_unlock(&servers_lock);
	  return NULL; /* we need no server status thread. */
	}
	for(;;) {
		{
		  int minwait=3600;
		  time_t now=time(NULL);

		  for (i=0;i<DA_NEL(servers);++i) {
		    sp=&DA_INDEX(servers,i);
		    if(sp->interval>0) {
		      int j;

		      for(j=0;j<DA_NEL(sp->atup_a);++j) {
			int wait= DA_INDEX(sp->atup_a,j).i_ts + sp->interval - now;
			if(wait < minwait) minwait=wait;
		      }
		    }
		  }
		  pthread_mutex_unlock(&servers_lock);
		  if(minwait>0) sleep_r(minwait);
		  else usleep_r(500000);
		}
		pthread_mutex_lock(&servers_lock);
		schm[0] = '\0';
		for (i=0;i<DA_NEL(servers);++i) {
			sp=&DA_INDEX(servers,i);
			if(sp->interval>0) {
			  int j;

			  for(j=0;j<DA_NEL(sp->atup_a);++j) {
			    time_t tj=DA_INDEX(sp->atup_a,j).i_ts;
			    time_t now=time(NULL);
			    if (now-tj>sp->interval ||
				tj>now) { /* kluge for clock skew */
			      retest(i,j);
			    }
			  }
			}
		}
	}
	return NULL;
}

/*
 * Start the server status thread.
 */
void start_servstat_thread()
{
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
	if (pthread_create(&stt,&attr,servstat_thread,NULL))
		log_warn("Failed to start server status thread. Assuming all servers to be up all time.");
	else
		log_info(2,"Server status thread started.");
	pthread_attr_destroy(&attr);
}

/*
 * If a connect() to a server failed, try to mark it as down (only for uptest=ping servers)
 */ 
void mark_server_down(pdnsd_a *sa, int retst)
{
	int i,j;
	
	pthread_mutex_lock(&servers_lock);
	for(i=0;i<DA_NEL(servers);++i) {
	  servparm_t *sp=&DA_INDEX(servers,i);
	  for(j=0;j<DA_NEL(sp->atup_a);++j) {
	    atup_t *at=&DA_INDEX(sp->atup_a,j);
	    if(same_inaddr(&at->a,sa)) {
	      if(retst?(sp->uptest==C_PING):(sp->interval>0)) {
		at->is_up=0;
		at->i_ts=time(NULL);
	      } 
	      else if(retst && at->is_up && sp->uptest!=C_NONE) {
		  retest(i,j);
	      }
	    }
	  }
	}

	pthread_mutex_unlock(&servers_lock);
}

/* Put a server up or down */
void mark_server(int i, int j, int up)
{
	servparm_t *sp;
	time_t now;
	int n;

	pthread_mutex_lock(&servers_lock);
	sp=&DA_INDEX(servers,i);
	now=time(NULL);
	if(j>=0)
	  n=j+1;
	else {
	  j=0; n=DA_NEL(sp->atup_a);
	}
	for(;j<n;++j) {
	  DA_INDEX(sp->atup_a,j).is_up=up;
	  DA_INDEX(sp->atup_a,j).i_ts=now;
	}

	pthread_mutex_unlock(&servers_lock);
}

void perform_uptest(int i, int j)
{
	pthread_mutex_lock(&servers_lock);
	schm[0] = '\0';
	retest(i,j);
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
	for (i=0;i<DA_NEL(servers);i++) {
		if (DA_INDEX(servers,i).interval<0) {
			retest(i,-1);
		}
	}
	pthread_mutex_unlock(&servers_lock);
}


void lock_server_data()
{
     pthread_mutex_lock(&servers_lock);
     ++server_data_users;
     pthread_mutex_unlock(&servers_lock);
}

void unlock_server_data()
{
     pthread_mutex_lock(&servers_lock);
     PDNSD_ASSERT(server_data_users>0, "server_data_users non-positive before attempt to decrement it");
     if (--server_data_users==0) pthread_cond_broadcast(&server_data_cond);
     pthread_mutex_unlock(&servers_lock);
}


/*
  Change addresses of servers during runtime.
*/
int change_servers(int i, addr_array ar, int c)
{
     int change=0,result=0;
     int n=DA_NEL(ar);
     servparm_t *sp;

     pthread_mutex_lock(&servers_lock);
     sp=&DA_INDEX(servers,i);
     if(n != DA_NEL(sp->atup_a))
       change=1;
     else {
       int j;
       for(j=0;j<n;++j)
	 if(!same_inaddr(&DA_INDEX(ar,j),&DA_INDEX(sp->atup_a,j).a)) {
	   change=1;
	   break;
	 }
     }
     if(change) {
       /* we need exclusive access to the server data to make the changes */
       struct timeval now;
       struct timespec timeout;

       DEBUG_MSG("Changing IPs of server section #%d\n",i);
       gettimeofday(&now,NULL);
       timeout.tv_sec = now.tv_sec + 60;     /* time out after 60 seconds */
       timeout.tv_nsec = now.tv_usec * 1000;
       while (server_data_users>0) {
	 if(pthread_cond_timedwait(&server_data_cond, &servers_lock, &timeout) == ETIMEDOUT)
	   goto unlock_mutex;
       }

       sp->atup_a = DA_RESIZE(sp->atup_a, n);
     }

     {
       time_t now = time(NULL);
       int upordown = (c==CTL_S_UP)?1:(c==CTL_S_DOWN)?0:sp->preset;
       int j;
       for(j=0; j<n; ++j) {
	 atup_t *at = &DA_INDEX(sp->atup_a,j);
	 if(change) at->a = DA_INDEX(ar,j);
	 at->is_up=upordown;
	 at->i_ts=now;
       }
     }

     if(c==CTL_S_RETEST) retest(i,-1);
     result=1;

 unlock_mutex:
     pthread_mutex_unlock(&servers_lock);
     return result;
}
