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
#include "thread.h"
#include "cacheing/cache.h"
#include "error.h"
#include "servers.h"
#include "helpers.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: status.c,v 1.11 2000/11/11 20:11:00 thomas Exp $";
#endif

char sock_path[1024];

pthread_t st;

/* Print an error to the socket */
void print_serr(int rs, char *msg)
{
	short cmd;

	cmd=htons(1);
	write(rs,&cmd,sizeof(cmd));
	fsprintf(rs,msg);
}

/* Print an success msg socket */
void print_succ(int rs)
{
	short cmd;

	cmd=htons(0);
	write(rs,&cmd,sizeof(cmd));
}

/* Read a cmd short */
short read_short(int fh)
{
	short cmd;

	if (read(fh,&cmd,sizeof(cmd))!=sizeof(cmd))
		return -2;
	return ntohs(cmd);
}

/* Read a cmd long */
long read_long(int fh)
{
	long cmd;

	if (read(fh,&cmd,sizeof(cmd))!=sizeof(cmd))
		return -2;
	return ntohl(cmd);
}

/* Read a zero-terminated string of maximum len. Len must be >1 */
short fsgets(int fh, char *buf, int len)
{
	int i=0;
	char c='a';

	do {
		if (read(fh,&c,sizeof(c))!=sizeof(c))
			return 0;
		buf[i]=c;
		i++;
		if (i>=len && c!='\0')
			return 0;
	} while (c!='\0');
	return 1;
}

/*
 * Give out server status information on the fifo "status" in the cache directory.
 * Inquire it by doing "cat <your-server-dir>/status"
 */
void *status_thread (void *p)
{
	int sock,rs,sz,i;
	socklen_t res;
	struct utsname nm;
	short cmd,cmd2;
	struct sockaddr_un a,ra;
	char fn[1025];
	char buf[257],dbuf[256];
	char errbuf[256];
	char owner[256];
	long ttl;
	dns_cent_t cent;

	THREAD_SIGINIT;

	if (!global.strict_suid) {
		if (!run_as(global.run_as)) {
			log_error("Could not change user and group id to those of run_as user %s",global.run_as);
			pdnsd_exit();
		}
	}

	uname(&nm);
	(void)p; /* To inhibit "unused variable" warning */
	strncpy(sock_path, TEMPDIR, 1024);
	sock_path[1023]='\0';
	strncat(sock_path, "/.pdnsd.status", 1024-strlen(sock_path));
	sock_path[1023]='\0';
	unlink(sock_path); /* Delete the socket */
	if ((sock=socket(PF_UNIX,SOCK_STREAM,0))==-1) {
		if (errno!=EINTR)
			log_warn("Failed to open socket: %s. Status readback will be impossible",strerror(errno));
	}
	a.sun_family=AF_UNIX;
	strncpy(a.sun_path,sock_path,99);
	a.sun_path[98]='\0';
	if (bind(sock,(struct sockaddr *)&a,sizeof(a))==-1) {
		log_warn("Error: could not bind socket: %s.\nStatus readback will be impossible",strerror(errno));
		close(sock);
		return NULL;
	}
	chmod(sock_path,global.ctl_perms);
	if (listen(sock,5)==-1) {
		log_warn("Error: could not listen onsocket: %s.\nStatus readback will be impossible",strerror(errno));
		close(sock);
		return NULL;
	}
	do {
		res=sizeof(ra);
		if ((rs=accept(sock,&ra,&res))!=-1) {
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
				DEBUG_MSG1("Received SERVER command.\n");
				if ((cmd=read_short(rs))<-1)
					break;
				if ((cmd2=read_short(rs))<0)
					break;
				if (cmd<-1 || cmd>=serv_num) {
					print_serr(rs,"Server index out of range.");
				}
				switch (cmd2) {
				case CTL_S_UP:
					if (cmd==-1) 
						for (i=0;i<serv_num;i++) {
							mark_server(i,1);
						}
					else 
						mark_server(cmd,1);
					print_succ(rs);
					break;
				case CTL_S_DOWN:
					if (cmd==-1) 
						for (i=0;i<serv_num;i++) {
							mark_server(i,0);
						}
					else
						mark_server(cmd,0);
					print_succ(rs);
					break;
				case CTL_S_RETEST:
					if (cmd==-1) 
						for (i=0;i<serv_num;i++) {
							perform_uptest(i);
						}
					else
						perform_uptest(cmd);
					print_succ(rs);
					break;
				default:
					print_serr(rs,"Bad command.");
				}
				break;
			case CTL_RECORD:
				DEBUG_MSG1("Received RECORD command.\n");
				if ((cmd=read_short(rs))<0)
					break;
				if (!fsgets(rs,buf,256)) {
					print_serr(rs,"Bad domain name.");
					break;
				}
				if (buf[strlen(buf)-1]!='.') {
					buf[strlen(buf)+1]='\0';
					buf[strlen(buf)]='.';
				}					
				switch (cmd) {
				case CTL_R_DELETE:
					del_cache((unsigned char*)buf);
					print_succ(rs);
					break;
				case CTL_R_INVAL:
					invalidate_record((unsigned char*)buf);
					print_succ(rs);
					break;
				default:
					print_serr(rs,"Bad command.");
				}
				break;
			case CTL_SOURCE:
				DEBUG_MSG1("Received SOURCE command.\n");
				if (!fsgets(rs,fn,1024)) {
					print_serr(rs,"Bad filename name.");
					break;
				}
				if (!fsgets(rs,buf,256)) {
					print_serr(rs,"Bad domain name.");
					break;
				}
				if (buf[strlen(buf)-1]!='.') {
					buf[strlen(buf)+1]='\0';
					buf[strlen(buf)]='.';
				}					
				if (!str2rhn((unsigned char *)buf,(unsigned char *)owner)) {
					print_serr(rs,"Bad domain name.");
					break;
				}
				if ((ttl=read_long(rs))<0)
					break;
				if ((cmd=read_short(rs))<0)
					break;
				if (read_hosts(fn,(unsigned char *)owner,ttl,cmd,errbuf,256))
					print_succ(rs);
				else
					print_serr(rs,errbuf);
				break;
			case CTL_ADD:
				DEBUG_MSG1("Received ADD command.\n");
				if ((cmd=read_short(rs))<0)
					break;
				if (!fsgets(rs,buf,256)) {
					print_serr(rs,"Bad owner name.");
					break;
				}
				if (buf[strlen(buf)-1]!='.') {
					buf[strlen(buf)+1]='\0';
					buf[strlen(buf)]='.';
				}
				if (!str2rhn((unsigned char *)buf,(unsigned char *)owner)) {
					print_serr(rs,"Bad domain name.");
					break;
				}
				if ((ttl=read_long(rs))<0)
					break;

				sz=-1;
				switch (cmd) {
				case T_A:
					if (read(rs,dbuf,sizeof(struct in_addr))<sizeof(struct in_addr)) {
						print_serr(rs,"Bad arg.");
					}
					sz=sizeof(struct in_addr);
					break;
#ifdef ENABLE_IPV6
				case T_AAAA:
					if (read(rs,dbuf,sizeof(struct in6_addr))<sizeof(struct in6_addr)) {
						print_serr(rs,"Bad arg.");
					}
					sz=sizeof(struct in6_addr);
					break;
#endif
				case T_CNAME:
				case T_PTR:
					if (!fsgets(rs,owner,256)) {
						print_serr(rs,"Bad domain name.");
						break;
					}
					if (!str2rhn((unsigned char *)owner,(unsigned char *)dbuf)) {
						print_serr(rs,"Bad domain name.");
						break;
					}
					sz=strlen(dbuf)+1;;
					break;
				default:
					print_serr(rs,"Bad arg.");
					break;
				}
				if (sz<0)
					break;
			
				if (!init_cent(&cent, (unsigned char *)buf, 0, time(NULL), 0)) {
					print_serr(rs,"Out of memory");
					break;
				}
				add_cent_rr(&cent,ttl,0,CF_LOCAL,sz,dbuf,cmd);
				add_cache(cent);
				print_succ(rs);
				break;
			case CTL_NEG:
				DEBUG_MSG1("Received NEG command.\n");
				if (!fsgets(rs,buf,256)) {
					DEBUG_MSG1("pipe NEG: received bad domain name.\n");
					print_serr(rs,"Bad domain name.");
					break;
				}
				if (buf[strlen(buf)-1]!='.') {
					buf[strlen(buf)+1]='\0';
					buf[strlen(buf)]='.';
				}
				if (!str2rhn((unsigned char *)buf,(unsigned char *)owner)) {
					DEBUG_MSG1("pipe NEG: received bad domain name.\n");
					print_serr(rs,"Bad domain name.");
					break;
				}
				if ((cmd=read_short(rs))<0)
					break;
				if ((ttl=read_long(rs))<0)
					break;
				if (cmd!=255 && (cmd<T_MIN || cmd>T_MAX)) {
					DEBUG_MSG1("pipe NEG: received bad record type.\n");
					print_serr(rs,"Bad record type.");
					break;
				}
				if (cmd==255) {
					if (!init_cent(&cent, (unsigned char *)buf, DF_LOCAL|DF_NEGATIVE, time(NULL), ttl)) {
						print_serr(rs,"Out of memory");
						break;
					}
				} else {
					if (!init_cent(&cent, (unsigned char *)buf, 0, time(NULL), 0)) {
						print_serr(rs,"Out of memory");
						break;
					}
					if (!add_cent_rrset(&cent,cmd,ttl,0,CF_LOCAL|CF_NEGATIVE,0)) {
						free_cent(cent);
						print_serr(rs,"Out of memory");
						break;
					}
				}
				add_cache(cent);
				print_succ(rs);
				break;
			default:
				print_serr(rs,"Unknown command.");
			}
			close(rs);
			usleep_r(100000); /* sleep some time. I do not want the query frequency to be too high. */
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

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
	if (pthread_create(&st,&attr,status_thread,NULL))
		log_warn("Failed to start status thread. The status fifo will be unuseable");
	else
		log_info(2,"Status pipe thread started.");
}
