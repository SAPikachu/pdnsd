/* status.c - Allow control of a running server using a socket
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
#include "ipvers.h"
#include "status.h"
#include "thread.h"
#include "cache.h"
#include "error.h"
#include "servers.h"
#include "helpers.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: status.c,v 1.30 2001/06/02 18:07:15 tmm Exp $";
#endif

char sock_path[MAXPATH];
int stat_sock;

pthread_t st;

/* Print an error to the socket */
void print_serr(int rs, char *msg)
{
	short cmd;

	cmd=htons(1);
	write(rs,&cmd,sizeof(cmd));
	fsprintf(rs,"%s",msg);
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

	if (read(fh,&cmd,sizeof(cmd))!=sizeof(cmd)) {
		print_serr(fh,"Bad arg.");
		return -2;
	}
	return ntohs(cmd);
}

/* Read a cmd long */
long read_long(int fh)
{
	long cmd;

	if (read(fh,&cmd,sizeof(cmd))!=sizeof(cmd)) {
		print_serr(fh,"Bad arg.");
		return -2;
	}
	return ntohl(cmd);
}

/* Read a zero-terminated string of maximum len. Len must be >1 */
short fsgets(int fh, char *buf, int len)
{
	int i=0;
	char c;

	do {
		if (i>=len)
			return 0;
		if (read(fh,&c,sizeof(c))!=sizeof(c))
			return 0;
		buf[i]=c;
		i++;
	} while (c!='\0');
	return 1;
}

int read_domain(int fh, char *buf, int buflen)
{
	PDNSD_ASSERT(buflen>0, "bad read_domain call");
	if (!fsgets(fh,buf,buflen-1)) {
		print_serr(fh,"Bad domain name.");
		return 0;
	}
	if (buf[strlen(buf)-1]!='.') {
		buf[strlen(buf)+1]='\0';
		buf[strlen(buf)]='.';
	}
	if (strlen(buf)>255) {
		print_serr(fh,"Bad domain name.");
		return 0;
	}
	return 1;
}

void *status_thread (void *p)
{
	int rs,sz,i,updown;
	socklen_t res;
	struct utsname nm;
	short cmd,cmd2;
	struct sockaddr_un ra;
	char fn[1025];
	char buf[257],dbuf[256];
	char errbuf[256];
	char owner[256];
	long ttl;
	dns_cent_t cent;

	THREAD_SIGINIT;
	(void)p; /* To inhibit "unused variable" warning */

	if (!global.strict_suid) {
		if (!run_as(global.run_as)) {
			log_error("Could not change user and group id to those of run_as user %s",global.run_as);
			pdnsd_exit();
		}
	}

	uname(&nm);
	if (listen(stat_sock,5)==-1) {
		log_warn("Error: could not listen on socket: %s.\nStatus readback will be impossible",strerror(errno));
		close(stat_sock);
		return NULL;
	}
	do {
		res=sizeof(ra);
		if ((rs=accept(stat_sock,(struct sockaddr *)&ra,&res))!=-1) {
			DEBUG_MSG("Status socket query pending.\n");
			read(rs,&cmd,sizeof(cmd));
			switch(ntohs(cmd)) {
			case CTL_STATS:
				DEBUG_MSG("Received STATUS query.\n");
				fsprintf(rs,"pdnsd-%s running on %s.\n",VERSION,nm.nodename);
				report_cache_stat(rs);
				report_conf_stat(rs);
				break;
			case CTL_SERVER:
				DEBUG_MSG("Received SERVER command.\n");
				if (!fsgets(rs,buf,sizeof(buf))) {
					print_serr(rs,"Bad server label.");
					break;
				}
                                if(sscanf(buf,"%hd%c",&cmd,&dbuf[0])!=1) {
					if (!strcmp(buf, "all"))
						cmd=-2; /* all servers */
					else
						cmd=-1; /* compare names */
				}
				if ((cmd2=read_short(rs))<-1)
					break;
				if (cmd<-2 || cmd>=da_nel(servers)) {
					print_serr(rs,"Server index out of range.");
					break;
				}
				updown=0;
				switch (cmd2) {
				case CTL_S_UP:
					updown=1;
					/* fall though */
				case CTL_S_DOWN:
					if (cmd<0) {
						for (i=0;i<da_nel(servers);i++)
							if (cmd==-2 || !strcmp(DA_INDEX(servers,i,servparm_t)->label,buf))
								mark_server(i,updown);
					} else
						mark_server(cmd,updown);
					print_succ(rs);
					break;
				case CTL_S_RETEST:
					if (cmd<0) {
						for (i=0;i<da_nel(servers);i++) {
							if (cmd==-2 || !strcmp(DA_INDEX(servers,i,servparm_t)->label,buf))
								perform_uptest(i);
						}
					} else
						perform_uptest(cmd);
					print_succ(rs);
					break;
				default:
					print_serr(rs,"Bad command.");
				}
				break;
			case CTL_RECORD:
				DEBUG_MSG("Received RECORD command.\n");
				if ((cmd=read_short(rs))<-1)
					break;
				if (!read_domain(rs, buf, sizeof(buf)))
					break;
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
				DEBUG_MSG("Received SOURCE command.\n");
				if (!fsgets(rs,fn,1024)) {
					print_serr(rs,"Bad filename name.");
					break;
				}
				if (!read_domain(rs, buf, sizeof(buf)))
					break;
				if (!str2rhn((unsigned char *)buf,(unsigned char *)owner)) {
					print_serr(rs,"Bad domain name.");
					break;
				}
				if ((ttl=read_long(rs))<-1)
					break;
				if ((cmd=read_short(rs))<-1)	/* serve aliases */
					break;
				if ((cmd2=read_short(rs))<-1)	/* caching flags */
					break;
				if (read_hosts(fn,(unsigned char *)owner,ttl,cmd2, cmd,errbuf,sizeof(errbuf)))
					print_succ(rs);
				else
					print_serr(rs,errbuf);
				break;
			case CTL_ADD:
				DEBUG_MSG("Received ADD command.\n");
				if ((cmd=read_short(rs))<-1)
					break;
				if (!read_domain(rs, buf, sizeof(buf)))
					break;
				if (!str2rhn((unsigned char *)buf,(unsigned char *)owner)) {
					print_serr(rs,"Bad domain name.");
					break;
				}
				if ((ttl=read_long(rs))<0)
					break;
				if ((cmd2=read_short(rs))<-1)	/* caching flags */
					break;

				sz=-1;
				switch (cmd) {
				case T_A:
					if (read(rs,dbuf,sizeof(struct in_addr))<sizeof(struct in_addr)) {
						print_serr(rs,"Bad arg.");
						break;
					}
					sz=sizeof(struct in_addr);
					break;
#ifdef ENABLE_IPV6
				case T_AAAA:
					if (read(rs,dbuf,sizeof(struct in6_addr))<sizeof(struct in6_addr)) {
						print_serr(rs,"Bad arg.");
						break;
					}
					sz=sizeof(struct in6_addr);
					break;
#endif
				case T_CNAME:
				case T_PTR:
					if (!read_domain(rs, owner, sizeof(owner)))
						break;
					if (!str2rhn((unsigned char *)owner,(unsigned char *)dbuf)) {
						print_serr(rs,"Bad domain name.");
						break;
					}
					sz=rhnlen((unsigned char *)dbuf);
					break;
				case T_MX:
					if (read(rs,dbuf,sizeof(short))<sizeof(short)) {
						print_serr(rs,"Bad arg.");
						break;
					}
					if (!read_domain(rs, owner, sizeof(owner)))
						break;
					if (!str2rhn((unsigned char *)owner,(unsigned char *)dbuf+2)) {
						print_serr(rs,"Bad domain name.");
						break;
					}
					sz=rhnlen((unsigned char *)(dbuf+2))+2;;
					break;
				default:
					print_serr(rs,"Bad arg.");
				}
				if (sz<0)
					break;
			
				if (!init_cent(&cent, (unsigned char *)buf, cmd2, time(NULL), 0, 1)) {
					print_serr(rs,"Out of memory");
					break;
				}
				add_cent_rr(&cent,ttl,0,CF_LOCAL,sz,dbuf,cmd,1);
				add_cache(cent);
				free_cent(cent,1);
				print_succ(rs);
				break;
			case CTL_NEG:
				DEBUG_MSG("Received NEG command.\n");
				if (!read_domain(rs, buf, sizeof(buf)))
					break;
				if (!str2rhn((unsigned char *)buf,(unsigned char *)owner)) {
					DEBUG_MSG("NEG: received bad domain name.\n");
					print_serr(rs,"Bad domain name.");
					break;
				}
				if ((cmd=read_short(rs))<-1)
					break;
				if ((ttl=read_long(rs))<-1)
					break;
				if (cmd!=255 && (cmd<T_MIN || cmd>T_MAX)) {
					DEBUG_MSG("NEG: received bad record type.\n");
					print_serr(rs,"Bad record type.");
					break;
				}
				if (cmd==255) {
					if (!init_cent(&cent, (unsigned char *)buf, DF_LOCAL|DF_NEGATIVE, time(NULL), ttl, 1)) {
						print_serr(rs,"Out of memory");
						break;
					}
				} else {
					if (!init_cent(&cent, (unsigned char *)buf, 0, time(NULL), 0, 1)) {
						print_serr(rs,"Out of memory");
						break;
					}
					if (!add_cent_rrset(&cent,cmd,ttl,0,CF_LOCAL|CF_NEGATIVE,0, 1)) {
						free_cent(cent, 1);
						print_serr(rs,"Out of memory");
						break;
					}
				}
				add_cache(cent);
				free_cent(cent, 1);
				print_succ(rs);
				break;
			default:
				print_serr(rs,"Unknown command.");
			}
			close(rs);
			usleep_r(100000); /* sleep some time. I do not want the query frequency to be too high. */
		} else {
			if (errno!=EINTR)
				log_warn("Failed to open socket: %s. Status readback will be impossible",strerror(errno));
			return NULL;
		}
	} while(1);
	return NULL;
}

/*
 * Initialize the status socket
 */
void init_stat_sock()
{
	struct sockaddr_un a;
	mode_t omask;
	
	/* Early initialization, so that umask can be used race-free. */
	if (snprintf(a.sun_path, sizeof(a.sun_path), "%s/pdnsd.status", global.cache_dir) >= sizeof(a.sun_path)) {
		log_warn("cache directory name too long");
		return;
	}
	if (unlink(a.sun_path)!=0 && errno!=ENOENT) { /* Delete the socket */
		log_warn("Failed to unlink %s: %s.",strerror(errno));
		pdnsd_exit();
	}
	if ((stat_sock=socket(PF_UNIX,SOCK_STREAM,0))==-1) {
		if (errno!=EINTR)
			log_warn("Failed to open socket: %s. Status readback will be impossible",strerror(errno));
		return;
	}
	a.sun_family=AF_UNIX;
#ifdef BSD44_SOCKA
	a.sun_len=SUN_LEN(&a);
#endif
	omask = umask((S_IRWXU|S_IRWXG|S_IRWXO)&(~global.ctl_perms));
	if (bind(stat_sock,(struct sockaddr *)&a,sizeof(a))==-1) {
		log_warn("Error: could not bind socket: %s.\nStatus readback will be impossible",strerror(errno));
		close(stat_sock);
		return NULL;
	}
	umask(omask);
}

/*
 * Start the status socket thread (see above)
 */
void start_stat_sock()
{
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
	if (pthread_create(&st,&attr,status_thread,NULL))
		log_warn("Failed to start status thread. The status socket will be unuseable");
	else
		log_info(2,"Status thread started.");
}
