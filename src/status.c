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
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>	/* for offsetof */
#include "ipvers.h"
#include "status.h"
#include "thread.h"
#include "cache.h"
#include "error.h"
#include "servers.h"
#include "helpers.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: status.c,v 1.34 2002/07/12 14:32:28 tmm Exp $";
#endif

char *sock_path=NULL;
int stat_sock;

pthread_t st;

/* Print an error to the socket */
static void print_serr(int rs, char *msg)
{
	short cmd;

	cmd=htons(1);
	if(write(rs,&cmd,sizeof(cmd))==sizeof(cmd))
	  write_all(rs,msg,strlen(msg));
}

/* Print an success msg socket */
static void print_succ(int rs)
{
	short cmd;

	cmd=htons(0);
	write(rs,&cmd,sizeof(cmd));
}

/* Read a cmd short */
static int read_short(int fh, short *res)
{
	short cmd;

	if (read(fh,&cmd,sizeof(cmd))!=sizeof(cmd)) {
		/* print_serr(fh,"Bad arg."); */
		return 0;
	}
	*res= ntohs(cmd);
	return 1;
}

/* Read a cmd long */
static int read_long(int fh,long *res)
{
	long cmd;

	if (read(fh,&cmd,sizeof(cmd))!=sizeof(cmd)) {
		/* print_serr(fh,"Bad arg."); */
		return 0;
	}
	*res= ntohl(cmd);
	return 1;
}

/* Read a string preceded by a char count.
   Place it in a buffer of size len and terminate by a null char.
 */
static int read_string(int fh, char *buf, int buflen)
{
	unsigned short count;
	int nread=0;

	if(!read_short(fh,&count)) return 0;
	if(count==(unsigned short)(~0)) return -1;
	if(count >=buflen) return 0;
	while(nread<count) {
	  int m=read(fh,buf+nread,count-nread);
	  if(m<=0) return 0;
	  nread+=m;
	}
	buf[count]=0;
	return 1;
}

static int read_domain(int fh, char *buf, int buflen)
{
	PDNSD_ASSERT(buflen>0, "bad read_domain call");
	if (read_string(fh,buf,buflen-1)<=0) {
		/* print_serr(fh,"Bad domain name."); */
		return 0;
	}
	{
	  char *p=strchr(buf,0);
	  if (*(p-1)!='.') {
		*p='.';
		*++p='\0';
	  }
	  if (p-buf>255) {
		  /* print_serr(fh,"Bad domain name."); */
		return 0;
	  }
	}
	return 1;
}

static void *status_thread (void *p)
{
	int rs,i;
	socklen_t res;
	struct utsname nm;
	short cmd,cmd2;
	struct sockaddr_un ra;
	char buf[257],dbuf[260];
	char owner[256];
	long ttl;
	dns_cent_t cent;

	THREAD_SIGINIT;
	/* (void)p; */  /* To inhibit "unused variable" warning */

	if (!global.strict_suid) {
		if (!run_as(global.run_as)) {
			log_error("Could not change user and group id to those of run_as user %s",global.run_as);
			pdnsd_exit();
		}
	}

	uname(&nm);
	if (listen(stat_sock,5)==-1) {
		log_warn("Error: could not listen on socket: %s.\nStatus readback will be impossible",strerror(errno));
		stat_pipe=0;
		close(stat_sock);
		return NULL;
	}
	for(;;) {
		res=sizeof(ra);
		if ((rs=accept(stat_sock,(struct sockaddr *)&ra,&res))!=-1) {
			DEBUG_MSG("Status socket query pending.\n");
			if (read_short(rs,&cmd)) {
			    switch(cmd) {
			    case CTL_STATS:
				    DEBUG_MSG("Received STATUS query.\n");
				    fsprintf(rs,"pdnsd-%s running on %s.\n",VERSION,nm.nodename);
				    report_cache_stat(rs);
				    report_conf_stat(rs);
				    break;
			    case CTL_SERVER:
			    {
				    char *endptr;
				    int indx,dns_spec;
				    DEBUG_MSG("Received SERVER command.\n");
				    if (read_string(rs,buf,sizeof(buf))<=0) {
					    print_serr(rs,"Bad server label.");
					    break;
				    }
				    if (!read_short(rs,&cmd2)) {
					    print_serr(rs,"Missing up|down|retest.");
					    break;
				    }
				    if(!(dns_spec=read_string(rs, dbuf, sizeof(dbuf)))) {
					    print_serr(rs,"Missing DNS addresses.");
					    break;
				    }
				    indx=strtol(buf,&endptr,0);
				    if(!*endptr) {
					    if (indx<0 || indx>=DA_NEL(servers)) {
						    print_serr(rs,"Server index out of range.");
						    break;
					    }
				    }
				    else {
					    if (!strcmp(buf, "all"))
						    indx=-2; /* all servers */
					    else
						    indx=-1; /* compare names */
				    }
				    switch (cmd2) {
				    case CTL_S_UP:
				    case CTL_S_DOWN:
				    case CTL_S_RETEST:
				        if(dns_spec<0) {
					    if (indx<0) {
						    int found_label=0;
						    for (i=0;i<DA_NEL(servers);++i) {
						      if (indx==-2 || !strcmp(DA_INDEX(servers,i).label,buf)) {
							found_label=1;
							if(cmd2==CTL_S_RETEST)
							  perform_uptest(i,-1);
							else
							  mark_server(i,-1,cmd2==CTL_S_UP);
						      }
						    }
						    if(found_label) print_succ(rs);
						    else print_serr(rs,"Bad server label.");
					    } else {
					      if(cmd2==CTL_S_RETEST)
						perform_uptest(indx,-1);
					      else
						mark_server(indx,-1,cmd2==CTL_S_UP);
					      print_succ(rs);
					    }
					}
					else { /* Change server addresses */
					    if(indx==-2) {
					      print_serr(rs,"Can't use label \"all\" to change server addresses.");
					      break;
					    }
					    if(indx==-1) {
					      for(i=0;i<DA_NEL(servers);++i) {
						if (!strcmp(DA_INDEX(servers,i).label,buf)) {
						  if(indx!=-1) {
						    print_serr(rs,"server label must be unique to change server addresses.");
						    goto switch_break;
						  }
						  indx=i;
						}
					      }
					      if(indx==-1) {
						print_serr(rs,"Bad server label.");
						break;
					      }
					    }
					    {
					      unsigned char *ipstr,*q=dbuf;
					      addr_array ar=NULL;
					      pdnsd_a addr;
					      for(;;) {
						for(;;) {
						  if(!*q) goto change_servs;
						  if(*q!=',' && !isspace(*q)) break;
						  ++q;
						}
						ipstr=q;
						for(;;) {
						  ++q;
						  if(!*q) break;
						  if(*q==',' || isspace(*q)) {*q++=0; break; }
						}
						if(!str2pdnsd_a(ipstr,&addr)) {
						  print_serr(rs,"Bad server ip");
						  goto free_ar;
						}
						if(!(ar=DA_GROW1(ar))) {
						  goto out_of_memory;
						}
						DA_LAST(ar)=addr;
					      }
					    change_servs:
					      if(change_servers(indx,ar,cmd2))
						print_succ(rs);
					      else
						print_serr(rs,"Timed out while trying to gain access to server data.");
					    free_ar:
					      da_free(ar);
					    }
					}
					break;
				    default:
				        goto bad_command;
				    }
			    }
			    switch_break:
				    break;
			    case CTL_RECORD:
				    DEBUG_MSG("Received RECORD command.\n");
				    if (!read_short(rs,&cmd))
					    goto incomplete_command;
				    if (!read_domain(rs, buf, sizeof(buf)))
					    goto incomplete_command;
				    switch (cmd) {
				    case CTL_R_DELETE:
					    del_cache(buf);
					    print_succ(rs);
					    break;
				    case CTL_R_INVAL:
					    invalidate_record(buf);
					    print_succ(rs);
					    break;
				    default:
					    goto bad_command;
				    }
				    break;
			    case CTL_SOURCE:
			    {
				    char fn[1025];

				    DEBUG_MSG("Received SOURCE command.\n");
				    if (read_string(rs,fn,1024)<=0) {
					    print_serr(rs,"Bad filename name.");
					    break;
				    }
				    if (!read_domain(rs, buf, sizeof(buf)))
					    goto incomplete_command;
				    if (!read_long(rs,&ttl))
					    goto incomplete_command;
				    if (!read_short(rs,&cmd))	/* serve aliases */
					    goto incomplete_command;
				    if (!read_short(rs,&cmd2))	/* caching flags */
					    goto incomplete_command;
				    if (!str2rhn(buf,owner))
					    goto bad_domain_name;
				    if (ttl < 0)
					    goto bad_ttl;
				    {
				      char *errstr;
				      if (read_hosts(fn,owner,ttl,cmd2, cmd,&errstr))
					print_succ(rs);
				      else {
					print_serr(rs,errstr?:"Out of memory.");
					if(errstr) free(errstr);
				      }
				    }
			    }
				    break;
			    case CTL_ADD:
			    {
				    int sz;
				    DEBUG_MSG("Received ADD command.\n");
				    if (!read_short(rs,&cmd))
					    goto incomplete_command;
				    if (!read_domain(rs, buf, sizeof(buf)))
					    goto incomplete_command;
				    if (!read_long(rs,&ttl))
					    goto incomplete_command;
				    if (!read_short(rs,&cmd2))	/* caching flags */
					    goto incomplete_command;
				    if (!str2rhn(buf,owner))
					    goto bad_domain_name;
				    if (ttl < 0)
					    goto bad_ttl;

				    switch (cmd) {
				    case T_A:
					    if (read(rs,dbuf,sizeof(struct in_addr))!=sizeof(struct in_addr))
						    goto bad_arg;
					    sz=sizeof(struct in_addr);
					    break;
#ifdef ENABLE_IPV6
				    case T_AAAA:
					    if (read(rs,dbuf,sizeof(struct in6_addr))!=sizeof(struct in6_addr))
						    goto bad_arg;
					    sz=sizeof(struct in6_addr);
					    break;
#endif
				    case T_CNAME:
				    case T_PTR:
					    if (!read_domain(rs, owner, sizeof(owner)))
						    goto incomplete_command;
					    if (!str2rhn(owner,dbuf))
						    goto bad_domain_name;
					    sz=rhnlen(dbuf);
					    break;
				    case T_MX:
					    if (read(rs,dbuf,sizeof(short))!=sizeof(short))
						    goto bad_arg;
					    if (!read_domain(rs, owner, sizeof(owner)))
						    goto incomplete_command;
					    if (!str2rhn(owner,dbuf+2))
						    goto bad_domain_name;
					    sz=rhnlen(dbuf+2)+2;
					    break;
				    default:
					    goto bad_arg;
				    }

				    if (!init_cent(&cent, buf, cmd2, time(NULL), 0  DBG1))
					    goto out_of_memory;
				    if (!add_cent_rr(&cent,ttl,0,CF_LOCAL,sz,dbuf,cmd  DBG1))
					    goto out_of_memory;
				    add_cache(&cent);
				    free_cent(&cent  DBG1);
				    print_succ(rs);
			    }
				    break;
			    case CTL_NEG:
				    DEBUG_MSG("Received NEG command.\n");
				    if (!read_domain(rs, buf, sizeof(buf)))
					    goto incomplete_command;
				    if (!read_short(rs,&cmd))
					    goto incomplete_command;
				    if (!read_long(rs,&ttl))
					    goto incomplete_command;
				    if (!str2rhn(buf,owner)) {
					    DEBUG_MSG("NEG: received bad domain name.\n");
					    goto bad_domain_name;
				    }
				    if (cmd!=255 && (cmd<T_MIN || cmd>T_MAX)) {
					    DEBUG_MSG("NEG: received bad record type.\n");
					    print_serr(rs,"Bad record type.");
					    break;
				    }
				    if (ttl < 0)
					    goto bad_ttl;
				    if (cmd==255) {
					    if (!init_cent(&cent, buf, DF_LOCAL|DF_NEGATIVE, time(NULL), ttl  DBG1))
						    goto out_of_memory;
				    } else {
					    if (!init_cent(&cent, buf, 0, time(NULL), 0  DBG1))
						    goto out_of_memory;
					    if (!add_cent_rrset(&cent,cmd,ttl,0,CF_LOCAL|CF_NEGATIVE,0  DBG1)) {
						    free_cent(&cent  DBG1);
						    goto out_of_memory;
					    }
				    }
				    add_cache(&cent);
				    free_cent(&cent DBG1);
				    print_succ(rs);
				    break;
			    incomplete_command:
				    print_serr(rs,"Malformed or incomplete command.");
				    break;
			    bad_command:
				    print_serr(rs,"Bad command.");
				    break;
			    bad_arg:
				    print_serr(rs,"Bad arg.");
				    break;
			    bad_domain_name:
				    print_serr(rs,"Bad domain name.");
				    break;
			    bad_ttl:
				    print_serr(rs, "Bad TTL");
				    break;
			    out_of_memory:
				    print_serr(rs,"Out of memory.");
				    break;
			    default:
				    print_serr(rs,"Unknown command.");
			    }
			}
			else {
				DEBUG_MSG("short status socket query");
			}
			close(rs);
			usleep_r(100000); /* sleep some time. I do not want the query frequency to be too high. */
		} else {
			if (errno!=EINTR)
				log_warn("Failed to open socket: %s. Status readback will be impossible",strerror(errno));
			break;
		}
	}
	return NULL;
}

/*
 * Initialize the status socket
 */
void init_stat_sock()
{
	struct sockaddr_un *sa;
	int sa_size = (offsetof(struct sockaddr_un, sun_path) + sizeof("/pdnsd.status") + strlen(global.cache_dir));

	sa=(struct sockaddr_un *)alloca(sa_size);
	stpcpy(stpcpy(sa->sun_path,global.cache_dir),"/pdnsd.status");

	if (unlink(sa->sun_path)!=0 && errno!=ENOENT) { /* Delete the socket */
		log_warn("Failed to unlink %s: %s.\nStatus readback will be disabled",sa->sun_path, strerror(errno));
		stat_pipe=0;
		return;
	}
	if ((stat_sock=socket(PF_UNIX,SOCK_STREAM,0))==-1) {
		log_warn("Failed to open socket: %s. Status readback will be impossible",strerror(errno));
		stat_pipe=0;
		return;
	}
	sa->sun_family=AF_UNIX;
#ifdef BSD44_SOCKA
	sa->sun_len=SUN_LEN(sa);
#endif
	/* Early initialization, so that umask can be used race-free. */
	{
	  mode_t old_mask = umask((S_IRWXU|S_IRWXG|S_IRWXO)&(~global.ctl_perms));
	  if (bind(stat_sock,(struct sockaddr *)sa,sa_size)==-1) {
	    log_warn("Error: could not bind socket: %s.\nStatus readback will be impossible",strerror(errno));
	    close(stat_sock);
	    stat_pipe=0;
	  }
	  umask(old_mask);
	}

	if(stat_pipe) sock_path= strdup(sa->sun_path);
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

	pthread_attr_destroy(&attr);
}
