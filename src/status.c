/* status.c - Allow control of a running server using a socket
   Copyright (C) 2000, 2001 Thomas Moestl

   With modifications by Paul Rombouts, 2002, 2003, 2004.

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
	if(write(rs,&cmd,sizeof(cmd))!=sizeof(cmd) ||
	   write_all(rs,msg,strlen(msg))<0)
	{
		DEBUG_MSG("Error writing to control socket: %s\n"
			  "Failed to send error message '%s'\n",strerror(errno),msg);
	}
}

/* Print a success code to the socket */
static void print_succ(int rs)
{
	short cmd;

	cmd=htons(0);
	if(write(rs,&cmd,sizeof(cmd))!=sizeof(cmd)) {
		DEBUG_MSG("Error writing to control socket: %s\n"
			  "Failed to send success code.\n",strerror(errno));
	}
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
   A buffer of the right size is allocated to hold the result.
   A return value of 1 means success (if the result is undefined then *res is set to NULL),
   0 means read or allocation error.
*/
static int read_allocstring(int fh, char **res)
{
	unsigned short count;
	char *buf;
	int nread=0;

	if(!read_short(fh,&count)) return 0;
	if(count==(unsigned short)(~0)) {*res=NULL; return 1;}
	if(!(buf=malloc(count+1))) return 0;
	while(nread<count) {
		int m=read(fh,buf+nread,count-nread);
		if(m<=0) {free(buf); return 0;}
		nread+=m;
	}
	buf[count]=0;
	*res=buf;
	return 1;
}

/* Read a string preceded by a char count.
   Place it in a buffer of size buflen and terminate by a dot (if it is missing)
   and a null char.
   A return value of 1 means success, 0 means error (read error,
   buffer too small or result undefined).
*/
static int read_domain(int fh, char *buf, int buflen)
{
	unsigned short count;
	int nread=0;

	/* PDNSD_ASSERT(buflen>0, "bad read_domain call"); */
	if(!read_short(fh,&count)) return 0;
	if(count==(unsigned short)(~0)) return 0;
	if(count >=buflen) return 0;
	while(nread<count) {
		int m=read(fh,buf+nread,count-nread);
		if(m<=0) return 0;
		nread+=m;
	}
	buf[count]=0;
	if(count==0 || buf[count-1]!='.') {
		if(count+1>=buflen) return 0;
		buf[count]='.'; buf[count+1]=0;
	}
	return 1;
}

static void *status_thread (void *p)
{
	THREAD_SIGINIT;
	/* (void)p; */  /* To inhibit "unused variable" warning */

	if (!global.strict_suid) {
		if (!run_as(global.run_as)) {
			log_error("Could not change user and group id to those of run_as user %s",global.run_as);
			pdnsd_exit();
		}
	}

	if (listen(stat_sock,5)==-1) {
		log_warn("Error: could not listen on socket: %s.\nStatus readback will be impossible",strerror(errno));
		stat_pipe=0;
		close(stat_sock);
		return NULL;
	}
	for(;;) {
		struct sockaddr_un ra;
		socklen_t res=sizeof(ra);
		int rs;
		if ((rs=accept(stat_sock,(struct sockaddr *)&ra,&res))!=-1) {
			short cmd;
			DEBUG_MSG("Status socket query pending.\n");
			if (read_short(rs,&cmd)) {
			    char *errmsg;
			    switch(cmd) {
			    case CTL_STATS: {
				    struct utsname nm;
				    DEBUG_MSG("Received STATUS query.\n");
				    uname(&nm);
				    if(fsprintf(rs,"pdnsd-%s running on %s.\n",VERSION,nm.nodename)<0 ||
				       report_cache_stat(rs)<0 ||
				       report_conf_stat(rs)<0)
				    {
					    DEBUG_MSG("Error writing to control socket: %s\n"
						      "Failed to send status report.\n",strerror(errno));
				    }					    
			    }
				    break;
			    case CTL_SERVER: {
				    char *label,*dnsaddr;
				    int indx;
				    short cmd2;
				    DEBUG_MSG("Received SERVER command.\n");
				    if (!read_allocstring(rs,&label) || !label) {
					print_serr(rs,"Error reading server label.");
					break;
				    }
				    if (!read_short(rs,&cmd2)) {
					print_serr(rs,"Missing up|down|retest.");
					goto free_label_break;
				    }
				    if(!read_allocstring(rs, &dnsaddr)) {
					print_serr(rs,"Error reading DNS addresses.");
					goto free_label_break;
				    }
				    {
					char *endptr;
					indx=strtol(label,&endptr,0);
					if(!*endptr) {
					    if (indx<0 || indx>=DA_NEL(servers)) {
						print_serr(rs,"Server index out of range.");
						goto free_dnsaddr_label_break;
					    }
					}
					else {
					    if (!strcmp(label, "all"))
						indx=-2; /* all servers */
					    else
						indx=-1; /* compare names */
					}
				    }
				    if(cmd2==CTL_S_UP || cmd2==CTL_S_DOWN || cmd2==CTL_S_RETEST) {
					if(!dnsaddr) {
					    if (indx<0) {
						int i,found_label=0;
						for (i=0;i<DA_NEL(servers);++i) {
						    char *servlabel;
						    if (indx==-2 ||
							((servlabel=DA_INDEX(servers,i).label) && !strcmp(servlabel,label)))
						    {
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
						goto free_dnsaddr_label_break;
					    }
					    if(indx==-1) {
						int i;
						for(i=0;i<DA_NEL(servers);++i) {
						    char *servlabel;
						    if ((servlabel=DA_INDEX(servers,i).label) && !strcmp(servlabel,label)) {
							if(indx!=-1) {
							    print_serr(rs,"server label must be unique to change server addresses.");
							    goto free_dnsaddr_label_break;
							}
							indx=i;
						    }
						}
						if(indx==-1) {
						    print_serr(rs,"Bad server label.");
						    goto free_dnsaddr_label_break;
						}
					    }
					    {
						unsigned char *ipstr,*q=dnsaddr;
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
							print_serr(rs,"Out of memory.");
							goto free_dnsaddr_label_break;
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
				    }
				    else
					print_serr(rs,"Bad command.");

			    free_dnsaddr_label_break:
				    free(dnsaddr);
			    free_label_break:
				    free(label);
			    }
				    break;
			    case CTL_RECORD: {
				    short cmd2;
				    char name[256];
				    DEBUG_MSG("Received RECORD command.\n");
				    if (!read_short(rs,&cmd2))
					    goto incomplete_command;
				    if (!read_domain(rs, name, sizeof(name)))
					    goto incomplete_command;
				    switch (cmd2) {
				    case CTL_R_DELETE:
					    del_cache(name);
					    print_succ(rs);
					    break;
				    case CTL_R_INVAL:
					    invalidate_record(name);
					    print_succ(rs);
					    break;
				    default:
					    print_serr(rs,"Bad command.");
				    }
			    }
				    break;
			    case CTL_SOURCE: {
				    long ttl;
				    char *fn;
				    short servaliases,flags;
				    char buf[256],owner[256];

				    DEBUG_MSG("Received SOURCE command.\n");
				    if (!read_allocstring(rs,&fn) || !fn) {
					    print_serr(rs,"Bad filename name.");
					    break;
				    }
				    if (!read_domain(rs, buf, sizeof(buf)) ||
					!read_long(rs,&ttl) ||
					!read_short(rs,&servaliases) ||	/* serve aliases */
					!read_short(rs,&flags))		/* caching flags */
				    {
					    print_serr(rs,"Malformed or incomplete command.");
					    goto free_fn;
				    }
				    if ((errmsg=parsestr2rhn(buf,sizeof(buf),owner))!=NULL) {
					    print_serr(rs,errmsg);
					    goto free_fn;
				    }
				    if (ttl < 0) {
					    print_serr(rs, "Bad TTL.");
					    goto free_fn;
				    }
				    if (read_hosts(fn,owner,ttl,flags,servaliases,&errmsg))
					    print_succ(rs);
				    else {
					    print_serr(rs,errmsg?:"Out of memory.");
					    if(errmsg) free(errmsg);
				    }
			    free_fn:
				    free(fn);
			    }
				    break;
			    case CTL_ADD: {
				    long ttl;
				    int sz;
				    short tp,flags;
				    char name[256],buf[256],dbuf[260];

				    DEBUG_MSG("Received ADD command.\n");
				    if (!read_short(rs,&tp))
					    goto incomplete_command;
				    if (!read_domain(rs, name, sizeof(name)))
					    goto incomplete_command;
				    if (!read_long(rs,&ttl))
					    goto incomplete_command;
				    if (!read_short(rs,&flags))	/* caching flags */
					    goto incomplete_command;
				    if ((errmsg=parsestr2rhn(name,sizeof(name),buf))!=NULL)
					    goto bad_domain_name;
				    if (ttl < 0)
					    goto bad_ttl;

				    switch (tp) {
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
					    if (!read_domain(rs, buf, sizeof(buf)))
						    goto incomplete_command;
					    if ((errmsg=parsestr2rhn(buf,sizeof(buf),dbuf))!=NULL)
						    goto bad_domain_name;
					    sz=rhnlen(dbuf);
					    break;
				    case T_MX:
					    if (read(rs,dbuf,sizeof(short))!=sizeof(short))
						    goto bad_arg;
					    if (!read_domain(rs, buf, sizeof(buf)))
						    goto incomplete_command;
					    if ((errmsg=parsestr2rhn(buf,sizeof(buf),dbuf+2))!=NULL)
						    goto bad_domain_name;
					    sz=rhnlen(dbuf+2)+2;
					    break;
				    default:
					    goto bad_arg;
				    }
				    {
					    dns_cent_t cent;

					    if (!init_cent(&cent, name, flags, time(NULL), 0  DBG1))
						    goto out_of_memory;
					    if (!add_cent_rr(&cent,ttl,0,CF_LOCAL,sz,dbuf,tp  DBG1))
						    goto out_of_memory;
					    add_cache(&cent);
					    free_cent(&cent  DBG1);
				    }
				    print_succ(rs);
			    }
				    break;
			    case CTL_NEG: {
				    long ttl;
				    short tp;
				    char name[256],buf[256];

				    DEBUG_MSG("Received NEG command.\n");
				    if (!read_domain(rs, name, sizeof(name)))
					    goto incomplete_command;
				    if (!read_short(rs,&tp))
					    goto incomplete_command;
				    if (!read_long(rs,&ttl))
					    goto incomplete_command;
				    if ((errmsg=parsestr2rhn(name,sizeof(name),buf))!=NULL) {
					    DEBUG_MSG("NEG: received bad domain name.\n");
					    goto bad_domain_name;
				    }
				    if (tp!=255 && (tp<T_MIN || tp>T_MAX)) {
					    DEBUG_MSG("NEG: received bad record type.\n");
					    print_serr(rs,"Bad record type.");
					    break;
				    }
				    if (ttl < 0)
					    goto bad_ttl;
				    {
					    dns_cent_t cent;

					    if (tp==255) {
						    if (!init_cent(&cent, name, DF_LOCAL|DF_NEGATIVE, time(NULL), ttl  DBG1))
							    goto out_of_memory;
					    } else {
						    if (!init_cent(&cent, name, 0, time(NULL), 0  DBG1))
							    goto out_of_memory;
						    if (!add_cent_rrset(&cent,tp,ttl,0,CF_LOCAL|CF_NEGATIVE,0  DBG1)) {
							    free_cent(&cent  DBG1);
							    goto out_of_memory;
						    }
					    }
					    add_cache(&cent);
					    free_cent(&cent DBG1);
				    }
				    print_succ(rs);
			    }
				    break;
			    incomplete_command:
				    print_serr(rs,"Malformed or incomplete command.");
				    break;
			    bad_arg:
				    print_serr(rs,"Bad arg.");
				    break;
			    bad_domain_name:
				    print_serr(rs,errmsg);
				    break;
			    bad_ttl:
				    print_serr(rs, "Bad TTL.");
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
				print_serr(rs,"Command code missing or too short.");
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
	unsigned int sa_size = (offsetof(struct sockaddr_un, sun_path) + sizeof("/pdnsd.status") + strlen(global.cache_dir));

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
int start_stat_sock()
{
	int rv=pthread_create(&st,&attr_detached,status_thread,NULL);
	if (rv)
		log_warn("Failed to start status thread. The status socket will be unuseable");
	else
		log_info(2,"Status thread started.");
	return rv;
}
