/* conff.c - Maintain configuration information

   Copyright (C) 2000, 2001 Thomas Moestl
   Copyright (C) 2002, 2003, 2004, 2005, 2006 Paul A. Rombouts

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
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include "ipvers.h"
#include "conff.h"
#include "consts.h"
#include "helpers.h"
#include "conf-parser.h"
#include "servers.h"
#include "icmp.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: conff.c,v 1.26 2001/07/02 18:55:27 tmm Exp $";
#endif

globparm_t global={
  perm_cache:        2048,
  cache_dir:         NULL,
  pidfile:           NULL,
  port:              53,
#ifdef ENABLE_IPV4
  a:                 {{INADDR_ANY}},
#else
  a:                 {IN6ADDR_ANY_INIT},
#endif
#ifdef ENABLE_IPV6
  ipv4_6_prefix:     IN6ADDR_ANY_INIT,
#endif
  max_ttl:           604800,
  min_ttl:           120,
  neg_ttl:           900,
  neg_rrs_pol:       C_AUTH,
  neg_domain_pol:    C_AUTH,
  verbosity:         VERBOSITY,
  run_as:            "",
  daemon:            0,
  debug:             0,
  stat_pipe:         0,
  notcp:             0,
  strict_suid:       1,
  use_nss:           1,
  paranoid:          0,
  lndown_kluge:      0,
  onquery:           0,
  rnd_recs:          1,
  ctl_perms:         0600,
  scheme_file:       NULL,
  proc_limit:        40,
  procq_limit:       60,
  tcp_qtimeout:      TCP_TIMEOUT,
  timeout:           0,
  par_queries:       PAR_QUERIES,
  query_method:      M_PRESET,
  query_port_start:  0,
  query_port_end:    65535,
  deleg_only_zones:  NULL
};

servparm_t serv_presets={
  port:          53,
  uptest:        C_NONE,
  timeout:       120,
  interval:      900,
  ping_timeout:  600,
  scheme:        "",
  uptest_cmd:    NULL,
  uptest_usr:    "",
  interface:     "",
  device:        "",
  label:         NULL,
  purge_cache:   0,
  nocache:       0,
  lean_query:    1,
  is_proxy:      0,
  rootserver:    0,
  preset:        1,
  policy:        C_INCLUDED,
  alist:         NULL,
  atup_a:        NULL,
#ifdef ENABLE_IPV4
  ping_a:        {{INADDR_ANY}}
#else
  ping_a:        {IN6ADDR_ANY_INIT}
#endif
};

servparm_array servers=NULL;

static void free_zones(zone_array za);
static void free_server_data(servparm_array sa);
static int report_server_stat(int f,int i);


/*
 * Read a configuration file and save the result.
 * Return 1 on success, 0 on failure.
 * In case of failure, **errstr will refer to a newly allocated string containing an error message.
 * If we are multi-threaded, call with locks applied.
 */
int read_config_file(const char *nm, globparm_t *global, servparm_array *servers, char **errstr)
{
	int retval=0,fd;
	FILE *in;
	struct stat sb;

	if (nm==NULL)
		nm=conf_file;

	if (!(in=fopen(nm,"r"))) {
		if(asprintf(errstr,"Error: Could not open config file %s: %s",nm,strerror(errno))<0)
			*errstr=NULL;
		return 0;
	}
	fd=fileno(in);
	/* Note by Paul Rombouts: I am using fstat() instead of stat() here to
	   prevent a possible exploitable race condition */
	if (fd==-1 || fstat(fd,&sb)!=0) {
		if(asprintf(errstr, "Error: Could not stat config file %s: %s",nm,strerror(errno))<0)
			*errstr=NULL;
	}
	else if (sb.st_uid!=init_uid) {
		/* Note by Paul Rombouts:
		   Perhaps we should use getpwuid_r() instead of getpwuid(), which is not necessarily thread safe.
		   As long as getpwuid() is only used by only one thread, it should be OK,
		   but it is something to keep in mind.
		*/		   
		struct passwd *pws;
		char owner[24],user[24];
		if((pws=getpwuid(sb.st_uid)))
			strncp(owner,pws->pw_name,sizeof(owner));
		else
			sprintf(owner,"%i",sb.st_uid);
		if((pws=getpwuid(init_uid)))
			strncp(user,pws->pw_name,sizeof(user));
		else
			sprintf(user,"%i",init_uid);
		if(asprintf(errstr,
			    "Error: Config file %s is owned by '%s', but pdnsd was started as user '%s'.",
			    nm,owner,user)<0)
			*errstr=NULL;
	}
	else if ((sb.st_mode&(S_IWGRP|S_IWOTH))) {
		if(asprintf(errstr,
			    "Error: Bad config file permissions: file %s must be only writeable by the user.",nm)<0)
			*errstr=NULL;
	}
	else
		retval=confparse(in,global,servers,errstr);

	if(fclose(in) && retval) {
		if(asprintf(errstr,"Error: Could not close config file %s: %s",nm,strerror(errno))<0)
			*errstr=NULL;
		return 0;
	}
	return retval;
}

/*
 * Re-Read the configuration file.
 * Return 1 on success, 0 on failure.
 * In case of failure, the old configuration will be unchanged (although the cache may not) and
 * **errstr will refer to a newly allocated string containing an error message.
 */
int reload_config_file(const char *nm, char **errstr)
{
	globparm_t global_new;
	servparm_array servers_new;

	global_new=global;
	global_new.cache_dir=NULL;
	global_new.pidfile=NULL;
	global_new.scheme_file=NULL;
	global_new.deleg_only_zones=NULL;
	global_new.onquery=0;
	servers_new=NULL;
	if(read_config_file(nm,&global_new,&servers_new,errstr)) {
		if(global_new.cache_dir && strcmp(global_new.cache_dir,global.cache_dir)) {
			*errstr=strdup("Cannot reload config file: the specified cache_dir directory has changed.\n"
				       "Try restarting pdnsd instead.");
			goto cleanup_return;
		}
		if(global_new.pidfile && (!global.pidfile || strcmp(global_new.pidfile,global.pidfile))) {
			*errstr=strdup("Cannot reload config file: the specified pid_file has changed.\n"
				       "Try restarting pdnsd instead.");
			goto cleanup_return;
		}
		if(global_new.scheme_file && strcmp(global_new.scheme_file,global.scheme_file)) {
			*errstr=strdup("Cannot reload config file: the specified scheme_file has changed.\n"
				       "Try restarting pdnsd instead.");
			goto cleanup_return;
		}
		if(global_new.port!=global.port) {
			*errstr=strdup("Cannot reload config file: the specified server_port has changed.\n"
				       "Try restarting pdnsd instead.");
			goto cleanup_return;
		}
		if(!ADDR_EQUIV(&global_new.a,&global.a)) {
			*errstr=strdup("Cannot reload config file: the specified interface address (server_ip) has changed.\n"
				       "Try restarting pdnsd instead.");
			goto cleanup_return;
		}
#ifdef ENABLE_IPV6
		if(!IN6_ARE_ADDR_EQUAL(&global_new.ipv4_6_prefix,&global.ipv4_6_prefix)) {
			*errstr=strdup("Cannot reload config file: the specified ipv4_6_prefix has changed.\n"
				       "Try restarting pdnsd instead.");
			goto cleanup_return;
		}
#endif
		if(strcmp(global_new.run_as,global.run_as)) {
			*errstr=strdup("Cannot reload config file: the specified run_as id has changed.\n"
				       "Try restarting pdnsd instead.");
			goto cleanup_return;
		}
		if(global_new.daemon!=global.daemon) {
			*errstr=strdup("Cannot reload config file: the daemon option has changed.\n"
				       "Try restarting pdnsd instead.");
			goto cleanup_return;
		}
		if(global_new.debug!=global.debug) {
			*errstr=strdup("Cannot reload config file: the debug option has changed.\n"
				       "Try restarting pdnsd instead.");
			goto cleanup_return;
		}
		if(global_new.stat_pipe!=global.stat_pipe) {
			*errstr=strdup("Cannot reload config file: the status_ctl option has changed.\n"
				       "Try restarting pdnsd instead.");
			goto cleanup_return;
		}
		if(global_new.notcp!=global.notcp) {
			*errstr=strdup("Cannot reload config file: the tcp_server option has changed.\n"
				       "Try restarting pdnsd instead.");
			goto cleanup_return;
		}
		if(global_new.strict_suid!=global.strict_suid) {
			*errstr=strdup("Cannot reload config file: the strict_setuid option has changed.\n"
				       "Try restarting pdnsd instead.");
			goto cleanup_return;
		}
		if(global_new.ctl_perms!=global.ctl_perms) {
			*errstr=strdup("Cannot reload config file: the specified ctl_perms has changed.\n"
				       "Try restarting pdnsd instead.");
			goto cleanup_return;
		}
		if(ping_isocket==-1
#ifdef ENABLE_IPV6
		   && ping6_isocket==-1
#endif
		  ) {
			int i,n=DA_NEL(servers_new);
			for (i=0;i<n;++i) {
				if (DA_INDEX(servers_new,i).uptest==C_PING) {
					if(asprintf(errstr,"Cannot reload config file: the ping socket is not initialized"
						    " and the new config contains uptest=ping in server section %i.\n"
						    "Try restarting pdnsd instead.",i)<0)
						*errstr=NULL;
					goto cleanup_return;
				}
			}
		}

		/* we need exclusive access to the server data to make the changes */
		/* Wait at most 60 seconds to obtain a lock. */
		if(!exclusive_lock_server_data(60)) {
			*errstr=strdup("Cannot reload config file: Timed out while waiting for access to config data.");
			goto cleanup_return;
		}
		free(global_new.cache_dir); global_new.cache_dir=global.cache_dir;
		free(global_new.pidfile); global_new.pidfile=global.pidfile;
		free(global_new.scheme_file); global_new.scheme_file=global.scheme_file;
		free_zones(global.deleg_only_zones);
		global=global_new;

		free_server_data(servers);
		servers=servers_new;
		/* schedule a retest to check which servers are up,
		   and free the lock. */
		exclusive_unlock_server_data(1);

		return 1;
	}

 cleanup_return:
	free(global_new.cache_dir);
	free(global_new.pidfile);
	free(global_new.scheme_file);
	free_zones(global_new.deleg_only_zones);
	free_server_data(servers_new);
	return 0;
}

void free_zone(void *ptr)
{
  free(*((unsigned char **)ptr));
}

static void free_zones(zone_array za)
{
	int i,n=DA_NEL(za);
	for(i=0;i<n;++i)
		free(DA_INDEX(za,i));

	da_free(za);
}

void free_slist_domain(void *ptr)
{
	free(((slist_t *)ptr)->domain);
}

void free_slist_array(slist_array sla)
{
	int j,m=DA_NEL(sla);
	for(j=0;j<m;++j)
		free(DA_INDEX(sla,j).domain);
	da_free(sla);

}

void free_servparm(servparm_t *serv)
{
	free(serv->uptest_cmd);
	free(serv->label);
	da_free(serv->atup_a);
	free_slist_array(serv->alist);
}

static void free_server_data(servparm_array sa)
{
	int i,n=DA_NEL(sa);
	for(i=0;i<n;++i)
		free_servparm(&DA_INDEX(sa,i));
	da_free(sa);
}

/* Report the current configuration to the file descriptor f (for the status fifo, see status.c) */
int report_conf_stat(int f)
{
	int i,retval=0;
	
	fsprintf_or_return(f,"\nConfiguration:\n==============\nGlobal:\n-------\n");
	fsprintf_or_return(f,"\tCache size: %li kB\n",global.perm_cache);
	fsprintf_or_return(f,"\tServer directory: %s\n",global.cache_dir);
	fsprintf_or_return(f,"\tScheme file (for Linux pcmcia support): %s\n",global.scheme_file);
	fsprintf_or_return(f,"\tServer port: %i\n",global.port);
	{
	  char buf[ADDRSTR_MAXLEN];
	  fsprintf_or_return(f,"\tServer ip (%s=any available one): %s\n",run_ipv4?"0.0.0.0":"::",pdnsd_a2str(&global.a,buf,ADDRSTR_MAXLEN));
	}
#ifdef ENABLE_IPV6
	if(!run_ipv4) {
	  char buf[ADDRSTR_MAXLEN];
	  fsprintf_or_return(f,"\tIPv4 to IPv6 prefix: %s\n",inet_ntop(AF_INET6,&global.ipv4_6_prefix,buf,ADDRSTR_MAXLEN)?:"?.?.?.?");
	}
#endif
	fsprintf_or_return(f,"\tIgnore cache when link is down: %s\n",global.lndown_kluge?"on":"off");
	fsprintf_or_return(f,"\tMaximum ttl: %li\n",(long)global.max_ttl);
	fsprintf_or_return(f,"\tMinimum ttl: %li\n",(long)global.min_ttl);
	fsprintf_or_return(f,"\tNegative ttl: %li\n",(long)global.neg_ttl);
	fsprintf_or_return(f,"\tNegative RRS policy: %s\n",const_name(global.neg_rrs_pol));
	fsprintf_or_return(f,"\tNegative domain policy: %s\n",const_name(global.neg_domain_pol));
	fsprintf_or_return(f,"\tRun as: %s\n",global.run_as);
	fsprintf_or_return(f,"\tStrict run as: %s\n",global.strict_suid?"on":"off");
	fsprintf_or_return(f,"\tUse NSS: %s\n",global.use_nss?"on":"off");
	fsprintf_or_return(f,"\tParanoid mode (cache pollution prevention): %s\n",global.paranoid?"on":"off");
	fsprintf_or_return(f,"\tControl socket permissions (mode): %o\n",global.ctl_perms);
	fsprintf_or_return(f,"\tMaximum parallel queries served: %i\n",global.proc_limit);
	fsprintf_or_return(f,"\tMaximum queries queued for serving: %i\n",global.procq_limit);
	fsprintf_or_return(f,"\tGlobal timeout setting: %li\n",(long)global.timeout);
	fsprintf_or_return(f,"\tParallel queries increment: %i\n",global.par_queries);
	fsprintf_or_return(f,"\tRandomize records in answer: %s\n",global.rnd_recs?"on":"off");
	fsprintf_or_return(f,"\tQuery method: %s\n",const_name(global.query_method));
	fsprintf_or_return(f,"\tQuery port start: %i\n",global.query_port_start);
	fsprintf_or_return(f,"\tQuery port end: %i\n",global.query_port_end);
#ifndef NO_TCP_SERVER
	fsprintf_or_return(f,"\tTCP server thread: %s\n",global.notcp?"off":"on");
	if(!global.notcp)
	  {fsprintf_or_return(f,"\tTCP query timeout: %li\n",(long)global.tcp_qtimeout);}
#endif

	lock_server_data();
	{
		int rv=fsprintf(f,"\tDelegation-only zones: ");
		if(rv<0) {retval=rv; goto unlock_return;}
	}
	if(global.deleg_only_zones==NULL) {
		int rv=fsprintf(f,"(none)\n");
		if(rv<0) {retval=rv; goto unlock_return;}
	}
	else {
		int rv;
		for(i=0;i<DA_NEL(global.deleg_only_zones);++i) {
			unsigned char buf[256];
			rv=fsprintf(f,i==0?"%s":", %s",
					rhn2str(DA_INDEX(global.deleg_only_zones,i),buf,sizeof(buf)));
			if(rv<0) {retval=rv; goto unlock_return;}
		}
		rv=fsprintf(f,"\n");
		if(rv<0) {retval=rv; goto unlock_return;}
	}

	for(i=0;i<DA_NEL(servers);i++) {
		int rv=report_server_stat(f,i);
		if(rv<0) {retval=rv; goto unlock_return;}
	}
 unlock_return:
	unlock_server_data();

	return retval;
}

/* Report the current status of server i to the file descriptor f.
   Call with locks applied.
*/
static int report_server_stat(int f,int i)
{
	servparm_t *st=&DA_INDEX(servers,i);
	int j;

	fsprintf_or_return(f,"Server %i:\n------\n",i);
	fsprintf_or_return(f,"\tlabel: %s\n",st->label?st->label:"(none)");
	for(j=0;j<DA_NEL(st->atup_a);j++) {
		atup_t *at=&DA_INDEX(st->atup_a,j);
		{char buf[ADDRSTR_MAXLEN];
		 fsprintf_or_return(f,"\tip: %s\n",pdnsd_a2str(&at->a,buf,ADDRSTR_MAXLEN));}
		fsprintf_or_return(f,"\tserver assumed available: %s\n",at->is_up?"yes":"no");
	}		  
	fsprintf_or_return(f,"\tport: %hu\n",st->port);
	fsprintf_or_return(f,"\tuptest: %s\n",const_name(st->uptest));
	fsprintf_or_return(f,"\ttimeout: %li\n",(long)st->timeout);
	if(st->interval>0) {
		fsprintf_or_return(f,"\tuptest interval: %li\n",(long)st->interval);
	} else {
		fsprintf_or_return(f,"\tuptest interval: %s\n",
				   st->interval==-1?"onquery":
				   st->interval==-2?"ontimeout":
				                    "(never retest)");
	}
	fsprintf_or_return(f,"\tping timeout: %li\n",(long)st->ping_timeout);
	{char buf[ADDRSTR_MAXLEN];
	 fsprintf_or_return(f,"\tping ip: %s\n",is_inaddr_any(&st->ping_a)?"(using server ip)":pdnsd_a2str(&st->ping_a,buf,ADDRSTR_MAXLEN));}
	fsprintf_or_return(f,"\tinterface: %s\n",st->interface);
	fsprintf_or_return(f,"\tdevice (for special Linux ppp device support): %s\n",st->device);
	fsprintf_or_return(f,"\tuptest command: %s\n",st->uptest_cmd?:"");
	fsprintf_or_return(f,"\tuptest user: %s\n",st->uptest_usr[0]?st->uptest_usr:"(process owner)");
	if (st->scheme[0]!='\0') {
		fsprintf_or_return(f,"\tscheme: %s\n", st->scheme);
	}
	fsprintf_or_return(f,"\tforce cache purging: %s\n",st->purge_cache?"on":"off");
	fsprintf_or_return(f,"\tserver is cached: %s\n",st->nocache?"off":"on");
	fsprintf_or_return(f,"\tlean query: %s\n",st->lean_query?"on":"off");
	fsprintf_or_return(f,"\tUse only proxy?: %s\n",st->is_proxy?"on":"off");
	fsprintf_or_return(f,"\tAssumed root server: %s\n",st->rootserver?"yes":"no");
	fsprintf_or_return(f,"\tDefault policy: %s\n",const_name(st->policy));
	fsprintf_or_return(f,"\tPolicies:\n");
	if (st->alist==NULL) {
		fsprintf_or_return(f,"\t\t(none)\n");
	} else {
		for (j=0;j<DA_NEL(st->alist);j++) {
			slist_t *sl=&DA_INDEX(st->alist,j);
			unsigned char buf[256];
			fsprintf_or_return(f,"\t\t%s: %s%s\n",
					   sl->rule==C_INCLUDED?"include":"exclude",
					   sl->exact?"":".",
					   rhn2str(sl->domain,buf,sizeof(buf)));
		}
	}
	return 0;
}
