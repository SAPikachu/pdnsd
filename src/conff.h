/* conff.h - Definiton for configuration management.

   Copyright (C) 2000, 2001 Thomas Moestl
   Copyright (C) 2002, 2003, 2005 Paul A. Rombouts

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

/* $Id: conff.h,v 1.20 2002/01/29 23:49:47 tmm Exp $ */

#ifndef CONFF_H
#define CONFF_H

/* XXX should use the system defined ones. */
/* #define MAXPATH 1024 */
/* #define MAXIFNAME 31 */

#include <config.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <net/if.h>
#include "ipvers.h"
#include "list.h"

/* From main.c */
extern short int debug_p;
extern short int stat_pipe;
extern pthread_t main_thrid;
extern uid_t init_uid;
extern char *conf_file;

/* ----------- */

typedef DYNAMIC_ARRAY(pdnsd_a) *addr_array;

typedef struct {
  time_t     i_ts;
  char       is_up;
  pdnsd_a    a;
} atup_t;
typedef DYNAMIC_ARRAY(atup_t) *atup_array;

typedef struct {
	unsigned char   *domain;
	short            exact;
	short            rule;
} slist_t;
typedef DYNAMIC_ARRAY(slist_t) *slist_array;

typedef struct {
	unsigned short   port;
	short            uptest;
	time_t           timeout;
	time_t           interval;
	time_t           ping_timeout;
        char             scheme[32];
	char            *uptest_cmd;
	char             uptest_usr[21];
	char             interface[IFNAMSIZ];
 	char             device[IFNAMSIZ];
	char            *label;
	char             purge_cache;
	char             nocache;
	char             lean_query;
	char             is_proxy;
	char             rootserver;
	char             preset;
	short            policy;
	slist_array      alist;
	atup_array       atup_a;
	pdnsd_a          ping_a;
} servparm_t;
typedef DYNAMIC_ARRAY(servparm_t) *servparm_array;

typedef unsigned char *zone_t;
typedef DYNAMIC_ARRAY(zone_t) *zone_array;

typedef struct {
	long          perm_cache;
	char         *cache_dir;
	char         *pidfile;
	int           port;
	pdnsd_a       a;
#ifdef ENABLE_IPV6
	struct in6_addr ipv4_6_prefix;
#endif
	time_t        max_ttl;
	time_t        min_ttl;
	time_t        neg_ttl;
	short         neg_rrs_pol;
	short         neg_domain_pol;
	short         verbosity;
	char          run_as[21];
	char          daemon;
	char          debug;
	char          stat_pipe;
	char          notcp;
	char          strict_suid;
	char          paranoid;
	char          lndown_kluge;
	char	      onquery;
	char          rnd_recs;
	int           ctl_perms;
        char         *scheme_file;
	int           proc_limit;
	int           procq_limit;
	time_t        tcp_qtimeout;
	time_t        timeout;
	int           par_queries;
	int           query_method;
	int           query_port_start;
	int           query_port_end;
	zone_array    deleg_only_zones;
} globparm_t;

typedef struct {
	char	prefix,
		pidfile,
		verbosity,
		pdnsduser,
		daemon,
		debug,
		stat_pipe,
		notcp,
		query_method;
} cmdlineflags_t;

extern globparm_t global;
extern cmdlineflags_t cmdline;
extern servparm_t serv_presets;

extern servparm_array servers;

int read_config_file(const char *nm, globparm_t *global, servparm_array *servers, char **errstr);
int reload_config_file(const char *nm, char **errstr);
void free_zone(void *ptr);
void free_slist_domain(void *ptr);
void free_slist_array(slist_array sla);
void free_servparm(servparm_t *serv);

int report_conf_stat(int f);
#endif
