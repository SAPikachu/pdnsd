/* conff.h - Definiton for configuration management.
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

/* $Id: conff.h,v 1.16 2001/04/12 18:48:22 tmm Exp $ */

#ifndef CONFF_H
#define CONFF_H

/* XXX should use the system defined one */
#define MAXPATH 1024

#include "config.h"
#include <stdio.h>
#include <pthread.h>
#include "ipvers.h"
#include "list.h"

/* From main.c */
extern int daemon_p;
extern int debug_p;
extern int verbosity;
extern pthread_t main_thread;
extern char pidfile[MAXPATH];
extern int stat_pipe;
extern int notcp;
/* ----------- */

typedef struct {
	int              rule;
	char             domain[256];
} slist_t;

typedef struct {
	unsigned short   port;
	int              uptest;
	time_t           timeout;
	time_t           interval;
	time_t           ping_timeout;
        char             scheme[32];
	char             interface[7];
 	char             device[7];
	char             uptest_cmd[513];
	char             uptest_usr[21];
	char             purge_cache;
	char             nocache;
	char             lean_query;
	char             is_up;
	char             is_proxy;
	int              policy;
	darray           alist;
        time_t           i_ts;
	pdnsd_a          ping_a;
	pdnsd_a          a;
} servparm_t;

typedef struct {
	long          perm_cache;
	char          cache_dir[MAXPATH];
	int           port;
	pdnsd_a       a;
	char          lndown_kluge;
	time_t        max_ttl;
	time_t        min_ttl;
	time_t        neg_ttl;
	int           neg_rrs_pol;
	int           neg_domain_pol;
	char          run_as[21];
	char          strict_suid;
	char          paranoid;
	int           ctl_perms;
        char          scheme_file[MAXPATH];
	int           proc_limit;
	int           procq_limit;
	int           tcp_qtimeout;
	int           par_queries;
	char          rnd_recs;
} globparm_t;

extern globparm_t global;
extern servparm_t server;        /* This is only used temporarily */
extern servparm_t serv_presets;

extern darray servers;

void set_serv_presets(servparm_t *server);

void add_server(servparm_t serv);
char *slist_add(servparm_t *sp, char *nm, int tp);
void read_config_file(char *nm); /*nm may be NULL*/

void report_conf_stat(int f);
#endif
