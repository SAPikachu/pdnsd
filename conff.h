/* conff.h - Definiton for configuration management.
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

/* $Id: conff.h,v 1.3 2000/06/03 19:59:35 thomas Exp $ */

#ifndef _CONFF_H_
#define _CONFF_H_

#define MAXPATH 1024

#include "config.h"
#include <stdio.h>
#include <pthread.h>
#include "ipvers.h"

/* From main.c */
extern int daemon_p;
extern int debug_p;
extern int verbosity;
extern pthread_t main_thread;
/* ----------- */

typedef struct {
	unsigned short   port;
	int              uptest;
	long             timeout;
	long             interval;
	long             ping_timeout;
	char             interface[7];
	char             uptest_cmd[513];
	char             uptest_usr[20];
	char             purge_cache;
	char             nocache;
	char             lean_query;
	char             is_up;
        long             i_ts;
	pdnsd_a          ping_a;
	pdnsd_a          a;
} servparm_t;

typedef struct {
	long          perm_cache;
	char          cache_dir[MAXPATH];
	int           port;
} globparm_t;

extern globparm_t global;
extern servparm_t server;        /*This is only used temporarly*/
extern servparm_t serv_presets;

extern int serv_num;
extern servparm_t *servers;


void add_server(servparm_t serv);
void read_config_file(char *nm); /*nm may be NULL*/

void report_conf_stat(FILE *f);
#endif
