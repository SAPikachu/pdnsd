/* servers.h - manage a set of dns servers

   Copyright (C) 2000 Thomas Moestl
   Copyright (C) 2002, 2003, 2004 Paul A. Rombouts

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

/* $Id: servers.h,v 1.3 2001/05/09 17:51:52 tmm Exp $ */

#ifndef _SERVERS_H_
#define _SERVERS_H_

#include <config.h>
#include "consts.h"

/* Number of ping timeouts before we take a server offline. */
#define PINGREPEAT 2

int start_servstat_thread(void);
void sched_server_test(pdnsd_a *sa, int nadr, int up);
void mark_server(int i, int j, int up);
void test_onquery(void);
void perform_uptest(int i, int j);
void lock_server_data();
void unlock_server_data();
int exclusive_lock_server_data(int tm);
void exclusive_unlock_server_data(int retest);
int change_servers(int i, addr_array ar, int up);

inline static int needs_intermittent_testing(servparm_t *sp)
{
  return (sp->interval>0 && (sp->uptest!=C_NONE || sp->scheme[0]));
}

#endif
