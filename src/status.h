/* status.h - Make server status information accessible through a named pipe
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

/* $Id: status.h,v 1.11 2001/05/30 21:04:15 tmm Exp $ */

#ifndef _STATUS_H_
#define _STATUS_H_

#include <config.h>
#include "conff.h"

extern char sock_path[MAXPATH];

/* The commands for pdnsd-ctl */
#define CTL_STATS    1 /* Give out stats (like the "traditional" status pipe) */
#define CTL_SERVER   2 /* Enable or disable a server */
#define CTL_RECORD   3 /* Delete or invalidate records */
#define CTL_SOURCE   4 /* Read a hosts-style file */
#define CTL_ADD      5 /* Read a hosts-style file */
#define CTL_NEG      6 /* Read a hosts-style file */

#define CTL_S_UP     1
#define CTL_S_DOWN   2
#define CTL_S_RETEST 3
#define CTL_R_DELETE 1
#define CTL_R_INVAL  2

void init_stat_sock(void);
void start_stat_sock(void);

#endif
