/* dns_answer.h - Receive and process icoming dns queries.
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

/* $Id: dns_answer.h,v 1.3 2001/05/09 17:51:52 tmm Exp $ */

#ifndef DNS_ANSWER_H
#define DNS_ANSWER_H

#include <config.h>

/* --- from main.c */
extern pthread_t main_thrid,servstat_thrid,statsock_thrid,tcps_thrid,udps_thrid;
extern volatile int tcp_socket;
extern volatile int udp_socket;
/* --- */

int init_udp_socket(void);
int init_tcp_socket(void);
void start_dns_servers(void);
int report_thread_stat(int f);

#endif
