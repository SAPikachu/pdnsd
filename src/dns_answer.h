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

/* $Id: dns_answer.h,v 1.1 2000/07/20 20:03:10 thomas Exp $ */

#ifndef _DNS_ANSWER_H_
#define _DNS_ANSWER_H_

#include "config.h"

/* --- from main.c */
extern int tcp_socket;
extern int udp_socket;
/* --- */

int init_udp_socket(void);
int init_tcp_socket(void);
void start_dns_servers(void);

#endif
