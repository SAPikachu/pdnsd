/* icmp.h - Server response tests using ICMP echo requests
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

/* $Id: icmp.h,v 1.4 2001/05/09 17:51:52 tmm Exp $ */

#ifndef ICMP_H
#define ICMP_H


#include <config.h>
#include "ipvers.h"

volatile extern int ping_isocket;
volatile extern int ping6_isocket;

/* initialize a socket for pinging */
void init_ping_socket(void);

/* 
 * This is a classical ping routine
 * timeout in milliseconds, rep is the repetition time
 */

int ping(pdnsd_a *addr, int timeout, int rep);

#endif
