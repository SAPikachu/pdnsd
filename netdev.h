/* netdev.h - Test network devices for existence and status
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

/* $Id: netdev.h,v 1.2 2000/06/03 19:59:35 thomas Exp $ */

#ifndef _NETDEV_H_
#define _NETDEV_H_

#include "config.h"
#include "ipvers.h"

int if_up(char *devname);
int is_local_addr(pdnsd_a *a);

#endif
