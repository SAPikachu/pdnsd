/* consts.h - Common config constants & handling
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

/* $Id: consts.h,v 1.7 2001/04/06 18:11:34 tmm Exp $ */

#ifndef CONSTS_H
#define CONSTS_H

#include "config.h"

#define C_ERR      -1
#define C_RRTOFFS  64

#define C_ON        0
#define C_OFF       1
#define C_PING      2
#define C_NONE      3
#define C_IF        4
#define C_EXEC      5
#define C_ONQUERY   6
#define UDP_ONLY    7
#define TCP_ONLY    8
#define TCP_UDP     9
#define C_DEV      10
#define C_DIALD    11
#define C_INCLUDED 12
#define C_EXCLUDED 13
#define C_AUTH     14

int lookup_const(char *name);

#endif
