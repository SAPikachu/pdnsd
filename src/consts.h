/* consts.h - Common config constants & handling

   Copyright (C) 2000, 2001 Thomas Moestl
   Copyright (C) 2002, 2003 Paul A. Rombouts

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

/* $Id: consts.h,v 1.8 2001/05/09 17:51:52 tmm Exp $ */

#ifndef CONSTS_H
#define CONSTS_H

#include <config.h>

#define C_RRTOFFS  64

enum {
	C_ERR,
	C_ON,
	C_OFF,
	C_PING,
	C_NONE,
	C_IF,
	C_EXEC,
	C_QUERY,
	C_ONQUERY,
	UDP_ONLY,
	TCP_ONLY,
	TCP_UDP,
	C_DEV,
	C_DIALD,
	C_INCLUDED,
	C_EXCLUDED,
	C_SIMPLE_ONLY,
	C_FQDN_ONLY,
	C_AUTH,
	C_DOMAIN
};

typedef struct {
	const char *name;
	int         val;
} namevalue_t;

int binsearch_keyword(const char *name, int len, const namevalue_t dic[], int range);
int lookup_const(const char *name, int len);
const char *const_name(int c);  /* Added by Paul Rombouts */

#endif
