/* consts.c - Common config constants & handling
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

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "consts.h"
#include "rr_types.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: consts.c,v 1.3 2001/05/09 17:51:52 tmm Exp $";
#endif

typedef struct {
	int      c;
	char     *name;
} const_t;

/* Order alphabetically!! */
static const_t consts[]={
	{C_AUTH,       "auth"},
	{C_DEV,        "dev"},
	{C_DIALD,      "diald"},
	{C_EXCLUDED,   "excluded"},
	{C_EXEC,       "exec"},
	{C_FQDN_ONLY,  "fqdn_only"},
	{C_IF,         "if"},
	{C_INCLUDED,   "included"},
	{C_NONE,       "none"},
	{C_OFF,        "off"},
	{C_ON,         "on"},
	{C_ONQUERY,    "onquery"},
	{C_PING,       "ping"},
	{C_SIMPLE_ONLY,"simple_only"},
	{TCP_ONLY,     "tcp_only"},
	{TCP_UDP,      "tcp_udp"},
	{UDP_ONLY,     "udp_only"}
};

/* Added by Paul Rombouts */
static const char *const_names[]={
  "on",         /* 0 */
  "off",        /* 1 */
  "ping",       /* 2 */
  "none",       /* 3 */
  "if",         /* 4 */
  "exec",       /* 5 */
  "onquery",    /* 6 */
  "udp_only",   /* 7 */
  "tcp_only",   /* 8 */
  "tcp_udp",    /* 9 */
  "dev",        /* 10 */
  "diald",      /* 11 */
  "included",   /* 12 */
  "excluded",   /* 13 */
  "simple_only",/* 14 */
  "fqdn_only",  /* 15 */
  "auth"        /* 16 */
};
	 
static int cmp_const(const void *key, const void *el)
{
	return strcmp((char *)key, ((const_t *)el)->name);
}

int lookup_const(char *name)
{
	const_t *c=(const_t *)bsearch(name, consts, sizeof(consts)/sizeof(const_t), sizeof(const_t),cmp_const);
	if (c)
		return c->c;
	return C_ERR;
}


/* Added by Paul Rombouts */
const char *const_name(int c)
{
  return (c>=0 && c<sizeof(const_names)/sizeof(char *))? const_names[c] : "ILLEGAL!";
}
