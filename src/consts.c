/* consts.c - Common config constants & handling

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

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "consts.h"
#include "rr_types.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: consts.c,v 1.3 2001/05/09 17:51:52 tmm Exp $";
#endif

/* Order alphabetically!! */
static const namevalue_t const_dic[]={
	{"auth",        C_AUTH},
	{"dev",         C_DEV},
	{"diald",       C_DIALD},
	{"domain",      C_DOMAIN},
	{"excluded",    C_EXCLUDED},
	{"exec",        C_EXEC},
	{"fqdn_only",   C_FQDN_ONLY},
	{"if",          C_IF},
	{"included",    C_INCLUDED},
	{"none",        C_NONE},
	{"off",         C_OFF},
	{"on",          C_ON},
	{"onquery",     C_ONQUERY},
	{"ping",        C_PING},
	{"query",       C_QUERY},
	{"simple_only", C_SIMPLE_ONLY},
	{"tcp_only",    TCP_ONLY},
	{"tcp_udp",     TCP_UDP},
	{"udp_only",    UDP_ONLY}
};

/* Added by Paul Rombouts */
static const char *const_names[]={
	"error",
	"on",
	"off",
	"ping",
	"none",
	"if",
	"exec",
	"query",
	"onquery",
	"udp_only",
	"tcp_only",
	"tcp_udp",
	"dev",
	"diald",
	"included",
	"excluded",
	"simple_only",
	"fqdn_only",
	"auth",
	"domain"
};

/* compare two strings.
   The first one is given as pointer to a char array of length len,
   the second one as a pointer to a null terminated char array.
*/
inline static int keyncmp(const char *key1, int len, const char *key2)
{
	int cmp=strncmp(key1,key2,len);
	if(cmp) return cmp;
	return len-strlen(key2);
}

int binsearch_keyword(const char *name, int len, const namevalue_t dic[], int range)
{
	int i=0,j=range;

	while(i<j) {
		int k=(i+j)/2;
		int cmp=keyncmp(name,len,dic[k].name);
		if(cmp<0)
			j=k;
		else if(cmp>0)
			i=k+1;
		else
			return dic[k].val;
	}

	return 0;
}


int lookup_const(const char *name, int len)
{
	return binsearch_keyword(name,len,const_dic,sizeof(const_dic)/sizeof(namevalue_t));
}

/* Added by Paul Rombouts */
const char *const_name(int c)
{
  return (c>=0 && c<sizeof(const_names)/sizeof(char *))? const_names[c] : "ILLEGAL!";
}
