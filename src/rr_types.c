/* rr_types.c - A structure with names & descriptions of
                all rr types known to pdnsd
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

#include "rr_types.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: rr_types.c,v 1.3 2001/04/11 03:30:11 tmm Exp $";
#endif

char *rr_info[]={"A",
		 "NS",
		 "MD",
		 "MF",
		 "CNAME",
		 "SOA",
		 "MB",
		 "MG",
		 "MR",
		 "NULL",
		 "WKS",
		 "PTR",
		 "HINFO",
		 "MINFO",
		 "MX",
		 "TXT",
#ifdef DNS_NEW_RRS
		 "RP",
		 "AFSDB",
		 "X25",
		 "ISDN",
		 "RT",
		 "NSAP",
		 "NSAP_PTR",
		 "SIG",
		 "KEY",
		 "PX",
		 "GPOS",
		 "AAAA",
		 "LOC",
		 "NXT",
		 "EID",
		 "NIMLOC",
		 "SRV",
		 "ATMA",
		 "NAPTR",
		 "KX"
#endif
};

/*
 * OK, this is ineffective. But it is used _really_ seldom (only in some cases while parsing the
 * config file or by pdnsd-ctl), so it is much more effective to sort by id.
 */
int rr_tp_byname(char *name)
{
	int i;

	for (i=T_MIN;i<=T_MAX;i++) {
		if (strcmp(name, rr_info[i-T_MIN])==0)
			return i;
	}
	return -1; /* invalid */
}
