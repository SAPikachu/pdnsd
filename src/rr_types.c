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
static char rcsid[]="$Id: rr_types.c,v 1.4 2001/05/09 17:51:52 tmm Exp $";
#endif

/* Macro for standard records. No need to use it. Use with care (can produce
 * strange-lookdiung error messages) */
#define RR_ENT(name,tp) {name, RRCL_ ## tp, RRX_ ## tp}

/* There could be a separate table detailing the relationship of types, but this
 * is slightly more flexible, as it allows a finer granularity of exclusion. Also,
 * Membership in multiple classes could be added. */
struct rr_infos rr_info[]= {
	RR_ENT("A", 		RECORD),
	RR_ENT("NS", 		IDEM),
	RR_ENT("NS", 		IDEM),
	RR_ENT("MD", 		IDEM),
	RR_ENT("MF", 		IDEM),
	RR_ENT("CNAME", 	ALIAS),
	RR_ENT("SOA", 		IDEM),
	RR_ENT("MB", 		IDEM),
	RR_ENT("MG", 		IDEM),
	RR_ENT("MR", 		IDEM),
	RR_ENT("NULL",		IDEM),
	RR_ENT("WKS", 		IDEM),
	RR_ENT("PTR", 		PTR),
	RR_ENT("HINFO", 	RECORD),
	RR_ENT("MINFO", 	RECORD),
	RR_ENT("MX", 		IDEM),
	RR_ENT("TXT", 		RECORD),
#ifdef DNS_NEW_RRS
	RR_ENT("RP",		RECORD),
	RR_ENT("AFSDB",	RECORD),
	RR_ENT("X25",		RECORD),
	RR_ENT("ISDN",		RECORD),
	RR_ENT("RT",		RECORD),
	RR_ENT("NSAP",		RECORD),
	RR_ENT("NSAP_PTR",	PTR),		/* broken */
	RR_ENT("SIG",		IDEM),
	RR_ENT("KEY",		IDEM),
	RR_ENT("PX",		RECORD),
	RR_ENT("GPOS",		RECORD),
	RR_ENT("AAAA",		RECORD),
	RR_ENT("LOC",		RECORD),
	RR_ENT("NXT",		RECORD),
	RR_ENT("EID",		RECORD),
	RR_ENT("NIMLOC",	RECORD),
	RR_ENT("SRV",		RECORD),
	RR_ENT("ATMA",		RECORD),
	RR_ENT("NAPTR",	RECORD),
	RR_ENT("KX",		RECORD)
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
		if (strcmp(name, rr_info[i-T_MIN].name)==0)
			return i;
	}
	return -1; /* invalid */
}
