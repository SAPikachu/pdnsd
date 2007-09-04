/* rr_types.c - A structure with names & descriptions of
                all rr types known to pdnsd

   Copyright (C) 2000, 2001 Thomas Moestl
   Copyright (C) 2003, 2004, 2007 Paul A. Rombouts

  This file is part of the pdnsd package.

  pdnsd is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 3 of the License, or
  (at your option) any later version.

  pdnsd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with pdnsd; see the file COPYING. If not, see
  <http://www.gnu.org/licenses/>.
*/

#include <config.h>
#include <string.h>
#include <stdio.h>
#include "helpers.h"
#include "dns.h"
#include "rr_types.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: rr_types.c,v 1.7 2001/05/19 15:00:26 tmm Exp $";
#endif

/* Macro for standard records. No need to use it. Use with care (can produce
 * strange-looking error messages) */
#define RR_ENT(name,tp) {name, RRCL_ ## tp, RRX_ ## tp}

/* There could be a separate table detailing the relationship of types, but this
 * is slightly more flexible, as it allows a finer granularity of exclusion. Also,
 * Membership in multiple classes could be added. */
struct rr_infos rr_info[]= {
	RR_ENT("A", 		RECORD),
	RR_ENT("NS", 		IDEM),
	RR_ENT("MD", 		IDEM),
	RR_ENT("MF", 		IDEM),
	RR_ENT("CNAME", 	ALIAS),
	RR_ENT("SOA", 		IDEM),
	RR_ENT("MB", 		IDEM),
	RR_ENT("MG", 		IDEM),
	RR_ENT("MR", 		IDEM),
	RR_ENT("NULL",		IDEM),
	RR_ENT("WKS", 		RECORD),
	RR_ENT("PTR", 		PTR),
	RR_ENT("HINFO", 	RECORD),
	RR_ENT("MINFO", 	IDEM),
	RR_ENT("MX", 		IDEM),
	RR_ENT("TXT", 		IDEM),
#ifdef DNS_NEW_RRS
	RR_ENT("RP",		RECORD),
	RR_ENT("AFSDB",		RECORD),
	RR_ENT("X25",		RECORD),
	RR_ENT("ISDN",		RECORD),
	RR_ENT("RT",		RECORD),
	RR_ENT("NSAP",		RECORD),
	RR_ENT("NSAP_PTR",	PTR),		/* broken */
	RR_ENT("SIG",		IDEM),
	RR_ENT("KEY",		IDEM),
	RR_ENT("PX",		IDEM),
	RR_ENT("GPOS",		RECORD),
	RR_ENT("AAAA",		RECORD),
	RR_ENT("LOC",		RECORD),
	RR_ENT("NXT",		IDEM),
	RR_ENT("EID",		RECORD),
	RR_ENT("NIMLOC",	RECORD),
	RR_ENT("SRV",		RECORD),
	RR_ENT("ATMA",		RECORD),
	RR_ENT("NAPTR",		RECORD),
	RR_ENT("KX",		RECORD)
#endif
};

/*
 * OK, this is inefficient. But it is used _really_ seldom (only in some cases while parsing the
 * config file or by pdnsd-ctl), so it is much more effective to sort by id.
 */
int rr_tp_byname(char *name)
{
	int i;

	for (i=0;i<T_NUM;i++) {
		if (strcmp(name, rr_info[i].name)==0)
			return i+T_MIN;
	}
	return -1; /* invalid */
}

/* The following is not needed by pdnsd-ctl. */
#ifndef CLIENT_ONLY

static const unsigned int poweroften[8] = {1, 10, 100, 1000, 10000, 100000,
					   1000000,10000000};
#define NPRECSIZE (sizeof "90000000")
/* takes an XeY precision/size value, returns a string representation.
   This is an adapted version of the function of the same name that
   can be found in the BIND 9 source.
 */
static const char *precsize_ntoa(uint8_t prec,char *retbuf)
{
	unsigned int mantissa, exponent;

	mantissa = (prec >> 4);
	exponent = (prec & 0x0f);

	if(mantissa>=10 || exponent>=10)
		return NULL;
	if (exponent>= 2)
		sprintf(retbuf, "%u", mantissa * poweroften[exponent-2]);
	else
		sprintf(retbuf, "0.%.2u", mantissa * poweroften[exponent]);
	return (retbuf);
}

/* takes an on-the-wire LOC RR and formats it in a human readable format.
   This is an adapted version of the loc_ntoa function that
   can be found in the BIND 9 source.
 */
const char *loc2str(const void *binary, char *ascii, size_t asclen)
{
	const unsigned char *cp = binary;

	int latdeg, latmin, latsec, latsecfrac;
	int longdeg, longmin, longsec, longsecfrac;
	char northsouth, eastwest;
	const char *altsign;
	int altmeters, altfrac;

	const uint32_t referencealt = 100000 * 100;

	int32_t latval, longval, altval;
	uint32_t templ;
	uint8_t sizeval, hpval, vpval, versionval;
    
	char sizestr[NPRECSIZE],hpstr[NPRECSIZE],vpstr[NPRECSIZE];

	versionval = *cp++;

	if (versionval) {
		/* unknown LOC RR version */
		return NULL;
	}

	sizeval = *cp++;

	hpval = *cp++;
	vpval = *cp++;

	GETINT32(templ, cp);
	latval = (templ - ((unsigned)1<<31));

	GETINT32(templ, cp);
	longval = (templ - ((unsigned)1<<31));

	GETINT32(templ, cp);
	if (templ < referencealt) { /* below WGS 84 spheroid */
		altval = referencealt - templ;
		altsign = "-";
	} else {
		altval = templ - referencealt;
		altsign = "";
	}

	if (latval < 0) {
		northsouth = 'S';
		latval = -latval;
	} else
		northsouth = 'N';

	latsecfrac = latval % 1000;
	latval /= 1000;
	latsec = latval % 60;
	latval /= 60;
	latmin = latval % 60;
	latval /= 60;
	latdeg = latval;

	if (longval < 0) {
		eastwest = 'W';
		longval = -longval;
	} else
		eastwest = 'E';

	longsecfrac = longval % 1000;
	longval /= 1000;
	longsec = longval % 60;
	longval /= 60;
	longmin = longval % 60;
	longval /= 60;
	longdeg = longval;

	altfrac = altval % 100;
	altmeters = (altval / 100);

	if(!precsize_ntoa(sizeval,sizestr) || !precsize_ntoa(hpval,hpstr) || !precsize_ntoa(vpval,vpstr))
		return NULL;
	{
		int n=snprintf(ascii,asclen,
			       "%d %.2d %.2d.%.3d %c %d %.2d %.2d.%.3d %c %s%d.%.2dm %sm %sm %sm",
			       latdeg, latmin, latsec, latsecfrac, northsouth,
			       longdeg, longmin, longsec, longsecfrac, eastwest,
			       altsign, altmeters, altfrac,
			       sizestr, hpstr, vpstr);
		if(n<0 || n>=asclen)
			return NULL;
	}
	
	return (ascii);
}

#endif
