/* rr_types.h - A structure with names & descriptions of
                all rr types known to pdnsd
   Copyright (C) 2000, 2001 Thomas Moestl
   Copyright (C) 2007 Paul A. Rombouts

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

/* $Id: rr_types.h,v 1.2 2001/05/09 17:51:52 tmm Exp $ */

#ifndef _RR_TYPES_H_
#define _RR_TYPES_H_

#include <config.h>

#define T_MIN       1
#define T_A         1
#define T_NS        2    /* additional A*/
#define T_MD        3    /* additional A*/
#define T_MF        4    /* additional A*/
#define T_CNAME     5
#define T_SOA       6
#define T_MB        7    /* additional A*/
#define T_MG        8  
#define T_MR        9    
#define T_NULL     10
#define T_WKS      11
#define T_PTR      12
#define T_HINFO    13
#define T_MINFO    14
#define T_MX       15    /* additional A*/
#define T_TXT      16
#ifdef DNS_NEW_RRS
# define T_MAX     36
# define T_NUM     36
#else
# define T_MAX     16
# define T_NUM     16
#endif

#define T_RP	   17
#define T_AFSDB    18
#define T_X25      19
#define T_ISDN     20
#define T_RT       21
#define T_NSAP     22
#define T_NSAP_PTR 23    /* deprecated (ill-designed) and not supported */
#define T_SIG      24
#define T_KEY      25
#define T_PX       26
#define T_GPOS     27
#define T_AAAA     28
#define T_LOC      29
#define T_NXT      30
#define T_EID      31
#define T_NIMLOC   32
#define T_SRV      33    /* additional A*/
#define T_ATMA     34
#define T_NAPTR    35
#define T_KX       36

/* Structure for rr information */
struct rr_infos {
	char	*name;		/* name of the RR */
	int	class;		/* class (values see below) */
	int	excludes;	/* relations to other classes. Mutual exclusion is marked by or'ing the
				 * respective RRCL value in this field. Exclusions should be symmetric. */
};

/* Class values */
#define RRCL_ALIAS	1	/* for CNAMES, conflics with RRCL_RECORD */
#define RRCL_RECORD	2	/* normal direct record */
#define RRCL_IDEM	4	/* types that conflict with no others (MX, CNAME, ...) */
#define RRCL_PTR	8	/* PTR */

/* Standard excludes for the classes */
#define RRX_ALIAS	(RRCL_RECORD|RRCL_PTR)
#define	RRX_RECORD	(RRCL_ALIAS|RRCL_PTR)
#define	RRX_IDEM	0
#define	RRX_PTR		(RRCL_ALIAS|RRCL_RECORD)

extern struct rr_infos rr_info[];

int rr_tp_byname(char *name);
const char *loc2str(const void *binary, char *ascii, size_t asclen);

#endif




