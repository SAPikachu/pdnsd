/* rr_types.h - A structure with names & descriptions of
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

/* $Id: rr_types.h,v 1.1 2001/04/03 19:33:01 tmm Exp $ */

#ifndef _RR_TYPES_H_
#define _RR_TYPES_H_

#include "../config.h"

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
#define T_SRV      33
#define T_ATMA     34
#define T_NAPTR    35
#define T_KX       36


extern char *rr_info[];

int rr_tp_byname(char *name);

#endif




