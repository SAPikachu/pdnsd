/* A Bison parser, made from conf-parse.y
   by GNU bison 1.35.  */

#define YYBISON 1  /* Identify Bison output.  */

# define	NUMBER	257
# define	STRING	258
# define	ERROR	259
# define	GLOBAL	260
# define	SERVER	261
# define	RR	262
# define	NEG	263
# define	SOURCE	264
# define	PERM_CACHE	265
# define	CACHE_DIR	266
# define	SERVER_PORT	267
# define	SERVER_IP	268
# define	SCHEME_FILE	269
# define	LINKDOWN_KLUGE	270
# define	MAX_TTL	271
# define	MIN_TTL	272
# define	RUN_AS	273
# define	STRICT_SETUID	274
# define	PARANOID	275
# define	STATUS_CTL	276
# define	DAEMON	277
# define	C_TCP_SERVER	278
# define	PID_FILE	279
# define	C_VERBOSITY	280
# define	C_QUERY_METHOD	281
# define	RUN_IPV4	282
# define	C_DEBUG	283
# define	C_CTL_PERMS	284
# define	C_PROC_LIMIT	285
# define	C_PROCQ_LIMIT	286
# define	TCP_QTIMEOUT	287
# define	C_PAR_QUERIES	288
# define	C_RAND_RECS	289
# define	NEG_TTL	290
# define	NEG_RRS_POL	291
# define	NEG_DOMAIN_POL	292
# define	QUERY_PORT_START	293
# define	QUERY_PORT_END	294
# define	DELEGATION_ONLY	295
# define	IP	296
# define	PORT	297
# define	SCHEME	298
# define	UPTEST	299
# define	TIMEOUT	300
# define	PING_TIMEOUT	301
# define	PING_IP	302
# define	UPTEST_CMD	303
# define	INTERVAL	304
# define	INTERFACE	305
# define	DEVICE	306
# define	PURGE_CACHE	307
# define	CACHING	308
# define	LEAN_QUERY	309
# define	PRESET	310
# define	PROXY_ONLY	311
# define	INCLUDE	312
# define	EXCLUDE	313
# define	POLICY	314
# define	LABEL	315
# define	A	316
# define	PTR	317
# define	MX	318
# define	SOA	319
# define	CNAME	320
# define	NAME	321
# define	OWNER	322
# define	TTL	323
# define	TYPES	324
# define	FILET	325
# define	SERVE_ALIASES	326
# define	AUTHREC	327
# define	NDOMAIN	328
# define	CONST	329
# define	RRTYPE	330

#line 1 "conf-parse.y"

/* conf.y - Parser for pdnsd config files.
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
#include "ipvers.h"
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "conff.h"
#include "consts.h"
#include "cache.h"
#include "dns.h"
#include "dns_query.h"
#include "helpers.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: conf-parse.y,v 1.37 2003/04/06 23:02:46 tmm Exp $";
#endif

/* this stuff should be declared locally to yyparse, not globally
   where it keeps occupying space long after we're done with it.
   Unfortunately, there is no mechanism supported by bison, as far as I know,
   that can be used to insert C declarations into the main scope of yyparse(),
   so we'll have to insert a macro call to YYPARSE_LOCAL_DECL ourselves.
   Some of these variables are initialized to zero. This is only done
   to stop the compiler from complaining.
*/

#define YYPARSE_LOCAL_DECL  \
servparm_t server;  \
dns_cent_t c_cent;  \
unsigned char c_owner[256];  \
unsigned char c_name[256];  \
time_t c_ttl=0;  \
int c_flags=0,in_or_excluded=0;  \
unsigned char c_aliases=0, hdtp=0, htp=0;


#ifndef NO_YYLINENO
/*
 * This comes from the generated lexer. It is an undocumented variable in lex, and in flex
 * we explicitely switch it on.
 */
extern int yylineno;
#endif

int yyerror (char *s); /* To inhibit "implicit declaration" compiler warning */

/* Bah. I want strlcpy. */
#define YSTRNCP(dst, src, err) 				 \
        {						 \
	        if (!strncp(dst,src,sizeof(dst))) {	 \
		        yyerror(err": string too long"); \
		        YYERROR; 			 \
	        } 					 \
	}

#define YSTRDUP(dst,src) \
        {  \
	  if(dst) free(dst);  \
	  if(!(dst=strdup(src))) {  \
	    yyerror("Out of memory");  \
	    YYERROR;  \
	  }  \
	}

#define YSTRASSIGN(dst,src) \
        {  \
	  if(dst) free(dst);  \
	  (dst)=(src);  \
	}

/* This was originally in conff.h */

/*
 * Add a server (with parameters contained in serv) into the internal server list
 * (in the pointer servers)
 */
inline static void add_server(servparm_t *serv)
{
  if (!(servers=DA_GROW1(servers))) {
    fprintf(stderr,"Error: out of memory.\n");
    exit(1);
  }
  DA_LAST(servers)=*serv;
}

static char *addr_add(servparm_t *sp, char *ipstr);
static char *slist_add(servparm_t *sp, char *nm, int tp);
static char *zone_add(zone_array *za, char *zone);


#line 114 "conf-parse.y"
#ifndef YYSTYPE
typedef union {
long 	      num;
unsigned char *nm;
} yystype;
# define YYSTYPE yystype
# define YYSTYPE_IS_TRIVIAL 1
#endif
#ifndef YYDEBUG
# define YYDEBUG 0
#endif



#define	YYFINAL		343
#define	YYFLAG		-32768
#define	YYNTBASE	82

/* YYTRANSLATE(YYLEX) -- Bison token number corresponding to YYLEX. */
#define YYTRANSLATE(x) ((unsigned)(x) <= 330 ? yytranslate[x] : 105)

/* YYTRANSLATE[YYLEX] -- Bison token number corresponding to YYLEX. */
static const char yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,    79,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,    81,
       2,    80,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    77,     2,    78,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     3,     4,     5,
       6,     7,     8,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
      46,    47,    48,    49,    50,    51,    52,    53,    54,    55,
      56,    57,    58,    59,    60,    61,    62,    63,    64,    65,
      66,    67,    68,    69,    70,    71,    72,    73,    74,    75,
      76
};

#if YYDEBUG
static const short yyprhs[] =
{
       0,     0,     1,     4,     9,    10,    16,    17,    23,    24,
      30,    31,    37,    38,    41,    43,    47,    52,    57,    62,
      67,    72,    77,    82,    87,    92,    97,   102,   107,   112,
     117,   122,   127,   132,   137,   142,   147,   152,   157,   162,
     167,   172,   177,   182,   187,   192,   197,   202,   207,   208,
     211,   213,   217,   219,   223,   228,   233,   238,   243,   248,
     253,   258,   263,   270,   275,   280,   285,   290,   295,   300,
     305,   310,   315,   320,   321,   327,   328,   334,   339,   340,
     343,   348,   353,   358,   363,   368,   373,   380,   385,   402,
     403,   406,   411,   416,   421,   426,   431,   432,   435,   440,
     445,   450,   455,   457,   461
};
static const short yyrhs[] =
{
      -1,    82,    83,     0,     6,    77,    88,    78,     0,     0,
       7,    77,    84,    91,    78,     0,     0,     8,    77,    85,
      97,    78,     0,     0,     9,    77,    86,   101,    78,     0,
       0,    10,    77,    87,    99,    78,     0,     0,    88,    90,
       0,     4,     0,    89,    79,     4,     0,    11,    80,    75,
      81,     0,    11,    80,     3,    81,     0,    12,    80,     4,
      81,     0,    13,    80,     3,    81,     0,    14,    80,     4,
      81,     0,    15,    80,     4,    81,     0,    16,    80,    75,
      81,     0,    17,    80,     3,    81,     0,    18,    80,     3,
      81,     0,    19,    80,     4,    81,     0,    20,    80,    75,
      81,     0,    21,    80,    75,    81,     0,    22,    80,    75,
      81,     0,    23,    80,    75,    81,     0,    24,    80,    75,
      81,     0,    25,    80,     4,    81,     0,    26,    80,     3,
      81,     0,    27,    80,    75,    81,     0,    28,    80,    75,
      81,     0,    29,    80,    75,    81,     0,    30,    80,     3,
      81,     0,    31,    80,     3,    81,     0,    32,    80,     3,
      81,     0,    33,    80,     3,    81,     0,    34,    80,     3,
      81,     0,    35,    80,    75,    81,     0,    36,    80,     3,
      81,     0,    37,    80,    75,    81,     0,    38,    80,    75,
      81,     0,    39,    80,     3,    81,     0,    40,    80,     3,
      81,     0,    41,    80,    89,    81,     0,     0,    91,    94,
       0,     4,     0,    92,    79,     4,     0,     4,     0,    93,
      79,     4,     0,    42,    80,    92,    81,     0,    43,    80,
       3,    81,     0,    44,    80,     4,    81,     0,    45,    80,
      75,    81,     0,    46,    80,     3,    81,     0,    47,    80,
       3,    81,     0,    48,    80,     4,    81,     0,    49,    80,
       4,    81,     0,    49,    80,     4,    79,     4,    81,     0,
      50,    80,     3,    81,     0,    50,    80,    75,    81,     0,
      51,    80,     4,    81,     0,    52,    80,     4,    81,     0,
      53,    80,    75,    81,     0,    54,    80,    75,    81,     0,
      55,    80,    75,    81,     0,    56,    80,    75,    81,     0,
      57,    80,    75,    81,     0,    60,    80,    75,    81,     0,
       0,    58,    80,    95,    93,    81,     0,     0,    59,    80,
      96,    93,    81,     0,    61,    80,     4,    81,     0,     0,
      97,    98,     0,    67,    80,     4,    81,     0,    68,    80,
       4,    81,     0,    69,    80,     3,    81,     0,    73,    80,
      75,    81,     0,    62,    80,     4,    81,     0,    63,    80,
       4,    81,     0,    64,    80,     4,    79,     3,    81,     0,
      66,    80,     4,    81,     0,    65,    80,     4,    79,     4,
      79,     3,    79,     3,    79,     3,    79,     3,    79,     3,
      81,     0,     0,    99,   100,     0,    68,    80,     4,    81,
       0,    69,    80,     3,    81,     0,    71,    80,     4,    81,
       0,    72,    80,    75,    81,     0,    73,    80,    75,    81,
       0,     0,   101,   102,     0,    67,    80,     4,    81,     0,
      69,    80,     3,    81,     0,    70,    80,    74,    81,     0,
      70,    80,   103,    81,     0,   104,     0,   104,    79,   103,
       0,    76,     0
};

#endif

#if YYDEBUG
/* YYRLINE[YYN] -- source line where rule number YYN was defined. */
static const short yyrline[] =
{
       0,   215,   216,   219,   220,   220,   241,   241,   261,   261,
     271,   271,   288,   289,   292,   302,   314,   323,   327,   331,
     335,   343,   347,   356,   360,   364,   369,   378,   387,   396,
     405,   414,   418,   422,   452,   467,   476,   480,   484,   488,
     492,   496,   505,   509,   518,   527,   539,   551,   554,   555,
     558,   568,   580,   590,   602,   604,   608,   613,   622,   626,
     630,   638,   642,   648,   652,   661,   666,   671,   680,   689,
     698,   707,   716,   725,   725,   726,   726,   727,   734,   735,
     738,   765,   784,   788,   797,   840,   860,   886,   906,   951,
     952,   955,   968,   972,   987,   996,  1008,  1009,  1013,  1030,
    1034,  1052,  1057,  1058,  1061
};
#endif


#if (YYDEBUG) || defined YYERROR_VERBOSE

/* YYTNAME[TOKEN_NUM] -- String name of the token TOKEN_NUM. */
static const char *const yytname[] =
{
  "$", "error", "$undefined.", "NUMBER", "STRING", "ERROR", "GLOBAL", 
  "SERVER", "RR", "NEG", "SOURCE", "PERM_CACHE", "CACHE_DIR", 
  "SERVER_PORT", "SERVER_IP", "SCHEME_FILE", "LINKDOWN_KLUGE", "MAX_TTL", 
  "MIN_TTL", "RUN_AS", "STRICT_SETUID", "PARANOID", "STATUS_CTL", 
  "DAEMON", "C_TCP_SERVER", "PID_FILE", "C_VERBOSITY", "C_QUERY_METHOD", 
  "RUN_IPV4", "C_DEBUG", "C_CTL_PERMS", "C_PROC_LIMIT", "C_PROCQ_LIMIT", 
  "TCP_QTIMEOUT", "C_PAR_QUERIES", "C_RAND_RECS", "NEG_TTL", 
  "NEG_RRS_POL", "NEG_DOMAIN_POL", "QUERY_PORT_START", "QUERY_PORT_END", 
  "DELEGATION_ONLY", "IP", "PORT", "SCHEME", "UPTEST", "TIMEOUT", 
  "PING_TIMEOUT", "PING_IP", "UPTEST_CMD", "INTERVAL", "INTERFACE", 
  "DEVICE", "PURGE_CACHE", "CACHING", "LEAN_QUERY", "PRESET", 
  "PROXY_ONLY", "INCLUDE", "EXCLUDE", "POLICY", "LABEL", "A", "PTR", "MX", 
  "SOA", "CNAME", "NAME", "OWNER", "TTL", "TYPES", "FILET", 
  "SERVE_ALIASES", "AUTHREC", "NDOMAIN", "CONST", "RRTYPE", "'{'", "'}'", 
  "','", "'='", "';'", "file", "spec", "@1", "@2", "@3", "@4", "glob_s", 
  "zone_list", "glob_el", "serv_s", "ip_list", "inexclude_list", 
  "serv_el", "@5", "@6", "rr_s", "rr_el", "source_s", "source_el", 
  "rrneg_s", "rrneg_el", "rr_type_list", "rr_type", 0
};
#endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives. */
static const short yyr1[] =
{
       0,    82,    82,    83,    84,    83,    85,    83,    86,    83,
      87,    83,    88,    88,    89,    89,    90,    90,    90,    90,
      90,    90,    90,    90,    90,    90,    90,    90,    90,    90,
      90,    90,    90,    90,    90,    90,    90,    90,    90,    90,
      90,    90,    90,    90,    90,    90,    90,    90,    91,    91,
      92,    92,    93,    93,    94,    94,    94,    94,    94,    94,
      94,    94,    94,    94,    94,    94,    94,    94,    94,    94,
      94,    94,    94,    95,    94,    96,    94,    94,    97,    97,
      98,    98,    98,    98,    98,    98,    98,    98,    98,    99,
      99,   100,   100,   100,   100,   100,   101,   101,   102,   102,
     102,   102,   103,   103,   104
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN. */
static const short yyr2[] =
{
       0,     0,     2,     4,     0,     5,     0,     5,     0,     5,
       0,     5,     0,     2,     1,     3,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     0,     2,
       1,     3,     1,     3,     4,     4,     4,     4,     4,     4,
       4,     4,     6,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     0,     5,     0,     5,     4,     0,     2,
       4,     4,     4,     4,     4,     4,     6,     4,    16,     0,
       2,     4,     4,     4,     4,     4,     0,     2,     4,     4,
       4,     4,     1,     3,     1
};

/* YYDEFACT[S] -- default rule to reduce with in state S when YYTABLE
   doesn't specify something else to do.  Zero means the default is an
   error. */
static const short yydefact[] =
{
       1,     0,     0,     0,     0,     0,     0,     2,    12,     4,
       6,     8,    10,     0,    48,    78,    96,    89,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     3,
      13,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     5,    49,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     7,    79,     0,
       0,     0,     9,    97,     0,     0,     0,     0,     0,    11,
      90,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    14,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      73,    75,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    17,    16,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,     0,    47,    50,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   104,     0,
     102,     0,     0,     0,     0,     0,    15,     0,    54,    55,
      56,    57,    58,    59,    60,     0,    61,    63,    64,    65,
      66,    67,    68,    69,    70,    71,    52,     0,     0,    72,
      77,    84,    85,     0,     0,    87,    80,    81,    82,    83,
      98,    99,   100,   101,     0,    91,    92,    93,    94,    95,
      51,     0,     0,    74,    76,     0,     0,   103,    62,    53,
      86,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    88,     0,     0
};

static const short yydefgoto[] =
{
       1,     7,    14,    15,    16,    17,    13,   163,    50,    51,
     235,   297,   107,   252,   253,    52,   118,    54,   130,    53,
     123,   269,   270
};

static const short yypact[] =
{
  -32768,    80,   -44,   -23,   -13,   -10,     1,-32768,-32768,-32768,
  -32768,-32768,-32768,    -9,-32768,-32768,-32768,-32768,   -12,    -5,
      13,    22,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,    43,
      44,    45,    46,    47,    48,    49,    50,    51,    52,-32768,
  -32768,    -8,    -7,     7,    23,    -3,    79,   101,   129,   130,
      60,   133,   134,   135,    63,    65,    66,    67,    68,   140,
     142,    71,    72,    73,   146,   147,   148,   149,   150,    81,
     151,    82,    83,   152,   156,   157,    84,    85,    86,    87,
      88,    89,    90,    91,    92,    93,    94,    95,    96,    97,
      98,    99,   100,   102,   103,   104,-32768,-32768,   105,   106,
     107,   108,   109,   110,   111,   112,   113,-32768,-32768,   114,
     115,   116,-32768,-32768,   117,   118,   119,   120,   121,-32768,
  -32768,   122,   123,   124,   125,   126,   127,   128,   131,   132,
     136,   137,   138,   139,   141,   143,   144,   145,   153,   154,
     155,   158,   159,   160,   161,   162,   163,   164,   165,   166,
     167,   168,-32768,   -16,   177,   199,   206,   175,   208,   211,
     212,   217,    -2,   219,   223,   176,   178,   179,   180,   181,
  -32768,-32768,   182,   224,   225,   226,   227,   228,   229,   233,
     234,   249,   183,   255,   257,     5,   258,   260,   261,   186,
     189,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
  -32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
  -32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
  -32768,-32768,   262,-32768,-32768,     3,   187,   188,   190,   191,
     192,   193,    18,   194,   195,   196,   197,   198,   200,   201,
     202,   203,   263,   263,   204,   205,   207,   209,   210,   213,
     214,   215,   216,   218,   220,   221,   222,   230,-32768,   231,
     235,   232,   236,   237,   238,   239,-32768,   266,-32768,-32768,
  -32768,-32768,-32768,-32768,-32768,   276,-32768,-32768,-32768,-32768,
  -32768,-32768,-32768,-32768,-32768,-32768,-32768,    19,    24,-32768,
  -32768,-32768,-32768,   284,   287,-32768,-32768,-32768,-32768,-32768,
  -32768,-32768,-32768,-32768,   240,-32768,-32768,-32768,-32768,-32768,
  -32768,   241,   289,-32768,-32768,   242,   245,-32768,-32768,-32768,
  -32768,   291,   246,   295,   247,   297,   248,   301,   250,   302,
     251,-32768,   306,-32768
};

static const short yypgoto[] =
{
  -32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
  -32768,   -93,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
  -32768,  -152,-32768
};


#define	YYLAST		332


static const short yytable[] =
{
     131,   243,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
      46,    47,    48,     8,    86,    87,    88,    89,    90,    91,
      92,    93,    94,    95,    96,    97,    98,    99,   100,   101,
     102,   103,   104,   105,     9,   108,   109,   110,   111,   112,
     113,   114,   115,   232,    10,   233,   116,    11,    55,    49,
     106,   117,   132,   244,   119,    56,   120,   121,    12,   267,
     342,   268,   277,   133,   278,   122,     2,     3,     4,     5,
       6,   124,   125,    57,   126,   127,   128,   285,   322,   286,
     323,   129,    58,   322,   134,   324,    59,    60,    61,    62,
      63,    64,    65,    66,    67,    68,    69,    70,    71,    72,
      73,    74,    75,    76,    77,    78,    79,    80,    81,    82,
      83,    84,    85,   135,   136,   137,   138,   139,   141,   140,
     142,   143,   144,   145,   146,   147,   148,   149,   150,   151,
     152,   153,   154,   155,   157,   160,   156,   158,   159,   161,
     298,   162,   327,     0,   164,   165,   166,   167,   168,   169,
     170,   171,   172,   173,   174,   175,   176,   177,   178,   179,
     180,   234,   181,   182,   183,   184,   185,   186,   187,   188,
     189,   190,   191,   192,   193,   194,   195,   196,   197,   198,
     199,   200,   236,   201,   202,   203,   204,   205,   206,   207,
     237,   239,   208,   209,   240,     0,   241,   210,   211,   212,
     213,   242,   214,   245,   215,   216,   217,   246,   255,   256,
     257,   258,   259,   260,   218,   219,   220,   261,   262,   221,
     222,   223,   224,   225,   226,   227,   228,   229,   230,   231,
     238,   247,   263,   248,   249,   250,   251,   254,   264,   265,
     266,   274,   271,   272,   275,   273,   276,   296,   279,   280,
     320,   281,   282,   283,   284,   287,   288,   289,   290,   291,
     321,   292,   293,   294,   295,   299,   300,   325,   301,   303,
     302,   326,   304,   329,   332,   305,   306,   307,   334,   308,
     336,   309,   310,   311,   338,   340,   343,     0,     0,     0,
       0,   312,   313,   315,   314,     0,   268,   316,   317,   318,
     319,     0,   328,   330,   331,   333,   335,   337,     0,   339,
       0,     0,   341
};

static const short yycheck[] =
{
       3,     3,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    40,    41,    77,    42,    43,    44,    45,    46,    47,
      48,    49,    50,    51,    52,    53,    54,    55,    56,    57,
      58,    59,    60,    61,    77,    62,    63,    64,    65,    66,
      67,    68,    69,    79,    77,    81,    73,    77,    80,    78,
      78,    78,    75,    75,    67,    80,    69,    70,    77,    74,
       0,    76,    79,     4,    81,    78,     6,     7,     8,     9,
      10,    68,    69,    80,    71,    72,    73,    79,    79,    81,
      81,    78,    80,    79,     3,    81,    80,    80,    80,    80,
      80,    80,    80,    80,    80,    80,    80,    80,    80,    80,
      80,    80,    80,    80,    80,    80,    80,    80,    80,    80,
      80,    80,    80,     4,     4,    75,     3,     3,    75,     4,
      75,    75,    75,    75,     4,     3,    75,    75,    75,     3,
       3,     3,     3,     3,     3,     3,    75,    75,    75,     3,
     253,     4,   314,    -1,    80,    80,    80,    80,    80,    80,
      80,    80,    80,    80,    80,    80,    80,    80,    80,    80,
      80,     4,    80,    80,    80,    80,    80,    80,    80,    80,
      80,    80,    80,    80,    80,    80,    80,    80,    80,    80,
      80,    80,     3,    81,    81,    81,    81,    81,    81,    81,
       4,     3,    81,    81,     3,    -1,     4,    81,    81,    81,
      81,     4,    81,     4,    81,    81,    81,     4,     4,     4,
       4,     4,     4,     4,    81,    81,    81,     4,     4,    81,
      81,    81,    81,    81,    81,    81,    81,    81,    81,    81,
      75,    75,     3,    75,    75,    75,    75,    75,    75,     4,
       3,    75,     4,     3,    75,     4,     4,     4,    81,    81,
       4,    81,    81,    81,    81,    81,    81,    81,    81,    81,
       4,    81,    81,    81,    81,    81,    81,     3,    81,    79,
      81,     4,    79,     4,     3,    81,    81,    81,     3,    81,
       3,    81,    81,    81,     3,     3,     0,    -1,    -1,    -1,
      -1,    81,    81,    81,    79,    -1,    76,    81,    81,    81,
      81,    -1,    81,    81,    79,    79,    79,    79,    -1,    79,
      -1,    -1,    81
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "/usr/share/bison/bison.simple"

/* Skeleton output parser for bison,

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002 Free Software
   Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* This is the parser code that is written into each bison parser when
   the %semantic_parser declaration is not specified in the grammar.
   It was written by Richard Stallman by simplifying the hairy parser
   used when %semantic_parser is specified.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

#if ! defined (yyoverflow) || defined (YYERROR_VERBOSE)

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# if YYSTACK_USE_ALLOCA
#  define YYSTACK_ALLOC alloca
# else
#  ifndef YYSTACK_USE_ALLOCA
#   if defined (alloca) || defined (_ALLOCA_H)
#    define YYSTACK_ALLOC alloca
#   else
#    ifdef __GNUC__
#     define YYSTACK_ALLOC __builtin_alloca
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning. */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
# else
#  if defined (__STDC__) || defined (__cplusplus)
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   define YYSIZE_T size_t
#  endif
#  define YYSTACK_ALLOC malloc
#  define YYSTACK_FREE free
# endif
#endif /* ! defined (yyoverflow) || defined (YYERROR_VERBOSE) */


#if (! defined (yyoverflow) \
     && (! defined (__cplusplus) \
	 || (YYLTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  short yyss;
  YYSTYPE yyvs;
# if YYLSP_NEEDED
  YYLTYPE yyls;
# endif
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAX (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# if YYLSP_NEEDED
#  define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short) + sizeof (YYSTYPE) + sizeof (YYLTYPE))	\
      + 2 * YYSTACK_GAP_MAX)
# else
#  define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short) + sizeof (YYSTYPE))				\
      + YYSTACK_GAP_MAX)
# endif

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  register YYSIZE_T yyi;		\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (0)
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAX;	\
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (0)

#endif


#if ! defined (YYSIZE_T) && defined (__SIZE_TYPE__)
# define YYSIZE_T __SIZE_TYPE__
#endif
#if ! defined (YYSIZE_T) && defined (size_t)
# define YYSIZE_T size_t
#endif
#if ! defined (YYSIZE_T)
# if defined (__STDC__) || defined (__cplusplus)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# endif
#endif
#if ! defined (YYSIZE_T)
# define YYSIZE_T unsigned int
#endif

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0
#define YYACCEPT	goto yyacceptlab
#define YYABORT 	goto yyabortlab
#define YYERROR		goto yyerrlab1
/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */
#define YYFAIL		goto yyerrlab
#define YYRECOVERING()  (!!yyerrstatus)
#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yychar1 = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { 								\
      yyerror ("syntax error: cannot back up");			\
      YYERROR;							\
    }								\
while (0)

#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Compute the default location (before the actions
   are run).

   When YYLLOC_DEFAULT is run, CURRENT is set the location of the
   first token.  By default, to implement support for ranges, extend
   its range to the last symbol.  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)       	\
   Current.last_line   = Rhs[N].last_line;	\
   Current.last_column = Rhs[N].last_column;
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#if YYPURE
# if YYLSP_NEEDED
#  ifdef YYLEX_PARAM
#   define YYLEX		yylex (&yylval, &yylloc, YYLEX_PARAM)
#  else
#   define YYLEX		yylex (&yylval, &yylloc)
#  endif
# else /* !YYLSP_NEEDED */
#  ifdef YYLEX_PARAM
#   define YYLEX		yylex (&yylval, YYLEX_PARAM)
#  else
#   define YYLEX		yylex (&yylval)
#  endif
# endif /* !YYLSP_NEEDED */
#else /* !YYPURE */
# define YYLEX			yylex ()
#endif /* !YYPURE */


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (0)
/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
#endif /* !YYDEBUG */

/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   SIZE_MAX < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#if YYMAXDEPTH == 0
# undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif

#ifdef YYERROR_VERBOSE

# ifndef yystrlen
#  if defined (__GLIBC__) && defined (_STRING_H)
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
#   if defined (__STDC__) || defined (__cplusplus)
yystrlen (const char *yystr)
#   else
yystrlen (yystr)
     const char *yystr;
#   endif
{
  register const char *yys = yystr;

  while (*yys++ != '\0')
    continue;

  return yys - yystr - 1;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined (__GLIBC__) && defined (_STRING_H) && defined (_GNU_SOURCE)
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
#   if defined (__STDC__) || defined (__cplusplus)
yystpcpy (char *yydest, const char *yysrc)
#   else
yystpcpy (yydest, yysrc)
     char *yydest;
     const char *yysrc;
#   endif
{
  register char *yyd = yydest;
  register const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif
#endif

#line 315 "/usr/share/bison/bison.simple"


/* The user can define YYPARSE_PARAM as the name of an argument to be passed
   into yyparse.  The argument should have type void *.
   It should actually point to an object.
   Grammar actions can access the variable by casting it
   to the proper pointer type.  */

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
#  define YYPARSE_PARAM_ARG void *YYPARSE_PARAM
#  define YYPARSE_PARAM_DECL
# else
#  define YYPARSE_PARAM_ARG YYPARSE_PARAM
#  define YYPARSE_PARAM_DECL void *YYPARSE_PARAM;
# endif
#else /* !YYPARSE_PARAM */
# define YYPARSE_PARAM_ARG
# define YYPARSE_PARAM_DECL
#endif /* !YYPARSE_PARAM */

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
# ifdef YYPARSE_PARAM
int yyparse (void *);
# else
int yyparse (void);
# endif
#endif

/* YY_DECL_VARIABLES -- depending whether we use a pure parser,
   variables are global, or local to YYPARSE.  */

#define YY_DECL_NON_LSP_VARIABLES			\
/* The lookahead symbol.  */				\
int yychar;						\
							\
/* The semantic value of the lookahead symbol. */	\
YYSTYPE yylval;						\
							\
/* Number of parse errors so far.  */			\
int yynerrs;

#if YYLSP_NEEDED
# define YY_DECL_VARIABLES			\
YY_DECL_NON_LSP_VARIABLES			\
						\
/* Location data for the lookahead symbol.  */	\
YYLTYPE yylloc;
#else
# define YY_DECL_VARIABLES			\
YY_DECL_NON_LSP_VARIABLES
#endif


/* If nonreentrant, generate the variables here. */

#if !YYPURE
YY_DECL_VARIABLES
#endif  /* !YYPURE */

int
yyparse (YYPARSE_PARAM_ARG)
     YYPARSE_PARAM_DECL
{
  YYPARSE_LOCAL_DECL
  /* If reentrant, generate the variables here. */
#if YYPURE
  YY_DECL_VARIABLES
#endif  /* !YYPURE */

  register int yystate;
  register int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Lookahead token as an internal (translated) token number.  */
  int yychar1 = 0;

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack. */
  short	yyssa[YYINITDEPTH];
  short *yyss = yyssa;
  register short *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  register YYSTYPE *yyvsp;

#if YYLSP_NEEDED
  /* The location stack.  */
  YYLTYPE yylsa[YYINITDEPTH];
  YYLTYPE *yyls = yylsa;
  YYLTYPE *yylsp;
#endif

#if YYLSP_NEEDED
# define YYPOPSTACK   (yyvsp--, yyssp--, yylsp--)
#else
# define YYPOPSTACK   (yyvsp--, yyssp--)
#endif

  YYSIZE_T yystacksize = YYINITDEPTH;


  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;
#if YYLSP_NEEDED
  YYLTYPE yyloc;
#endif

  /* When reducing, the number of symbols on the RHS of the reduced
     rule. */
  int yylen;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;
#if YYLSP_NEEDED
  yylsp = yyls;
#endif
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed. so pushing a state here evens the stacks.
     */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyssp >= yyss + yystacksize - 1)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack. Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	short *yyss1 = yyss;

	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  */
# if YYLSP_NEEDED
	YYLTYPE *yyls1 = yyls;
	/* This used to be a conditional around just the two extra args,
	   but that might be undefined if yyoverflow is a macro.  */
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yyls1, yysize * sizeof (*yylsp),
		    &yystacksize);
	yyls = yyls1;
# else
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yystacksize);
# endif
	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyoverflowlab;
# else
      /* Extend the stack our own way.  */
      if (yystacksize >= YYMAXDEPTH)
	goto yyoverflowlab;
      yystacksize *= 2;
      if (yystacksize > YYMAXDEPTH)
	yystacksize = YYMAXDEPTH;

      {
	short *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyoverflowlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);
# if YYLSP_NEEDED
	YYSTACK_RELOCATE (yyls);
# endif
# undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;
#if YYLSP_NEEDED
      yylsp = yyls + yysize - 1;
#endif

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyssp >= yyss + yystacksize - 1)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* yychar is either YYEMPTY or YYEOF
     or a valid token in external form.  */

  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  /* Convert token to internal form (in yychar1) for indexing tables with */

  if (yychar <= 0)		/* This means end of input. */
    {
      yychar1 = 0;
      yychar = YYEOF;		/* Don't call YYLEX any more */

      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yychar1 = YYTRANSLATE (yychar);

#if YYDEBUG
     /* We have to keep this `#if YYDEBUG', since we use variables
	which are defined only if `YYDEBUG' is set.  */
      if (yydebug)
	{
	  YYFPRINTF (stderr, "Next token is %d (%s",
		     yychar, yytname[yychar1]);
	  /* Give the individual parser a way to print the precise
	     meaning of a token, for further debugging info.  */
# ifdef YYPRINT
	  YYPRINT (stderr, yychar, yylval);
# endif
	  YYFPRINTF (stderr, ")\n");
	}
#endif
    }

  yyn += yychar1;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != yychar1)
    goto yydefault;

  yyn = yytable[yyn];

  /* yyn is what to do for this token type in this state.
     Negative => reduce, -yyn is rule number.
     Positive => shift, yyn is new state.
       New state is final state => don't bother to shift,
       just return success.
     0, or most negative number => error.  */

  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrlab;

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */
  YYDPRINTF ((stderr, "Shifting token %d (%s), ",
	      yychar, yytname[yychar1]));

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;
#if YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  yystate = yyn;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to the semantic value of
     the lookahead token.  This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];

#if YYLSP_NEEDED
  /* Similarly for the default location.  Let the user run additional
     commands if for instance locations are ranges.  */
  yyloc = yylsp[1-yylen];
  YYLLOC_DEFAULT (yyloc, (yylsp - yylen), yylen);
#endif

#if YYDEBUG
  /* We have to keep this `#if YYDEBUG', since we use variables which
     are defined only if `YYDEBUG' is set.  */
  if (yydebug)
    {
      int yyi;

      YYFPRINTF (stderr, "Reducing via rule %d (line %d), ",
		 yyn, yyrline[yyn]);

      /* Print the symbols being reduced, and their result.  */
      for (yyi = yyprhs[yyn]; yyrhs[yyi] > 0; yyi++)
	YYFPRINTF (stderr, "%s ", yytname[yyrhs[yyi]]);
      YYFPRINTF (stderr, " -> %s\n", yytname[yyr1[yyn]]);
    }
#endif

  switch (yyn) {

case 1:
#line 215 "conf-parse.y"
{}
    break;
case 2:
#line 216 "conf-parse.y"
{}
    break;
case 3:
#line 219 "conf-parse.y"
{}
    break;
case 4:
#line 220 "conf-parse.y"
{server=serv_presets; }
    break;
case 5:
#line 221 "conf-parse.y"
{
				/* if (!server.atup_a) {
					yyerror("bad ip or no ip specified in section");
					YYERROR;
				} */
				if (server.uptest==C_EXEC) {
					if (!server.uptest_cmd) {
						yyerror("you must specify uptest_cmd if you specify uptest=exec!");
						YYERROR;
					}
				}
				{
				  int j;
				  for(j=0;j<DA_NEL(server.atup_a);++j)
				    DA_INDEX(server.atup_a,j).is_up=server.preset;
				}
				if(server.interval<0) global.onquery=1;

				add_server(&server);
			}
    break;
case 6:
#line 242 "conf-parse.y"
{
					c_owner[0]='\0';
					c_name[0]='\0';
					c_ttl=86400;
					c_flags=DF_LOCAL;
					
				}
    break;
case 7:
#line 250 "conf-parse.y"
{
				if (!c_owner[0] || !c_name[0]) {
				        yyerror("must specify owner and name in a rr record.");
					YYERROR;
				}

				/* add the authority */
				add_cent_rr(&c_cent, c_ttl,0,CF_LOCAL, strlen(c_owner)+1, c_owner, T_NS  DBG0);
				add_cache(&c_cent);
				free_cent(&c_cent  DBG0);
			}
    break;
case 8:
#line 262 "conf-parse.y"
{
					htp=0;
					hdtp=0;
					c_name[0]='\0';
					c_ttl=86400;
				}
    break;
case 9:
#line 269 "conf-parse.y"
{
			}
    break;
case 10:
#line 272 "conf-parse.y"
{
					c_owner[0]='\0';
					c_ttl=86400;
					c_flags=DF_LOCAL;
					c_aliases=0;
					
				}
    break;
case 11:
#line 280 "conf-parse.y"
{
				if (c_owner[0]=='\0') {
					yyerror("you must specify owner in a source record.");
					YYERROR;
				}
			}
    break;
case 12:
#line 288 "conf-parse.y"
{}
    break;
case 13:
#line 289 "conf-parse.y"
{}
    break;
case 14:
#line 293 "conf-parse.y"
{
			  char *e;

			  if ((e=zone_add(&global.deleg_only_zones,yyvsp[0].nm))!=NULL) {
			    yyerror(e);
			    YYERROR;
			  }
			  free(yyvsp[0].nm);
			}
    break;
case 15:
#line 303 "conf-parse.y"
{
			  char *e;

			  if ((e=zone_add(&global.deleg_only_zones,yyvsp[0].nm))!=NULL) {
			    yyerror(e);
			    YYERROR;
			  }
			  free(yyvsp[0].nm);
			}
    break;
case 16:
#line 315 "conf-parse.y"
{
				if (yyvsp[-1].num==C_OFF) {
					global.perm_cache=0;
				} else {
					yyerror("bad qualifier in perm_cache= option.");
					YYERROR;
				}
			}
    break;
case 17:
#line 324 "conf-parse.y"
{
				global.perm_cache=yyvsp[-1].num;
			}
    break;
case 18:
#line 328 "conf-parse.y"
{
				YSTRASSIGN(global.cache_dir, yyvsp[-1].nm);
			}
    break;
case 19:
#line 332 "conf-parse.y"
{
				global.port=yyvsp[-1].num;
			}
    break;
case 20:
#line 336 "conf-parse.y"
{
				if (!str2pdnsd_a(yyvsp[-1].nm,&global.a)) {
					yyerror("bad ip in server_ip= option.");
					YYERROR;
				}
				free(yyvsp[-1].nm);
 			}
    break;
case 21:
#line 344 "conf-parse.y"
{
				YSTRASSIGN(global.scheme_file, yyvsp[-1].nm);
                        }
    break;
case 22:
#line 348 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					global.lndown_kluge=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in linkdown_kluge= option.");
					YYERROR;
				}
			}
    break;
case 23:
#line 357 "conf-parse.y"
{
				global.max_ttl=yyvsp[-1].num;
			}
    break;
case 24:
#line 361 "conf-parse.y"
{
				global.min_ttl=yyvsp[-1].num;
			}
    break;
case 25:
#line 365 "conf-parse.y"
{
				YSTRNCP(global.run_as, yyvsp[-1].nm, "run_as");
				free(yyvsp[-1].nm);
			}
    break;
case 26:
#line 370 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					global.strict_suid=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in strict_setuid= option.");
					YYERROR;
				}
			}
    break;
case 27:
#line 379 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					global.paranoid=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in paranoid= option.");
					YYERROR;
				}
			}
    break;
case 28:
#line 388 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					stat_pipe=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in status_pipe= option.");
					YYERROR;
				}
			}
    break;
case 29:
#line 397 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					daemon_p=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in daemon= option.");
					YYERROR;
				}
			}
    break;
case 30:
#line 406 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					notcp=(yyvsp[-1].num==C_OFF);
				} else {
					yyerror("bad qualifier in tcp_server= option.");
					YYERROR;
				}
			}
    break;
case 31:
#line 415 "conf-parse.y"
{
			  YSTRASSIGN(pidfile,yyvsp[-1].nm);
			}
    break;
case 32:
#line 419 "conf-parse.y"
{
				verbosity=yyvsp[-1].num;
			}
    break;
case 33:
#line 423 "conf-parse.y"
{
				if (yyvsp[-1].num==TCP_ONLY || yyvsp[-1].num==UDP_ONLY || yyvsp[-1].num==TCP_UDP) {
#ifdef NO_TCP_QUERIES
					if (yyvsp[-1].num==TCP_ONLY) {
						yyerror("the tcp_only option is only available when pdnsd is compiled with TCP support.");
						YYERROR;
					}
					else
#endif
#ifdef NO_UDP_QUERIES
					if (yyvsp[-1].num==UDP_ONLY) {
						yyerror("the udp_only option is only available when pdnsd is compiled with UDP support.");
						YYERROR;
					}
					else
#endif
#if defined(NO_TCP_QUERIES) || defined(NO_UDP_QUERIES)
					if (yyvsp[-1].num==TCP_UDP) {
						yyerror("the tcp_udp option is only available when pdnsd is compiled with both TCP and UDP support.");
						YYERROR;
					}
					else
#endif
					query_method=yyvsp[-1].num;
				} else {
					yyerror("bad qualifier in query_method= option.");
					YYERROR;
				}
			}
    break;
case 34:
#line 453 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
#if defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
					run_ipv4=(yyvsp[-1].num==C_ON);
					run_ipv6=(yyvsp[-1].num!=C_ON);
#else
					yyerror("the run_ipv4 option is only available when pdnsd is compiled with IPv4 AND IPv6 support.");
					YYERROR;
#endif
				} else {
					yyerror("bad qualifier in run_ipv4= option.");
					YYERROR;
				}
			}
    break;
case 35:
#line 468 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					debug_p=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in debug= option.");
					YYERROR;
				}
			}
    break;
case 36:
#line 477 "conf-parse.y"
{
				global.ctl_perms=yyvsp[-1].num;
			}
    break;
case 37:
#line 481 "conf-parse.y"
{
				global.proc_limit=yyvsp[-1].num;
			}
    break;
case 38:
#line 485 "conf-parse.y"
{
				global.procq_limit=yyvsp[-1].num;
			}
    break;
case 39:
#line 489 "conf-parse.y"
{
				global.tcp_qtimeout=yyvsp[-1].num;
			}
    break;
case 40:
#line 493 "conf-parse.y"
{
				global.par_queries=yyvsp[-1].num;
			}
    break;
case 41:
#line 497 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					global.rnd_recs=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in randomize_recs= option.");
					YYERROR;
				}
			}
    break;
case 42:
#line 506 "conf-parse.y"
{
				global.neg_ttl=yyvsp[-1].num;
			}
    break;
case 43:
#line 510 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF || yyvsp[-1].num==C_AUTH) {
					global.neg_rrs_pol=yyvsp[-1].num;
				} else {
					yyerror("bad qualifier in neg_rrs_pol= option.");
					YYERROR;
				}
			}
    break;
case 44:
#line 519 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF || yyvsp[-1].num==C_AUTH) {
					global.neg_domain_pol=yyvsp[-1].num;
				} else {
					yyerror("bad qualifier in neg_domain_pol= option.");
					YYERROR;
				}
			}
    break;
case 45:
#line 528 "conf-parse.y"
{
				if(yyvsp[-1].num>65536||yyvsp[-1].num<1024) {
					yyerror("bad value for query_port_start.");
					YYERROR;
				} else if (global.query_port_end <= yyvsp[-1].num) {
					yyerror("query_port_end must be greater than query_port_start.");
					YYERROR;
				} else {
					global.query_port_start=yyvsp[-1].num;
				}
			}
    break;
case 46:
#line 540 "conf-parse.y"
{
				if(yyvsp[-1].num>65536||yyvsp[-1].num<1024) {
					yyerror("bad value for query_port_end.");
					YYERROR;
				} else if (global.query_port_start >= yyvsp[-1].num) {
					yyerror("query_port_end must be greater than query_port_start.");
					YYERROR;
				} else {
					global.query_port_end=yyvsp[-1].num;
				}
			}
    break;
case 47:
#line 551 "conf-parse.y"
{}
    break;
case 48:
#line 554 "conf-parse.y"
{}
    break;
case 49:
#line 555 "conf-parse.y"
{}
    break;
case 50:
#line 559 "conf-parse.y"
{
			  char *e;

			  if ((e=addr_add(&server,yyvsp[0].nm))!=NULL) {
			    yyerror(e);
			    YYERROR;
			  }
			  free(yyvsp[0].nm);
			}
    break;
case 51:
#line 569 "conf-parse.y"
{
			  char *e;

			  if ((e=addr_add(&server,yyvsp[0].nm))!=NULL) {
			    yyerror(e);
			    YYERROR;
			  }
			  free(yyvsp[0].nm);
			}
    break;
case 52:
#line 581 "conf-parse.y"
{
				char *e;
				
				if ((e=slist_add(&server,yyvsp[0].nm,in_or_excluded))!=NULL) {
					yyerror(e);
					YYERROR;
				}
				free(yyvsp[0].nm);
			}
    break;
case 53:
#line 591 "conf-parse.y"
{
				char *e;
				
				if ((e=slist_add(&server,yyvsp[0].nm,in_or_excluded))!=NULL) {
					yyerror(e);
					YYERROR;
				}
				free(yyvsp[0].nm);
			}
    break;
case 54:
#line 602 "conf-parse.y"
{}
    break;
case 55:
#line 605 "conf-parse.y"
{
				server.port=yyvsp[-1].num;
			}
    break;
case 56:
#line 609 "conf-parse.y"
{
				YSTRNCP(server.scheme, yyvsp[-1].nm, "scheme");
				free(yyvsp[-1].nm);
			}
    break;
case 57:
#line 614 "conf-parse.y"
{
 				if (yyvsp[-1].num==C_PING || yyvsp[-1].num==C_NONE || yyvsp[-1].num==C_IF || yyvsp[-1].num==C_EXEC || yyvsp[-1].num==C_DEV || yyvsp[-1].num==C_DIALD) {
					server.uptest=yyvsp[-1].num;
				} else {
					yyerror("bad qualifier in uptest= option.");
					YYERROR;
				}
			}
    break;
case 58:
#line 623 "conf-parse.y"
{
				server.timeout=yyvsp[-1].num;
			}
    break;
case 59:
#line 627 "conf-parse.y"
{
				server.ping_timeout=yyvsp[-1].num;
			}
    break;
case 60:
#line 631 "conf-parse.y"
{
				if (!str2pdnsd_a(yyvsp[-1].nm,&server.ping_a)) {
					yyerror("bad ip in ping_ip= option.");
					YYERROR;
				}
				free(yyvsp[-1].nm);
			}
    break;
case 61:
#line 639 "conf-parse.y"
{
				YSTRASSIGN(server.uptest_cmd, yyvsp[-1].nm);
			}
    break;
case 62:
#line 643 "conf-parse.y"
{
				YSTRASSIGN(server.uptest_cmd, yyvsp[-3].nm);
				YSTRNCP(server.uptest_usr, yyvsp[-1].nm, "uptest_cmd");
				free(yyvsp[-1].nm);
			}
    break;
case 63:
#line 649 "conf-parse.y"
{
				server.interval=yyvsp[-1].num;
			}
    break;
case 64:
#line 653 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ONQUERY) {
					server.interval=-1;
				} else {
					yyerror("bad qualifier in interval= option.");
					YYERROR;
				}
			}
    break;
case 65:
#line 662 "conf-parse.y"
{
				YSTRNCP(server.interface, yyvsp[-1].nm, "interface");
				free(yyvsp[-1].nm);
			}
    break;
case 66:
#line 667 "conf-parse.y"
{
				YSTRNCP(server.device, yyvsp[-1].nm, "device");
				free(yyvsp[-1].nm);
  			}
    break;
case 67:
#line 672 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					server.purge_cache=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in purge_cache= option.");
					YYERROR;
				}
			}
    break;
case 68:
#line 681 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					server.nocache=(yyvsp[-1].num==C_OFF);
				} else {
					yyerror("bad qualifier in caching= option.");
					YYERROR;
				}
			}
    break;
case 69:
#line 690 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					server.lean_query=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in lean_query= option.");
					YYERROR;
				}
			}
    break;
case 70:
#line 699 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					server.preset=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in preset= option.");
					YYERROR;
				}
			}
    break;
case 71:
#line 708 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					server.is_proxy=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in proxy_only= option.");
					YYERROR;
				}
			}
    break;
case 72:
#line 717 "conf-parse.y"
{
				if (yyvsp[-1].num==C_INCLUDED || yyvsp[-1].num==C_EXCLUDED || yyvsp[-1].num==C_SIMPLE_ONLY || yyvsp[-1].num==C_FQDN_ONLY) {
					server.policy=yyvsp[-1].num;
				} else {
					yyerror("bad qualifier in policy= option.");
					YYERROR;
				}
			}
    break;
case 73:
#line 725 "conf-parse.y"
{in_or_excluded=C_INCLUDED;}
    break;
case 74:
#line 725 "conf-parse.y"
{}
    break;
case 75:
#line 726 "conf-parse.y"
{in_or_excluded=C_EXCLUDED;}
    break;
case 76:
#line 726 "conf-parse.y"
{}
    break;
case 77:
#line 728 "conf-parse.y"
{
				YSTRNCP(server.label, yyvsp[-1].nm, "label");
				free(yyvsp[-1].nm);
			}
    break;
case 78:
#line 734 "conf-parse.y"
{}
    break;
case 79:
#line 735 "conf-parse.y"
{}
    break;
case 80:
#line 739 "conf-parse.y"
{
				char *e;
				unsigned char buf[256];
				/* if (strlen($3)>255) {
					yyerror("name too long.");
					YYERROR;
				} */
				if ((e=parsestr2rhn(yyvsp[-1].nm,buf))!=NULL) {
					yyerror(e);
					YYERROR;
				}
				YSTRNCP(c_name, yyvsp[-1].nm, "name");
				{ /* add a dot at the end */
					int len=strlen(c_name);
					if(len==0 || c_name[len-1]!='.') {
						c_name[len]='.'; c_name[len+1]=0;
					}
				}
				if (c_owner[0]) {
					if (!init_cent(&c_cent, c_name, c_flags, time(NULL), 0  DBG0)) {
						fprintf(stderr,"Out of memory.\n");
						YYERROR;
					}
				}
				free(yyvsp[-1].nm);
			}
    break;
case 81:
#line 766 "conf-parse.y"
{
				char *e;
				/* if (strlen($3)>255) {
					yyerror("name too long.");
					YYERROR;
				} */
				if ((e=parsestr2rhn(yyvsp[-1].nm,c_owner))!=NULL) {
					yyerror(e);
					YYERROR;
				}
				if (c_name[0]) {
					if (!init_cent(&c_cent, c_name, c_flags, time(NULL), 0  DBG0)) {
						fprintf(stderr,"Out of memory.\n");
						YYERROR;
					}
				}
				free(yyvsp[-1].nm);
			}
    break;
case 82:
#line 785 "conf-parse.y"
{
				c_ttl=yyvsp[-1].num;
			}
    break;
case 83:
#line 789 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					c_flags=(yyvsp[-1].num==C_ON)?DF_LOCAL:0;
				} else {
					yyerror("Bad qualifier in authrec= option.");
					YYERROR;
				}
			}
    break;
case 84:
#line 798 "conf-parse.y"
{
				int sz,tp;
				struct in_addr ina4;
				pdnsd_a c_a;

				if (!c_owner[0] || !c_name[0]) {
					yyerror("you must specify owner and name before a,ptr and soa records.");
					YYERROR;
				}
				if (inet_aton(yyvsp[-1].nm,&ina4)) {
#if !defined(ENABLE_IPV4) 
					yyerror("bad ip in a= option.");
					YYERROR;
#else
					c_a.ipv4=ina4;
					sz=sizeof(struct in_addr);
					tp=T_A;
#endif
				} else {
#if defined(DNS_NEW_RRS) && defined(ENABLE_IPV6)
					int err;

					if ((err=inet_pton(AF_INET6,yyvsp[-1].nm,&c_a.ipv6))!=1) {
						if (err==0) {
							yyerror("bad ip in a= option.");
							YYERROR;
						} else {
							perror("inet_pton");
							YYERROR;
						}
					} else {
						tp=T_AAAA;
						sz=sizeof(struct in6_addr);
					}
#else
					yyerror("bad ip in a= option.");
					YYERROR;
#endif
				}
				add_cent_rr(&c_cent,c_ttl,0,CF_LOCAL,sz,&c_a,tp  DBG0);
				free(yyvsp[-1].nm);
			}
    break;
case 85:
#line 841 "conf-parse.y"
{
				char *e;
				unsigned char c_ptr[256];

				if (!c_owner[0] || !c_name[0]) {
					yyerror("you must specify owner and name before a,ptr and soa records.");
					YYERROR;
				}
				/* if (strlen($3)>255) {
					yyerror("name too long.");
					YYERROR;
				} */
				if ((e=parsestr2rhn(yyvsp[-1].nm,c_ptr))!=NULL) {
					yyerror(e);
					YYERROR;
				}
				add_cent_rr(&c_cent,c_ttl,0,CF_LOCAL,rhnlen(c_ptr),c_ptr,T_PTR  DBG0);
				free(yyvsp[-1].nm);
			}
    break;
case 86:
#line 861 "conf-parse.y"
{
				char *e;
				unsigned char c_ptr[256];
				unsigned char buf[532];
				uint16_t ts;

				if (!c_owner[0] || !c_name[0]) {
					yyerror("you must specify owner and name before mx records.");
					YYERROR;
				}
				/* if (strlen($3)>255) {
					yyerror("name too long.");
					YYERROR;
				} */
				if ((e=parsestr2rhn(yyvsp[-3].nm,c_ptr))!=NULL) {
					yyerror(e);
					YYERROR;
				}
				memset(buf,0,sizeof(buf));
				ts=htons(yyvsp[-1].num);
				memcpy(buf,&ts,2);
				rhncpy(buf+2,c_ptr);
				add_cent_rr(&c_cent,c_ttl,0,CF_LOCAL,rhnlen(c_ptr)+2,buf,T_MX  DBG0);
				free(yyvsp[-3].nm);
			}
    break;
case 87:
#line 887 "conf-parse.y"
{
				char *e;
				unsigned char c_ptr[256];

				if (!c_owner[0] || !c_name[0]) {
					yyerror("you must specify owner and name before cname records.");
					YYERROR;
				}
				/* if (strlen($3)>255) {
					yyerror("name too long.");
					YYERROR;
				} */
				if ((e=parsestr2rhn(yyvsp[-1].nm,c_ptr))!=NULL) {
					yyerror(e);
					YYERROR;
				}
				add_cent_rr(&c_cent,c_ttl,0,CF_LOCAL,rhnlen(c_ptr),c_ptr,T_CNAME  DBG0);
				free(yyvsp[-1].nm);
			}
    break;
case 88:
#line 907 "conf-parse.y"
{
				char *e;
				unsigned char c_soa_owner[256];
			        unsigned char c_soa_r[256];
				unsigned char buf[532];
				soa_r_t c_soa;
				int idx;

				if (!c_owner[0] || !c_name[0]) {
					yyerror("you must specify owner and name before a, ptr and soa records.");
					YYERROR;
				}
				/* if (strlen($3)>255) {
					yyerror("name too long.");
					YYERROR;
				} */
				if ((e=parsestr2rhn(yyvsp[-13].nm,c_soa_owner))!=NULL) {
					yyerror(e);
					YYERROR;
				}
				/* if (strlen($5)>255) {
					yyerror("name too long.");
					YYERROR;
				} */
				if ((e=parsestr2rhn(yyvsp[-11].nm,c_soa_r))!=NULL) {
					yyerror(e);
					YYERROR;
				}
				c_soa.serial=htonl(yyvsp[-9].num);
				c_soa.refresh=htonl(yyvsp[-7].num);
				c_soa.retry=htonl(yyvsp[-5].num);
				c_soa.expire=htonl(yyvsp[-3].num);
				c_soa.minimum=htonl(yyvsp[-1].num);
				memset(buf,0,sizeof(buf));
				idx=rhncpy(buf,c_soa_owner);
				idx+=rhncpy(buf+idx,c_soa_r);
				memcpy(buf+idx,&c_soa,sizeof(soa_r_t));
				idx+=sizeof(soa_r_t);
				add_cent_rr(&c_cent,c_ttl,0,CF_LOCAL,idx,buf,T_SOA  DBG0);
				free(yyvsp[-13].nm);
				free(yyvsp[-11].nm);
			}
    break;
case 89:
#line 951 "conf-parse.y"
{}
    break;
case 90:
#line 952 "conf-parse.y"
{}
    break;
case 91:
#line 956 "conf-parse.y"
{
				char *e;
				/* if (strlen($3)>255) {
					yyerror("name too long.");
					YYERROR;
				} */
				if ((e=parsestr2rhn(yyvsp[-1].nm,c_owner))!=NULL) {
					yyerror(e);
					YYERROR;
				}
				free(yyvsp[-1].nm);
			}
    break;
case 92:
#line 969 "conf-parse.y"
{
				c_ttl=yyvsp[-1].num;
			}
    break;
case 93:
#line 973 "conf-parse.y"
{
				if (!c_owner[0]) {
					yyerror("you must specify owner before file= in source records.");
					YYERROR;
				}
				{
				  char *errstr;
				  if (!read_hosts(yyvsp[-1].nm, c_owner, c_ttl, c_flags, c_aliases,&errstr)) {
					fprintf(stderr,"%s\n",errstr?:"Out of memory");
					if(errstr) free(errstr);
				  }
				}
				free(yyvsp[-1].nm);
			}
    break;
case 94:
#line 988 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					c_aliases=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("Bad qualifier in serve_aliases= option.");
					YYERROR;
				}
			}
    break;
case 95:
#line 997 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					c_flags=(yyvsp[-1].num==C_ON)?DF_LOCAL:0;
				} else {
					yyerror("Bad qualifier in authrec= option.");
					YYERROR;
				}
			}
    break;
case 96:
#line 1008 "conf-parse.y"
{}
    break;
case 97:
#line 1009 "conf-parse.y"
{}
    break;
case 98:
#line 1014 "conf-parse.y"
{
				char *e;
				unsigned char buf[256];
				if ((e=parsestr2rhn(yyvsp[-1].nm,buf))!=NULL) {
					yyerror(e);
					YYERROR;
				}
				YSTRNCP(c_name,yyvsp[-1].nm, "name");
				{ /* add a dot at the end */
					int len=strlen(c_name);
					if(len==0 || c_name[len-1]!='.') {
						c_name[len]='.'; c_name[len+1]=0;
					}
				}
				free(yyvsp[-1].nm);
			}
    break;
case 99:
#line 1031 "conf-parse.y"
{
				c_ttl=yyvsp[-1].num;
			}
    break;
case 100:
#line 1035 "conf-parse.y"
{
				if (htp) {
					yyerror("You may not specify types=domain together with other types!");
					YYERROR;
				}
				if (!c_name[0]) {
					yyerror("you must specify a name before the types= option.");
					YYERROR;
				}
				hdtp=1;
				if (!init_cent(&c_cent, c_name, DF_LOCAL|DF_NEGATIVE, time(NULL), c_ttl  DBG0)) {
					fprintf(stderr,"Out of memory.\n");
					YYERROR;
				}
				add_cache(&c_cent);
				free_cent(&c_cent  DBG0);
			}
    break;
case 101:
#line 1053 "conf-parse.y"
{
			}
    break;
case 102:
#line 1057 "conf-parse.y"
{}
    break;
case 103:
#line 1058 "conf-parse.y"
{}
    break;
case 104:
#line 1062 "conf-parse.y"
{
				if (hdtp) {
					yyerror("You may not specify types=domain together with other types!.");
					YYERROR;
				}
				htp=1;
				if (!c_name[0]) {
					yyerror("you must specify a name before the types= option.");
					YYERROR;
				}
				if (!init_cent(&c_cent, c_name, 0, time(NULL), 0  DBG0)) {
					fprintf(stderr,"Out of memory.\n");
					YYERROR;
				}
				if (!add_cent_rrset(&c_cent,yyvsp[0].num,c_ttl,0,CF_LOCAL|CF_NEGATIVE,0  DBG0)) {
					free_cent(&c_cent  DBG0);
					fprintf(stderr,"Out of memory.\n");
					YYERROR;
				}
				add_cache(&c_cent);
				free_cent(&c_cent  DBG0);
				
			}
    break;
}

#line 705 "/usr/share/bison/bison.simple"


  yyvsp -= yylen;
  yyssp -= yylen;
#if YYLSP_NEEDED
  yylsp -= yylen;
#endif

#if YYDEBUG
  if (yydebug)
    {
      short *yyssp1 = yyss - 1;
      YYFPRINTF (stderr, "state stack now");
      while (yyssp1 != yyssp)
	YYFPRINTF (stderr, " %d", *++yyssp1);
      YYFPRINTF (stderr, "\n");
    }
#endif

  *++yyvsp = yyval;
#if YYLSP_NEEDED
  *++yylsp = yyloc;
#endif

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTBASE] + *yyssp;
  if (yystate >= 0 && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTBASE];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;

#ifdef YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (yyn > YYFLAG && yyn < YYLAST)
	{
	  YYSIZE_T yysize = 0;
	  char *yymsg;
	  int yyx, yycount;

	  yycount = 0;
	  /* Start YYX at -YYN if negative to avoid negative indexes in
	     YYCHECK.  */
	  for (yyx = yyn < 0 ? -yyn : 0;
	       yyx < (int) (sizeof (yytname) / sizeof (char *)); yyx++)
	    if (yycheck[yyx + yyn] == yyx)
	      yysize += yystrlen (yytname[yyx]) + 15, yycount++;
	  yysize += yystrlen ("parse error, unexpected ") + 1;
	  yysize += yystrlen (yytname[YYTRANSLATE (yychar)]);
	  yymsg = (char *) YYSTACK_ALLOC (yysize);
	  if (yymsg != 0)
	    {
	      char *yyp = yystpcpy (yymsg, "parse error, unexpected ");
	      yyp = yystpcpy (yyp, yytname[YYTRANSLATE (yychar)]);

	      if (yycount < 5)
		{
		  yycount = 0;
		  for (yyx = yyn < 0 ? -yyn : 0;
		       yyx < (int) (sizeof (yytname) / sizeof (char *));
		       yyx++)
		    if (yycheck[yyx + yyn] == yyx)
		      {
			const char *yyq = ! yycount ? ", expecting " : " or ";
			yyp = yystpcpy (yyp, yyq);
			yyp = yystpcpy (yyp, yytname[yyx]);
			yycount++;
		      }
		}
	      yyerror (yymsg);
	      YYSTACK_FREE (yymsg);
	    }
	  else
	    yyerror ("parse error; also virtual memory exhausted");
	}
      else
#endif /* defined (YYERROR_VERBOSE) */
	yyerror ("parse error");
    }
  goto yyerrlab1;


/*--------------------------------------------------.
| yyerrlab1 -- error raised explicitly by an action |
`--------------------------------------------------*/
yyerrlab1:
  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      /* return failure if at end of input */
      if (yychar == YYEOF)
	YYABORT;
      YYDPRINTF ((stderr, "Discarding token %d (%s).\n",
		  yychar, yytname[yychar1]));
      yychar = YYEMPTY;
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */

  yyerrstatus = 3;		/* Each real token shifted decrements this */

  goto yyerrhandle;


/*-------------------------------------------------------------------.
| yyerrdefault -- current state does not do anything special for the |
| error token.                                                       |
`-------------------------------------------------------------------*/
yyerrdefault:
#if 0
  /* This is wrong; only states that explicitly want error tokens
     should shift them.  */

  /* If its default is to accept any token, ok.  Otherwise pop it.  */
  yyn = yydefact[yystate];
  if (yyn)
    goto yydefault;
#endif


/*---------------------------------------------------------------.
| yyerrpop -- pop the current state because it cannot handle the |
| error token                                                    |
`---------------------------------------------------------------*/
yyerrpop:
  if (yyssp == yyss)
    YYABORT;
  yyvsp--;
  yystate = *--yyssp;
#if YYLSP_NEEDED
  yylsp--;
#endif

#if YYDEBUG
  if (yydebug)
    {
      short *yyssp1 = yyss - 1;
      YYFPRINTF (stderr, "Error: state stack now");
      while (yyssp1 != yyssp)
	YYFPRINTF (stderr, " %d", *++yyssp1);
      YYFPRINTF (stderr, "\n");
    }
#endif

/*--------------.
| yyerrhandle.  |
`--------------*/
yyerrhandle:
  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yyerrdefault;

  yyn += YYTERROR;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != YYTERROR)
    goto yyerrdefault;

  yyn = yytable[yyn];
  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrpop;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrpop;

  if (yyn == YYFINAL)
    YYACCEPT;

  YYDPRINTF ((stderr, "Shifting error token, "));

  *++yyvsp = yylval;
#if YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

/*---------------------------------------------.
| yyoverflowab -- parser overflow comes here.  |
`---------------------------------------------*/
yyoverflowlab:
  yyerror ("parser stack overflow");
  yyresult = 2;
  /* Fall through.  */

yyreturn:
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  return yyresult;
}
#line 1088 "conf-parse.y"


int yyerror (char *s)
{
#ifdef NO_YYLINENO
	fprintf(stderr, "Error in config file: %s\n",s);
#else
	fprintf(stderr, "Error in config file (line %i): %s\n",yylineno,s);
#endif
	return 0;
}

/* This was originally in conff.c */

/*
 * Add a server (with parameters contained in serv) into the internal server list
 * (in the pointer servers)
 */
/* void add_server(servparm_t *serv)
{
  if (!(servers=DA_GROW1(servers))) {
    fprintf(stderr,"Error: out of memory.\n");
    exit(1);
  }
  DA_LAST(servers)=*serv;
} */

static char *addr_add(servparm_t *sp, char *ipstr)
{
	atup_t *at;
	pdnsd_a addr;

	if(!str2pdnsd_a(ipstr,&addr)) {
		return "bad ip in ip= option.";
	}

	if (!(sp->atup_a=DA_GROW1(sp->atup_a))) {
		return "out of memory!";
	}
	at=&DA_LAST(sp->atup_a);
	at->a = addr;
	at->is_up=0;
	at->i_ts=0;
	return NULL;
}

static char *slist_add(servparm_t *sp, char *nm, int tp)
{
 	slist_t *sl;
	int adddot=0;
	int nmlen=strlen(nm);

	if (nmlen==0 || nm[nmlen-1]!='.') adddot=1;
	if (nmlen+adddot>255)
		return "include/exclude: name too long!";
	if (!(sp->alist=DA_GROW1(sp->alist))) {
		return "out of memory!";
	}
	sl=&DA_LAST(sp->alist);
	sl->rule=tp;

	if (!(sl->domain=malloc(nmlen+adddot+1)))
		return "out of memory!";
	strcpy(sl->domain,nm);
	if(adddot) {
		sl->domain[nmlen]='.';
		sl->domain[nmlen+1]='\0';
	}
	return NULL;
}

static char *zone_add(zone_array *za, char *zone)
{
	char *err;
	unsigned char rhn[256];

	if((err=parsestr2rhn(zone,rhn)))
		return err;
	if(!(*za=DA_GROW1(*za)) || !(DA_LAST(*za)=strdup(rhn)))
		return "out of memory!";
	return NULL;
}
