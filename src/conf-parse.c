#ifndef lint
static char const 
yyrcsid[] = "$FreeBSD: src/usr.bin/yacc/skeleton.c,v 1.28 2000/01/17 02:04:06 bde Exp $";
#endif
#include <stdlib.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX yylex()
#define YYEMPTY -1
#define yyclearin (yychar=(YYEMPTY))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING() (yyerrflag!=0)
static int yygrowstack();
#define YYPREFIX "yy"
#line 2 "conf-parse.y"
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
static char rcsid[]="$Id: conf-parse.y,v 1.36 2001/07/01 21:03:15 tmm Exp $";
#endif

dns_cent_t c_cent;
pdnsd_a c_a;
unsigned char c_soa_owner[256];
unsigned char c_soa_r[256];
soa_r_t c_soa;
unsigned char c_db[256];
unsigned char c_ptr[256];
unsigned char c_owner[256];
unsigned char c_name[256];
time_t c_ttl;
int c_aliases, c_flags;
unsigned char buf[532];
char errbuf[256];
int sz,tp,err;
int hdtp, htp;
struct in_addr ina4;
uint16_t ts;

int idx;

#ifndef NO_YYLINENO
/*
 * This comes from the generated lexer. It is an undocumented variable in lex, and in flex
 * we explicitely switch it on.
 */
extern int yylineno;
#endif

/* Bah. I want strlcpy. */
#define YSTRNCP(dst, src, err) 						\
        do {								\
	        if (!strncp((char *)(dst),(char *)src,sizeof(dst))) {	\
		        yyerror(err": string too long"); 		\
		        YYERROR; 					\
	        } 							\
	} while(0);

#line 79 "conf-parse.y"
typedef union {
long 	      num;
unsigned char *nm;
} YYSTYPE;
#line 99 "y.tab.c"
#define YYERRCODE 256
#define NUMBER 257
#define STRING 258
#define ERROR 259
#define GLOBAL 260
#define SERVER 261
#define RR 262
#define NEG 263
#define SOURCE 264
#define PERM_CACHE 265
#define CACHE_DIR 266
#define SERVER_PORT 267
#define SERVER_IP 268
#define SCHEME_FILE 269
#define LINKDOWN_KLUGE 270
#define MAX_TTL 271
#define MIN_TTL 272
#define RUN_AS 273
#define STRICT_SETUID 274
#define PARANOID 275
#define STATUS_CTL 276
#define DAEMON 277
#define C_TCP_SERVER 278
#define PID_FILE 279
#define C_VERBOSITY 280
#define C_QUERY_METHOD 281
#define RUN_IPV4 282
#define C_DEBUG 283
#define C_CTL_PERMS 284
#define C_PROC_LIMIT 285
#define C_PROCQ_LIMIT 286
#define TCP_QTIMEOUT 287
#define C_PAR_QUERIES 288
#define C_RAND_RECS 289
#define NEG_TTL 290
#define NEG_RRS_POL 291
#define NEG_DOMAIN_POL 292
#define QUERY_PORT_START 293
#define QUERY_PORT_END 294
#define IP 295
#define PORT 296
#define SCHEME 297
#define UPTEST 298
#define TIMEOUT 299
#define PING_TIMEOUT 300
#define PING_IP 301
#define UPTEST_CMD 302
#define INTERVAL 303
#define INTERFACE 304
#define DEVICE 305
#define PURGE_CACHE 306
#define CACHING 307
#define LEAN_QUERY 308
#define PRESET 309
#define PROXY_ONLY 310
#define INCLUDE 311
#define EXCLUDE 312
#define POLICY 313
#define LABEL 314
#define A 315
#define PTR 316
#define MX 317
#define SOA 318
#define CNAME 319
#define NAME 320
#define OWNER 321
#define TTL 322
#define TYPES 323
#define FILET 324
#define SERVE_ALIASES 325
#define AUTHREC 326
#define NDOMAIN 327
#define CONST 328
#define RRTYPE 329
const short yylhs[] = {                                        -1,
    0,    0,   11,    1,   12,    1,   13,    1,   14,    1,
   16,    1,    2,    2,    3,    3,    3,    3,    3,    3,
    3,    3,    3,    3,    3,    3,    3,    3,    3,    3,
    3,    3,    3,    3,    3,    3,    3,    3,    3,    3,
    3,    3,    3,    3,    3,    4,    4,    5,    5,    5,
    5,    5,    5,    5,    5,    5,    5,    5,    5,    5,
    5,    5,    5,    5,    5,    5,    5,    5,    5,    6,
    6,    7,    7,    7,    7,    7,    7,    7,    7,    7,
   15,   15,   17,   17,   17,   17,   17,    8,    8,    9,
    9,    9,    9,   10,   10,   18,   19,
};
const short yylen[] = {                                         2,
    0,    2,    0,    5,    0,    5,    0,    5,    0,    5,
    0,    5,    0,    2,    4,    4,    4,    4,    4,    4,
    4,    4,    4,    4,    4,    4,    4,    4,    4,    4,
    4,    4,    4,    4,    4,    4,    4,    4,    4,    4,
    4,    4,    4,    4,    4,    0,    2,    4,    4,    4,
    4,    4,    4,    4,    4,    6,    4,    4,    4,    4,
    4,    4,    4,    4,    4,    4,    4,    4,    4,    0,
    2,    4,    4,    4,    4,    4,    4,    6,    4,   16,
    0,    2,    4,    4,    4,    4,    4,    0,    2,    4,
    4,    4,    4,    1,    3,    1,    1,
};
const short yydefred[] = {                                      1,
    0,    0,    0,    0,    0,    0,    2,    3,    5,    7,
    9,   11,   13,   46,   70,   88,   81,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    4,   14,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    6,   47,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    8,   71,    0,    0,    0,
   10,   89,    0,    0,    0,    0,    0,   12,   82,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   96,    0,    0,    0,    0,    0,    0,    0,   16,   15,
   17,   18,   19,   20,   21,   22,   23,   24,   25,   26,
   27,   28,   29,   30,   31,   32,   33,   34,   35,   36,
   37,   38,   39,   40,   41,   42,   43,   44,   45,   48,
   49,   50,   51,   52,   53,   54,   55,    0,   57,   58,
   59,   60,   61,   62,   63,   64,   65,   67,   68,   66,
   69,   76,   77,    0,    0,   79,   72,   73,   74,   75,
   90,   91,   92,   93,    0,   83,   84,   85,   86,   87,
    0,    0,    0,   95,   56,   78,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   80,
};
const short yydgoto[] = {                                       1,
    7,   18,   54,   19,   76,   20,   87,   21,   92,  232,
   13,   14,   15,   16,   22,   17,   99,  233,    0,
};
const short yysindex[] = {                                      0,
 -249, -116, -114, -107, -106, -105,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0, -124,  -86, -125,
 -115, -122,  -42,  -40,  -38,  -37,  -36,  -35,  -34,  -33,
  -32,  -31,  -30,  -29,  -28,  -27,  -26,  -25,  -24,  -23,
  -21,  -20,  -19,  -18,  -17,  -16,  -15,  -14,  -13,  -12,
  -11,  -10,    0,    0,   -9,   -8,   -7,   -6,   -5,   -4,
   -3,   -2,   -1,    1,    2,    3,    4,    5,    6,    7,
    8,    9,   10,   11,    0,    0,   13,   15,   16,   17,
   18,   19,   20,   21,   22,    0,    0,   23,   24,   25,
    0,    0,   26,   27,   28,   29,   30,    0,    0, -255,
 -236, -196, -166, -165, -234, -162, -161, -160, -231, -229,
 -228, -227, -226, -155, -153, -223, -222, -221, -149, -148,
 -147, -146, -145, -215, -143, -213, -212, -140, -139, -138,
 -136, -135, -209, -133, -132, -131, -130, -253, -129, -128,
 -206, -202, -197, -195, -194, -126, -123, -192, -121, -120,
 -119, -118,  -87,  -85,  -84,  -83,  -81, -156,  -80,  -78,
 -321,  -77,  -75,  -74, -151, -142,  121,  124,  126,  128,
  129,  130,  139,  147,  170,  171,  172,  173,  174,  175,
  176,  177,  178,  179,  180,  181,  182,  183,  184,  185,
  186,  187,  188,  189,  190,  191,  192,  193,  194,  195,
  196,  197,  198,  199,  -39,  200,  201,  202,  203,  204,
  205,  206,  207,  208,  209,  210,  211,  212,  213,  214,
  230,  231,  217,  218,  219,  220,  221,  222,  223,  224,
    0,  225,  241,  227,  228,  229,  232,  233,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   31,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   33,   35,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  -22,    0,    0,    0,    0,    0,
  235,  236,  252,    0,    0,    0,   40,  254,   42,  256,
   44,  258,   46,  260,   48,  247,    0,
};
const short yyrindex[] = {                                      0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  249,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,
};
const short yygindex[] = {                                      0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   12,
    0,    0,    0,    0,    0,    0,    0,    0,    0,
};
#define YYTABLESIZE 317
const short yytable[] = {                                      86,
   53,  167,   98,  206,  278,  230,    8,  231,    9,   91,
    2,    3,    4,    5,    6,   10,   11,   12,  100,  277,
  101,  169,  102,  103,  104,  105,  106,  107,  108,  109,
  110,  111,  112,  113,  114,  115,  116,  117,   75,  118,
  119,  120,  121,  122,  123,  124,  125,  126,  127,  128,
  129,  130,  131,  132,  133,  134,  135,  136,  137,  138,
  170,  139,  140,  141,  142,  143,  144,  145,  146,  147,
  148,  149,  168,  150,  207,  151,  152,  153,  154,  155,
  156,  157,  158,  159,  160,  161,  162,  163,  164,  165,
  166,  171,  172,  173,  174,  175,  177,  176,  178,  179,
  180,  181,  182,  183,  184,  185,  186,  187,  188,  189,
  190,  191,  192,  193,  194,  195,  196,  197,  201,  198,
  199,  210,  200,  202,  203,  211,  204,  205,  208,  209,
  212,  215,  213,  214,  216,  217,  218,  219,  220,  221,
   23,   24,   25,   26,   27,   28,   29,   30,   31,   32,
   33,   34,   35,   36,   37,   38,   39,   40,   41,   42,
   43,   44,   45,   46,   47,   48,   49,   50,   51,   52,
  222,  227,  223,  224,  225,  226,  237,  228,  229,  239,
  234,  235,  240,  236,  241,  238,  242,  243,  244,   77,
   78,   79,   80,   81,   82,   83,   84,  245,   93,   94,
   85,   95,   96,   97,   88,  246,   89,   90,   55,   56,
   57,   58,   59,   60,   61,   62,   63,   64,   65,   66,
   67,   68,   69,   70,   71,   72,   73,   74,  247,  248,
  249,  250,  251,  252,  253,  254,  255,  256,  257,  258,
  259,  260,  261,  262,  263,  264,  265,  266,  267,  268,
  269,  270,  271,  272,  273,  274,  275,  276,  279,  280,
  281,  282,  283,  284,  285,  286,  287,  288,  289,  290,
  291,  292,  293,  294,  295,  296,  297,  298,  299,  300,
  301,  302,  303,  304,  305,  306,  307,  308,  311,  312,
  309,  310,  313,  315,  316,  317,  318,  319,  320,  321,
  322,  323,  324,  325,  326,  327,  231,   94,    0,    0,
    0,    0,    0,    0,    0,    0,  314,
};
const short yycheck[] = {                                     125,
  125,  257,  125,  257,   44,  327,  123,  329,  123,  125,
  260,  261,  262,  263,  264,  123,  123,  123,   61,   59,
   61,  258,   61,   61,   61,   61,   61,   61,   61,   61,
   61,   61,   61,   61,   61,   61,   61,   61,  125,   61,
   61,   61,   61,   61,   61,   61,   61,   61,   61,   61,
   61,   61,   61,   61,   61,   61,   61,   61,   61,   61,
  257,   61,   61,   61,   61,   61,   61,   61,   61,   61,
   61,   61,  328,   61,  328,   61,   61,   61,   61,   61,
   61,   61,   61,   61,   61,   61,   61,   61,   61,   61,
   61,  258,  258,  328,  257,  257,  328,  258,  328,  328,
  328,  328,  258,  257,  328,  328,  328,  257,  257,  257,
  257,  257,  328,  257,  328,  328,  257,  257,  328,  258,
  257,  328,  258,  257,  257,  328,  258,  258,  258,  258,
  328,  258,  328,  328,  258,  328,  258,  258,  258,  258,
  265,  266,  267,  268,  269,  270,  271,  272,  273,  274,
  275,  276,  277,  278,  279,  280,  281,  282,  283,  284,
  285,  286,  287,  288,  289,  290,  291,  292,  293,  294,
  258,  328,  258,  258,  258,  257,  328,  258,  257,   59,
  258,  257,   59,  258,   59,  328,   59,   59,   59,  315,
  316,  317,  318,  319,  320,  321,  322,   59,  321,  322,
  326,  324,  325,  326,  320,   59,  322,  323,  295,  296,
  297,  298,  299,  300,  301,  302,  303,  304,  305,  306,
  307,  308,  309,  310,  311,  312,  313,  314,   59,   59,
   59,   59,   59,   59,   59,   59,   59,   59,   59,   59,
   59,   59,   59,   59,   59,   59,   59,   59,   59,   59,
   59,   59,   59,   59,   59,   59,   59,   59,   59,   59,
   59,   59,   59,   59,   59,   59,   59,   59,   59,   59,
   59,   59,   59,   44,   44,   59,   59,   59,   59,   59,
   59,   59,   59,   59,   44,   59,   59,   59,  258,  257,
   59,   59,  258,   59,   59,   44,  257,   44,  257,   44,
  257,   44,  257,   44,  257,   59,  329,   59,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  305,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 329
#if YYDEBUG
const char * const yyname[] = {
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,"','",0,0,0,0,0,0,0,0,0,0,0,0,0,0,"';'",0,"'='",0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"NUMBER",
"STRING","ERROR","GLOBAL","SERVER","RR","NEG","SOURCE","PERM_CACHE","CACHE_DIR",
"SERVER_PORT","SERVER_IP","SCHEME_FILE","LINKDOWN_KLUGE","MAX_TTL","MIN_TTL",
"RUN_AS","STRICT_SETUID","PARANOID","STATUS_CTL","DAEMON","C_TCP_SERVER",
"PID_FILE","C_VERBOSITY","C_QUERY_METHOD","RUN_IPV4","C_DEBUG","C_CTL_PERMS",
"C_PROC_LIMIT","C_PROCQ_LIMIT","TCP_QTIMEOUT","C_PAR_QUERIES","C_RAND_RECS",
"NEG_TTL","NEG_RRS_POL","NEG_DOMAIN_POL","QUERY_PORT_START","QUERY_PORT_END",
"IP","PORT","SCHEME","UPTEST","TIMEOUT","PING_TIMEOUT","PING_IP","UPTEST_CMD",
"INTERVAL","INTERFACE","DEVICE","PURGE_CACHE","CACHING","LEAN_QUERY","PRESET",
"PROXY_ONLY","INCLUDE","EXCLUDE","POLICY","LABEL","A","PTR","MX","SOA","CNAME",
"NAME","OWNER","TTL","TYPES","FILET","SERVE_ALIASES","AUTHREC","NDOMAIN",
"CONST","RRTYPE",
};
const char * const yyrule[] = {
"$accept : file",
"file :",
"file : file spec",
"$$1 :",
"spec : GLOBAL '{' $$1 glob_s '}'",
"$$2 :",
"spec : SERVER '{' $$2 serv_s '}'",
"$$3 :",
"spec : RR '{' $$3 rr_s '}'",
"$$4 :",
"spec : NEG '{' $$4 rrneg_s '}'",
"$$5 :",
"spec : SOURCE '{' $$5 source_s '}'",
"glob_s :",
"glob_s : glob_s glob_el",
"glob_el : PERM_CACHE '=' CONST ';'",
"glob_el : PERM_CACHE '=' NUMBER ';'",
"glob_el : CACHE_DIR '=' STRING ';'",
"glob_el : SERVER_PORT '=' NUMBER ';'",
"glob_el : SERVER_IP '=' STRING ';'",
"glob_el : SCHEME_FILE '=' STRING ';'",
"glob_el : LINKDOWN_KLUGE '=' CONST ';'",
"glob_el : MAX_TTL '=' NUMBER ';'",
"glob_el : MIN_TTL '=' NUMBER ';'",
"glob_el : RUN_AS '=' STRING ';'",
"glob_el : STRICT_SETUID '=' CONST ';'",
"glob_el : PARANOID '=' CONST ';'",
"glob_el : STATUS_CTL '=' CONST ';'",
"glob_el : DAEMON '=' CONST ';'",
"glob_el : C_TCP_SERVER '=' CONST ';'",
"glob_el : PID_FILE '=' STRING ';'",
"glob_el : C_VERBOSITY '=' NUMBER ';'",
"glob_el : C_QUERY_METHOD '=' CONST ';'",
"glob_el : RUN_IPV4 '=' CONST ';'",
"glob_el : C_DEBUG '=' CONST ';'",
"glob_el : C_CTL_PERMS '=' NUMBER ';'",
"glob_el : C_PROC_LIMIT '=' NUMBER ';'",
"glob_el : C_PROCQ_LIMIT '=' NUMBER ';'",
"glob_el : TCP_QTIMEOUT '=' NUMBER ';'",
"glob_el : C_PAR_QUERIES '=' NUMBER ';'",
"glob_el : C_RAND_RECS '=' CONST ';'",
"glob_el : NEG_TTL '=' NUMBER ';'",
"glob_el : NEG_RRS_POL '=' CONST ';'",
"glob_el : NEG_DOMAIN_POL '=' CONST ';'",
"glob_el : QUERY_PORT_START '=' NUMBER ';'",
"glob_el : QUERY_PORT_END '=' NUMBER ';'",
"serv_s :",
"serv_s : serv_s serv_el",
"serv_el : IP '=' STRING ';'",
"serv_el : PORT '=' NUMBER ';'",
"serv_el : SCHEME '=' STRING ';'",
"serv_el : UPTEST '=' CONST ';'",
"serv_el : TIMEOUT '=' NUMBER ';'",
"serv_el : PING_TIMEOUT '=' NUMBER ';'",
"serv_el : PING_IP '=' STRING ';'",
"serv_el : UPTEST_CMD '=' STRING ';'",
"serv_el : UPTEST_CMD '=' STRING ',' STRING ';'",
"serv_el : INTERVAL '=' NUMBER ';'",
"serv_el : INTERVAL '=' CONST ';'",
"serv_el : INTERFACE '=' STRING ';'",
"serv_el : DEVICE '=' STRING ';'",
"serv_el : PURGE_CACHE '=' CONST ';'",
"serv_el : CACHING '=' CONST ';'",
"serv_el : LEAN_QUERY '=' CONST ';'",
"serv_el : PRESET '=' CONST ';'",
"serv_el : PROXY_ONLY '=' CONST ';'",
"serv_el : POLICY '=' CONST ';'",
"serv_el : INCLUDE '=' STRING ';'",
"serv_el : EXCLUDE '=' STRING ';'",
"serv_el : LABEL '=' STRING ';'",
"rr_s :",
"rr_s : rr_s rr_el",
"rr_el : NAME '=' STRING ';'",
"rr_el : OWNER '=' STRING ';'",
"rr_el : TTL '=' NUMBER ';'",
"rr_el : AUTHREC '=' CONST ';'",
"rr_el : A '=' STRING ';'",
"rr_el : PTR '=' STRING ';'",
"rr_el : MX '=' STRING ',' NUMBER ';'",
"rr_el : CNAME '=' STRING ';'",
"rr_el : SOA '=' STRING ',' STRING ',' NUMBER ',' NUMBER ',' NUMBER ',' NUMBER ',' NUMBER ';'",
"source_s :",
"source_s : source_s source_el",
"source_el : OWNER '=' STRING ';'",
"source_el : TTL '=' NUMBER ';'",
"source_el : FILET '=' STRING ';'",
"source_el : SERVE_ALIASES '=' CONST ';'",
"source_el : AUTHREC '=' CONST ';'",
"rrneg_s :",
"rrneg_s : rrneg_s rrneg_el",
"rrneg_el : NAME '=' STRING ';'",
"rrneg_el : TTL '=' NUMBER ';'",
"rrneg_el : TYPES '=' NDOMAIN ';'",
"rrneg_el : TYPES '=' rr_type_list ';'",
"rr_type_list : rr_type",
"rr_type_list : rr_type ',' rr_type_list",
"rr_type : RRTYPE",
"errnt : ERROR",
};
#endif
#if YYDEBUG
#include <stdio.h>
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH 10000
#endif
#endif
#define YYINITSTACKSIZE 200
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short *yyss;
short *yysslim;
YYSTYPE *yyvs;
int yystacksize;
#line 917 "conf-parse.y"

int yyerror (char *s)
{
#ifdef NO_YYLINENO
	fprintf(stderr, "Error in config file: %s\n",s);
#else
	fprintf(stderr, "Error in config file (line %i): %s\n",yylineno,s);
#endif
	return 0;
}
#line 545 "y.tab.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack()
{
    int newsize, i;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
    i = yyssp - yyss;
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss);
    if (newss == NULL)
        return -1;
    yyss = newss;
    yyssp = newss + i;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs);
    if (newvs == NULL)
        return -1;
    yyvs = newvs;
    yyvsp = newvs + i;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab

#ifndef YYPARSE_PARAM
#if defined(__cplusplus) || __STDC__
#define YYPARSE_PARAM_ARG void
#define YYPARSE_PARAM_DECL
#else	/* ! ANSI-C/C++ */
#define YYPARSE_PARAM_ARG
#define YYPARSE_PARAM_DECL
#endif	/* ANSI-C/C++ */
#else	/* YYPARSE_PARAM */
#ifndef YYPARSE_PARAM_TYPE
#define YYPARSE_PARAM_TYPE void *
#endif
#if defined(__cplusplus) || __STDC__
#define YYPARSE_PARAM_ARG YYPARSE_PARAM_TYPE YYPARSE_PARAM
#define YYPARSE_PARAM_DECL
#else	/* ! ANSI-C/C++ */
#define YYPARSE_PARAM_ARG YYPARSE_PARAM
#define YYPARSE_PARAM_DECL YYPARSE_PARAM_TYPE YYPARSE_PARAM;
#endif	/* ANSI-C/C++ */
#endif	/* ! YYPARSE_PARAM */

int
yyparse (YYPARSE_PARAM_ARG)
    YYPARSE_PARAM_DECL
{
    register int yym, yyn, yystate;
#if YYDEBUG
    register const char *yys;

    if ((yys = getenv("YYDEBUG")))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if ((yyn = yydefred[yystate])) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yysslim && yygrowstack())
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;
#if defined(lint) || defined(__GNUC__)
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#if defined(lint) || defined(__GNUC__)
    goto yyerrlab;
#endif
yyerrlab:
    ++yynerrs;
yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yysslim && yygrowstack())
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = (-1);
        goto yyloop;
    }
yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    yyval = yyvsp[1-yym];
    switch (yyn)
    {
case 1:
#line 177 "conf-parse.y"
{}
break;
case 2:
#line 178 "conf-parse.y"
{}
break;
case 3:
#line 182 "conf-parse.y"
{
#if defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
				if (run_ipv6)
					global.a.ipv6=in6addr_any;
#endif
			}
break;
case 4:
#line 188 "conf-parse.y"
{}
break;
case 5:
#line 189 "conf-parse.y"
{set_serv_presets(&server); }
break;
case 6:
#line 190 "conf-parse.y"
{
				if (is_inaddr_any(&server.a)) {
					yyerror("bad ip or no ip specified in section");
					YYERROR;
				}
				if (is_inaddr_any(&server.ping_a)) {
					memcpy(&server.ping_a, &server.a,sizeof(server.ping_a));
				}
				if (server.uptest==C_EXEC) {
					if (server.uptest_cmd[0]=='\0') {
						yyerror("you must specify uptest_cmd if you specify uptest=exec!");
						YYERROR;
					}
				}
				add_server(server);
			}
break;
case 7:
#line 207 "conf-parse.y"
{
					c_owner[0]='\0';
					c_name[0]='\0';
					c_ttl=86400;
					c_flags=DF_LOCAL;
					
				}
break;
case 8:
#line 215 "conf-parse.y"
{
				if (strlen((char *)c_owner)==0 || strlen((char *)c_name)==0) {
				        yyerror("must specify owner and name in a rr record.");
					YYERROR;
				}

				/* add the authority */
				add_cent_rr(&c_cent, c_ttl,0,CF_LOCAL, strlen((char *)c_owner)+1, c_owner, T_NS,0);
				add_cache(c_cent);
				free_cent(c_cent,0);
			}
break;
case 9:
#line 227 "conf-parse.y"
{
					htp=0;
					hdtp=0;
					c_name[0]='\0';
					c_ttl=86400;
				}
break;
case 10:
#line 234 "conf-parse.y"
{
			}
break;
case 11:
#line 237 "conf-parse.y"
{
					c_owner[0]='\0';
					c_ttl=86400;
					c_flags=DF_LOCAL;
					c_aliases=0;
					
				}
break;
case 12:
#line 245 "conf-parse.y"
{
				if (c_owner[0]=='\0') {
					yyerror("you must specify owner in a source record.");
					YYERROR;
				}
			}
break;
case 13:
#line 253 "conf-parse.y"
{}
break;
case 14:
#line 254 "conf-parse.y"
{}
break;
case 15:
#line 258 "conf-parse.y"
{
				if (yyvsp[-1].num==C_OFF) {
					global.perm_cache=0;
				} else {
					yyerror("bad qualifier in perm_cache= option.");
					YYERROR;
				}
			}
break;
case 16:
#line 267 "conf-parse.y"
{
				global.perm_cache=yyvsp[-1].num;
			}
break;
case 17:
#line 271 "conf-parse.y"
{
				YSTRNCP(global.cache_dir, (char *)yyvsp[-1].nm, "cache_dir");
			}
break;
case 18:
#line 275 "conf-parse.y"
{
				global.port=yyvsp[-1].num;
			}
break;
case 19:
#line 279 "conf-parse.y"
{
				if (!str2pdnsd_a((char *)yyvsp[-1].nm,&global.a)) {
					yyerror("bad ip in server_ip= option.");
					YYERROR;
				}
 			}
break;
case 20:
#line 286 "conf-parse.y"
{
				YSTRNCP(global.scheme_file, (char *)yyvsp[-1].nm, "scheme_file");
                        }
break;
case 21:
#line 290 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					global.lndown_kluge=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in linkdown_kluge= option.");
					YYERROR;
				}
			}
break;
case 22:
#line 299 "conf-parse.y"
{
				global.max_ttl=yyvsp[-1].num;
			}
break;
case 23:
#line 303 "conf-parse.y"
{
				global.min_ttl=yyvsp[-1].num;
			}
break;
case 24:
#line 307 "conf-parse.y"
{
				YSTRNCP(global.run_as, (char *)yyvsp[-1].nm, "run_as");
			}
break;
case 25:
#line 311 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					global.strict_suid=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in strict_setuid= option.");
					YYERROR;
				}
			}
break;
case 26:
#line 320 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					global.paranoid=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in paranoid= option.");
					YYERROR;
				}
			}
break;
case 27:
#line 329 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					stat_pipe=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in status_pipe= option.");
					YYERROR;
				}
			}
break;
case 28:
#line 338 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					daemon_p=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in daemon= option.");
					YYERROR;
				}
			}
break;
case 29:
#line 347 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					notcp=(yyvsp[-1].num==C_OFF);
				} else {
					yyerror("bad qualifier in tcp_server= option.");
					YYERROR;
				}
			}
break;
case 30:
#line 356 "conf-parse.y"
{
				YSTRNCP(pidfile, (char *)yyvsp[-1].nm, "pid_file");
			}
break;
case 31:
#line 360 "conf-parse.y"
{
				verbosity=yyvsp[-1].num;
			}
break;
case 32:
#line 364 "conf-parse.y"
{
				if (yyvsp[-1].num==TCP_ONLY || yyvsp[-1].num==UDP_ONLY || yyvsp[-1].num==TCP_UDP) {
					query_method=yyvsp[-1].num;
				} else {
					yyerror("bad qualifier in query_method= option.");
					YYERROR;
				}
			}
break;
case 33:
#line 373 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
#if defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
					run_ipv4=(yyvsp[-1].num==C_ON);
					run_ipv6=(yyvsp[-1].num!=C_ON);
#else
					yyerror("the run_ipv4 option is only available when pdnsd is compiled with IPv4 AND IPv6 support.");
#endif
				} else {
					yyerror("bad qualifier in run_ipv4= option.");
					YYERROR;
				}
			}
break;
case 34:
#line 387 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					debug_p=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in debug= option.");
					YYERROR;
				}
			}
break;
case 35:
#line 396 "conf-parse.y"
{
				global.ctl_perms=yyvsp[-1].num;
			}
break;
case 36:
#line 400 "conf-parse.y"
{
				global.proc_limit=yyvsp[-1].num;
			}
break;
case 37:
#line 404 "conf-parse.y"
{
				global.procq_limit=yyvsp[-1].num;
			}
break;
case 38:
#line 408 "conf-parse.y"
{
				global.tcp_qtimeout=yyvsp[-1].num;
			}
break;
case 39:
#line 412 "conf-parse.y"
{
				global.par_queries=yyvsp[-1].num;
			}
break;
case 40:
#line 416 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					global.rnd_recs=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in randomize_recs= option.");
					YYERROR;
				}
			}
break;
case 41:
#line 425 "conf-parse.y"
{
				global.neg_ttl=yyvsp[-1].num;
			}
break;
case 42:
#line 429 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF || yyvsp[-1].num==C_AUTH) {
					global.neg_rrs_pol=yyvsp[-1].num;
				} else {
					yyerror("bad qualifier in neg_rrs_pol= option.");
					YYERROR;
				}
			}
break;
case 43:
#line 438 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF || yyvsp[-1].num==C_AUTH) {
					global.neg_domain_pol=yyvsp[-1].num;
				} else {
					yyerror("bad qualifier in neg_domain_pol= option.");
					YYERROR;
				}
			}
break;
case 44:
#line 447 "conf-parse.y"
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
case 45:
#line 459 "conf-parse.y"
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
case 46:
#line 472 "conf-parse.y"
{}
break;
case 47:
#line 473 "conf-parse.y"
{}
break;
case 48:
#line 477 "conf-parse.y"
{
				if (!str2pdnsd_a((char *)yyvsp[-1].nm,&server.a)) {
					yyerror("bad ip in ip= option.");
					YYERROR;
				}
			}
break;
case 49:
#line 484 "conf-parse.y"
{
				server.port=yyvsp[-1].num;
			}
break;
case 50:
#line 488 "conf-parse.y"
{
				YSTRNCP(server.scheme, (char *)yyvsp[-1].nm, "scheme");
			}
break;
case 51:
#line 492 "conf-parse.y"
{
 				if (yyvsp[-1].num==C_PING || yyvsp[-1].num==C_NONE || yyvsp[-1].num==C_IF || yyvsp[-1].num==C_EXEC || yyvsp[-1].num==C_DEV || yyvsp[-1].num==C_DIALD) {
					server.uptest=yyvsp[-1].num;
				} else {
					yyerror("bad qualifier in uptest= option.");
					YYERROR;
				}
			}
break;
case 52:
#line 501 "conf-parse.y"
{
				server.timeout=yyvsp[-1].num;
			}
break;
case 53:
#line 505 "conf-parse.y"
{
				server.ping_timeout=yyvsp[-1].num;
			}
break;
case 54:
#line 509 "conf-parse.y"
{
				if (!str2pdnsd_a((char *)yyvsp[-1].nm,&server.ping_a)) {
					yyerror("bad ip in ping_ip= option.");
					YYERROR;
				}
			}
break;
case 55:
#line 516 "conf-parse.y"
{
				YSTRNCP(server.uptest_cmd, (char *)yyvsp[-1].nm, "uptest_cmd");
				server.uptest_usr[0] = '\0';
			}
break;
case 56:
#line 521 "conf-parse.y"
{
				YSTRNCP(server.uptest_cmd, (char *)yyvsp[-3].nm, "uptest_cmd");
				YSTRNCP(server.uptest_usr, (char *)yyvsp[-1].nm, "uptest_cmd");
			}
break;
case 57:
#line 526 "conf-parse.y"
{
				server.interval=yyvsp[-1].num;
			}
break;
case 58:
#line 530 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ONQUERY) {
					server.interval=-1;
				} else {
					yyerror("bad qualifier in interval= option.");
					YYERROR;
				}
			}
break;
case 59:
#line 539 "conf-parse.y"
{
				YSTRNCP(server.interface, (char *)yyvsp[-1].nm, "interface");
			}
break;
case 60:
#line 543 "conf-parse.y"
{
				YSTRNCP(server.device, (char *)yyvsp[-1].nm, "device");
  			}
break;
case 61:
#line 547 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					server.purge_cache=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in purge_cache= option.");
					YYERROR;
				}
			}
break;
case 62:
#line 556 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					server.nocache=(yyvsp[-1].num==C_OFF);
				} else {
					yyerror("bad qualifier in caching= option.");
					YYERROR;
				}
			}
break;
case 63:
#line 565 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					server.lean_query=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in lean_query= option.");
					YYERROR;
				}
			}
break;
case 64:
#line 574 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					server.is_up=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in preset= option.");
					YYERROR;
				}
			}
break;
case 65:
#line 583 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					server.is_proxy=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("bad qualifier in proxy_only= option.");
					YYERROR;
				}
			}
break;
case 66:
#line 592 "conf-parse.y"
{
				if (yyvsp[-1].num==C_INCLUDED || yyvsp[-1].num==C_EXCLUDED) {
					server.policy=yyvsp[-1].num;
				} else {
					yyerror("bad qualifier in policy= option.");
					YYERROR;
				}
			}
break;
case 67:
#line 601 "conf-parse.y"
{
				char *e;
				
				if ((e=slist_add(&server,(char *)yyvsp[-1].nm,C_INCLUDED))!=NULL) {
					yyerror(e);
					YYERROR;
				}
			}
break;
case 68:
#line 610 "conf-parse.y"
{
				char *e;
				
				if ((e=slist_add(&server,(char *)yyvsp[-1].nm,C_EXCLUDED))!=NULL) {
					yyerror(e);
					YYERROR;
				}
			}
break;
case 69:
#line 619 "conf-parse.y"
{
				YSTRNCP(server.label, (char *)yyvsp[-1].nm, "label");
			}
break;
case 70:
#line 624 "conf-parse.y"
{}
break;
case 71:
#line 625 "conf-parse.y"
{}
break;
case 72:
#line 629 "conf-parse.y"
{
				if (strlen((char *)yyvsp[-1].nm)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				YSTRNCP(c_name, (char *)yyvsp[-1].nm, "name");
				if (c_owner[0]!='\0') {
					if (!init_cent(&c_cent, c_name, c_flags, time(NULL), 0, 0)) {
						fprintf(stderr,"Out of memory.\n");
						YYERROR;
					}
				}
			}
break;
case 73:
#line 643 "conf-parse.y"
{
				if (strlen((char *)yyvsp[-1].nm)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				if (!str2rhn(yyvsp[-1].nm,c_owner)) {
					yyerror("bad domain name - must end in root domain.");
					YYERROR;
				}
				if (c_name[0]!='\0') {
					if (!init_cent(&c_cent, c_name, c_flags, time(NULL), 0, 0)) {
						fprintf(stderr,"Out of memory.\n");
						YYERROR;
					}
				}
			}
break;
case 74:
#line 660 "conf-parse.y"
{
				c_ttl=yyvsp[-1].num;
			}
break;
case 75:
#line 664 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					c_flags=(yyvsp[-1].num==C_ON)?DF_LOCAL:0;
				} else {
					yyerror("Bad qualifier in authrec= option.");
					YYERROR;
				}
			}
break;
case 76:
#line 673 "conf-parse.y"
{
				if (strlen((char *)c_owner)==0 || strlen((char *)c_name)==0) {
					yyerror("you must specify owner and name before a,ptr and soa records.");
					YYERROR;
				}
				if (inet_aton((char *)yyvsp[-1].nm,&ina4)) {
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
					if ((err=inet_pton(AF_INET6,(char *)yyvsp[-1].nm,&c_a.ipv6))!=1) {
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
				add_cent_rr(&c_cent,c_ttl,0,CF_LOCAL,sz,&c_a,tp, 0);
			}
break;
case 77:
#line 709 "conf-parse.y"
{
				if (strlen((char *)c_owner)==0 || strlen((char *)c_name)==0) {
					yyerror("you must specify owner and name before a,ptr and soa records.");
					YYERROR;
				}
				if (strlen((char *)yyvsp[-1].nm)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				if (!str2rhn(yyvsp[-1].nm,c_ptr)) {
					yyerror("bad domain name - must end in root domain.");
					YYERROR;
				}
				add_cent_rr(&c_cent,c_ttl,0,CF_LOCAL,rhnlen(c_ptr),c_ptr,T_PTR,0);
			}
break;
case 78:
#line 725 "conf-parse.y"
{
				if (strlen((char *)c_owner)==0 || strlen((char *)c_name)==0) {
					yyerror("you must specify owner and name before mx records.");
					YYERROR;
				}
				if (strlen((char *)yyvsp[-3].nm)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				if (!str2rhn(yyvsp[-3].nm,c_ptr)) {
					yyerror("bad domain name - must end in root domain.");
					YYERROR;
				}
				memset(buf,0,sizeof(buf));
				ts=htons(yyvsp[-1].num);
				memcpy(buf,&ts,2);
				rhncpy(buf+2,c_ptr);
				add_cent_rr(&c_cent,c_ttl,0,CF_LOCAL,rhnlen(c_ptr)+2,buf,T_MX,0);
			}
break;
case 79:
#line 745 "conf-parse.y"
{
				if (strlen((char *)c_owner)==0 || strlen((char *)c_name)==0) {
					yyerror("you must specify owner and name before cname records.");
					YYERROR;
				}
				if (strlen((char *)yyvsp[-1].nm)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				if (!str2rhn(yyvsp[-1].nm,c_ptr)) {
					yyerror("bad domain name - must end in root domain.");
					YYERROR;
				}
				add_cent_rr(&c_cent,c_ttl,0,CF_LOCAL,rhnlen(c_ptr),c_ptr,T_CNAME,0);
			}
break;
case 80:
#line 761 "conf-parse.y"
{
				if (strlen((char *)c_owner)==0 || strlen((char *)c_name)==0) {
					yyerror("you must specify owner and name before a, ptr and soa records.");
					YYERROR;
				}
				if (strlen((char *)yyvsp[-13].nm)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				if (!str2rhn(yyvsp[-13].nm,c_soa_owner)) {
					yyerror("bad domain name - must end in root domain.");
					YYERROR;
				}
				if (strlen((char *)yyvsp[-11].nm)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				if (!str2rhn(yyvsp[-11].nm,c_soa_r)) {
					yyerror("bad domain name - must end in root domain.");
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
				add_cent_rr(&c_cent,c_ttl,0,CF_LOCAL,idx,buf,T_SOA,0);
			}
break;
case 81:
#line 796 "conf-parse.y"
{}
break;
case 82:
#line 797 "conf-parse.y"
{}
break;
case 83:
#line 801 "conf-parse.y"
{
				if (strlen((char *)yyvsp[-1].nm)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				if (!str2rhn(yyvsp[-1].nm,c_owner)) {
					yyerror("bad domain name - must end in root domain.");
					YYERROR;
				}
			}
break;
case 84:
#line 812 "conf-parse.y"
{
				c_ttl=yyvsp[-1].num;
			}
break;
case 85:
#line 816 "conf-parse.y"
{
				if (strlen((char *)c_owner)==0) {
					yyerror("you must specify owner before file= in source records.");
					YYERROR;
				}
				if (!read_hosts((char *)yyvsp[-1].nm, c_owner, c_ttl, c_flags, c_aliases,errbuf,sizeof(errbuf)))
					fprintf(stderr,"%s\n",errbuf);
			}
break;
case 86:
#line 825 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					c_aliases=(yyvsp[-1].num==C_ON);
				} else {
					yyerror("Bad qualifier in serve_aliases= option.");
					YYERROR;
				}
			}
break;
case 87:
#line 834 "conf-parse.y"
{
				if (yyvsp[-1].num==C_ON || yyvsp[-1].num==C_OFF) {
					c_flags=(yyvsp[-1].num==C_ON)?DF_LOCAL:0;
				} else {
					yyerror("Bad qualifier in authrec= option.");
					YYERROR;
				}
			}
break;
case 88:
#line 845 "conf-parse.y"
{}
break;
case 89:
#line 846 "conf-parse.y"
{}
break;
case 90:
#line 851 "conf-parse.y"
{
				if (strlen((char *)yyvsp[-1].nm)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				YSTRNCP(c_name,(char *)yyvsp[-1].nm, "name");
			}
break;
case 91:
#line 859 "conf-parse.y"
{
				c_ttl=yyvsp[-1].num;
			}
break;
case 92:
#line 863 "conf-parse.y"
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
				if (!init_cent(&c_cent, (unsigned char *)c_name, DF_LOCAL|DF_NEGATIVE, time(NULL), c_ttl,0)) {
					fprintf(stderr,"Out of memory");
					YYERROR;
				}
				add_cache(c_cent);
				free_cent(c_cent,0);
			}
break;
case 93:
#line 881 "conf-parse.y"
{
			}
break;
case 94:
#line 885 "conf-parse.y"
{}
break;
case 95:
#line 886 "conf-parse.y"
{}
break;
case 96:
#line 890 "conf-parse.y"
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
				if (!init_cent(&c_cent, (unsigned char *)c_name, 0, time(NULL), 0, 0)) {
					fprintf(stderr,"Out of memory");
					YYERROR;
				}
				if (!add_cent_rrset(&c_cent,yyvsp[0].num,c_ttl,0,CF_LOCAL|CF_NEGATIVE,0, 0)) {
					free_cent(c_cent,0);
					fprintf(stderr,"Out of memory");
					YYERROR;
				}
				add_cache(c_cent);
				free_cent(c_cent, 0);
				
			}
break;
case 97:
#line 915 "conf-parse.y"
{YYERROR;}
break;
#line 1661 "y.tab.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yysslim && yygrowstack())
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    return (1);
yyaccept:
    return (0);
}
