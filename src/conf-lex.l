%{
/* conf.l - Lexer for pdnsd config files
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
#include <string.h>
#include "conf-parse.h"
#include "consts.h"
#include "rr_types.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: conf-lex.l.in,v 1.22 2001/07/01 21:03:15 tmm Exp $";
#endif

extern YYSTYPE yylval;

int br_level=0;
%}

/* In the location below, %option yylineno is inserted by configure in some 
 * cases.
 * It causes yylineno to be available in flex, which I prefer for error 
 * reporting. It is a little hairy, though, because it is neither part of 
 * the POSIX nor offcially documented in the AT&T lex. Look into configure.in
 * for the implementation. In short, if your lexer generator chokes on this, 
 * you won't get line numbers in the output.*/
%option yylineno

%s comment

C_COMM (\/\/)|(#)
C_OPEN  \/\*
C_CLOSE \*\/
%%

<INITIAL>[0-9]+				{sscanf(yytext,"%li",&yylval.num); return NUMBER;}
<INITIAL>"global"			{return GLOBAL;}
<INITIAL>"server"			{return SERVER;}
<INITIAL>"rr"			        {return RR;}
<INITIAL>"neg"			        {return NEG;}
<INITIAL>"source"			{return SOURCE;}

<INITIAL>"perm_cache"			{return PERM_CACHE;}
<INITIAL>"cache_dir"			{return CACHE_DIR;}
<INITIAL>"server_port"                  {return SERVER_PORT;}
<INITIAL>"server_ip"                    {return SERVER_IP;}
<INITIAL>"scheme_file"                  {return SCHEME_FILE;}
<INITIAL>"linkdown_kluge"		{return LINKDOWN_KLUGE;}
<INITIAL>"max_ttl"			{return MAX_TTL;}
<INITIAL>"min_ttl"			{return MIN_TTL;}
<INITIAL>"run_as"			{return RUN_AS;}
<INITIAL>"strict_setuid"		{return STRICT_SETUID;}
<INITIAL>"paranoid"			{return PARANOID;}
<INITIAL>"status_ctl"			{return STATUS_CTL;}
<INITIAL>"daemon"			{return DAEMON;}
<INITIAL>"tcp_server"			{return C_TCP_SERVER;}
<INITIAL>"pid_file"			{return PID_FILE;}
<INITIAL>"verbosity"			{return C_VERBOSITY;}
<INITIAL>"query_method"			{return C_QUERY_METHOD;}
<INITIAL>"run_ipv4"			{return RUN_IPV4;}
<INITIAL>"debug"			{return C_DEBUG;}
<INITIAL>"ctl_perms"			{return C_CTL_PERMS;}
<INITIAL>"proc_limit"			{return C_PROC_LIMIT;}
<INITIAL>"procq_limit"			{return C_PROCQ_LIMIT;}
<INITIAL>"tcp_qtimeout"			{return TCP_QTIMEOUT;}
<INITIAL>"par_queries"			{return C_PAR_QUERIES;}
<INITIAL>"randomize_recs"		{return C_RAND_RECS;}
<INITIAL>"neg_ttl"			{return NEG_TTL;}
<INITIAL>"neg_rrs_pol"			{return NEG_RRS_POL;}
<INITIAL>"neg_domain_pol"		{return NEG_DOMAIN_POL;}
<INITIAL>"query_port_start"		{return QUERY_PORT_START;}
<INITIAL>"query_port_end"		{return QUERY_PORT_END;}

<INITIAL>"ip"				{return IP;}
<INITIAL>"port"				{return PORT;}
<INITIAL>"scheme"                  	{return SCHEME;}
<INITIAL>"uptest"			{return UPTEST;}
<INITIAL>"timeout"			{return TIMEOUT;}
<INITIAL>"ping_timeout"			{return PING_TIMEOUT;}
<INITIAL>"ping_ip"			{return PING_IP;}
<INITIAL>"uptest_cmd"			{return UPTEST_CMD;}
<INITIAL>"interval"			{return INTERVAL;}
<INITIAL>"interface"			{return INTERFACE;}
<INITIAL>"device"			{return DEVICE;}
<INITIAL>"purge_cache"			{return PURGE_CACHE;}
<INITIAL>"caching"			{return CACHING;}
<INITIAL>"lean_query"			{return LEAN_QUERY;}
<INITIAL>"preset"			{return PRESET;}
<INITIAL>"proxy_only"			{return PROXY_ONLY;}
<INITIAL>"include"			{return INCLUDE;}
<INITIAL>"exclude"			{return EXCLUDE;}
<INITIAL>"policy"			{return POLICY;}
<INITIAL>"label"			{return LABEL;}

<INITIAL>"a"				{return A;}
<INITIAL>"ptr"				{return PTR;}
<INITIAL>"mx"				{return MX;}
<INITIAL>"cname"			{return CNAME;}
<INITIAL>"soa"				{return SOA;}
<INITIAL>"name"				{return NAME;}
<INITIAL>"owner"			{return OWNER;}
<INITIAL>"ttl"			        {return TTL;}
<INITIAL>"types"			{return TYPES;}
<INITIAL>"file"			        {return FILET;}
<INITIAL>"serve_aliases"	        {return SERVE_ALIASES;}
<INITIAL>"authrec"		        {return AUTHREC;}

<INITIAL>"domain"		        {return NDOMAIN;}

<INITIAL>[a-zA-Z_]+			{if ((yylval.num=lookup_const(yytext))!=-1)
						 return CONST; 
					 else if ((yylval.num=rr_tp_byname(yytext))!=-1)
						 return RRTYPE;
					 else {
						 return ERROR;					     
					 }}

<INITIAL>\"[^\"]*\"			{yylval.nm=(unsigned char *)yytext+1;
					 yylval.nm[strlen((char *)yylval.nm)-1]=(unsigned char)'\0';return STRING;}
<INITIAL>[=;\,\{\}]			{return yytext[0];}
<INITIAL>{C_COMM}[^\n]*			/*munch munch*/

{C_OPEN}				{
						br_level++;
						BEGIN(comment);
					}
<comment>{C_CLOSE}			{
						br_level--;
						if (br_level<0)
							return ERROR;
						if (br_level==0)
							BEGIN(INITIAL);
					}
<comment>.				/* Delete text in comments, */
[\ \t]+					/* white space, */
"\n"                                    /* new lines. */
.					{return ERROR;}

%%

void lex_set_io(FILE *in, FILE *out)
{
	yyin=in;
	yyout=out;
}

int yywrap()
{
	return 1;
}
