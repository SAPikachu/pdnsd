%{
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

#include "config.h"
#include "ipvers.h"
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "conff.h"
#include "consts.h"
#include "cacheing/cache.h"
#include "dns.h"
#include "dns_query.h"
#include "helpers.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: conf-parse.y,v 1.21 2001/01/24 23:02:55 thomas Exp $";
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
unsigned long c_ttl;
int c_aliases;
unsigned char buf[532];
char errbuf[256];
int sz,tp;
int hdtp, htp;
struct in_addr ina4;

int idx;

#ifndef NO_YYLINENO
/*
 * This comes from the generated lexer. It is an undocumented variable in lex, and in flex
 * we explicitely switch it on.
 */
extern int yylineno;
#endif

%}
%union {
long 	      num;
unsigned char *nm;
}

%token <num> NUMBER
%token <nm>  STRING
%token <num> ERROR

%token <num> GLOBAL
%token <num> SERVER
%token <num> RR
%token <num> NEG
%token <num> SOURCE

%token <num> PERM_CACHE
%token <num> CACHE_DIR
%token <num> SERVER_PORT
%token <num> SERVER_IP
%token <num> SCHEME_FILE
%token <num> LINKDOWN_KLUGE
%token <num> MAX_TTL
%token <num> MIN_TTL
%token <num> RUN_AS
%token <num> STRICT_SETUID
%token <num> PARANOID
%token <num> STATUS_CTL
%token <num> DAEMON
%token <num> C_TCP_SERVER
%token <num> PID_FILE
%token <num> C_VERBOSITY
%token <num> C_QUERY_METHOD
%token <num> RUN_IPV4
%token <num> C_DEBUG
%token <num> C_CTL_PERMS
%token <num> C_PROC_LIMIT
%token <num> C_PROCQ_LIMIT
%token <num> TCP_QTIMEOUT
%token <num> C_PAR_QUERIES
%token <num> C_RAND_RECS
%token <num> NEG_TTL
%token <num> NEG_RRS_POL
%token <num> NEG_DOMAIN_POL

%token <num> IP
%token <num> PORT
%token <num> SCHEME
%token <num> UPTEST
%token <num> TIMEOUT
%token <num> PING_TIMEOUT
%token <num> PING_IP
%token <num> UPTEST_CMD
%token <num> INTERVAL
%token <num> INTERFACE
%token <num> DEVICE
%token <num> PURGE_CACHE
%token <num> CACHING
%token <num> LEAN_QUERY
%token <num> PRESET
%token <num> PROXY_ONLY
%token <num> INCLUDE
%token <num> EXCLUDE
%token <num> POLICY

%token <num> A
%token <num> PTR
%token <num> SOA
%token <num> NAME
%token <num> OWNER
%token <num> TTL
%token <num> TYPES
%token <num> FILET
%token <num> SERVE_ALIASES

%token <num> NDOMAIN

%token <num> CONST
%token <num> RRTYPE

%type <num>  file
%type <num>  spec
%type <num>  glob_s
%type <num>  glob_el
%type <num>  serv_s
%type <num>  serv_el
%type <num>  rr_s
%type <num>  rr_el
%type <num>  rrneg_s
%type <num>  rrneg_el
%type <num>  rr_type_list

%%
file:		/* nothing */		{}
		| file spec   		{}	
		;

spec:		GLOBAL '{' 
			{
#if defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
				if (run_ipv6)
					global.a.ipv6=in6addr_any;
#endif
			}
			glob_s '}'	{}
		| SERVER '{' {set_serv_presets(&server); } serv_s '}'
			{
				if (is_inaddr_any(&server.a)) {
					yyerror("bad ip or no ip specified in section");
					YYERROR;
				}
				if (is_inaddr_any(&server.ping_a)) {
					memcpy(&server.ping_a, &server.a,sizeof(server.a));
				}
				if (server.uptest==C_EXEC) {
					if (server.uptest_cmd[0]=='\0') {
						yyerror("you must specify uptest_cmd if you specify uptest=exec!");
						YYERROR;
					}
				}
				add_server(server);
			}
		| RR '{' 
				{
					c_owner[0]='\0';
					c_name[0]='\0';
					c_ttl=86400;
					
				} 
			rr_s '}'
			{
				if (strlen((char *)c_owner)==0 || strlen((char *)c_name)==0) {
				        yyerror("must specify owner and name in a rr record.");
					YYERROR;
				}

				/* add the authority */
				add_cent_rr(&c_cent, c_ttl,0,CF_LOCAL, strlen((char *)c_owner)+1, c_owner, T_NS);
				add_cache(c_cent);
			}
		| NEG '{' 
				{
					htp=0;
					hdtp=0;
					c_name[0]='\0';
					c_ttl=86400;
				} 
			rrneg_s '}'
			{
			}
		| SOURCE '{'
				{
					c_owner[0]='\0';
					c_ttl=86400;
					c_aliases=0;
					
				} 
			source_s '}'
			{
				if (c_owner[0]=='\0') {
					yyerror("you must specify owner in a source record.");
					YYERROR;
				}
			}
		;

glob_s:		/* empty*/		{}
		| glob_s glob_el	{}
		;

glob_el:	PERM_CACHE '=' CONST ';'
			{
				if ($3==C_OFF) {
					global.perm_cache=0;
				} else {
					yyerror("bad qualifier in perm_cache= option.");
					YYERROR;
				}
			}
		| PERM_CACHE '=' NUMBER ';'
			{
				global.perm_cache=$3;
			}
		| CACHE_DIR '=' STRING ';'
			{
				strncpy(global.cache_dir,(char *)$3,MAXPATH);
				global.cache_dir[MAXPATH-1]='\0';
			}
		| SERVER_PORT '=' NUMBER ';'
			{
				global.port=$3;
			}
		| SERVER_IP '=' STRING ';'
			{
				if (!str2pdnsd_a((char *)$3,&global.a)) {
					yyerror("bad ip in server_ip= option.");
					YYERROR;
				}
 			}
		| SCHEME_FILE '=' STRING ';'
                        {
                                strncpy(global.scheme_file,(char *)$3,MAXPATH);
                                global.scheme_file[MAXPATH-1]='\0';
                        }
		| LINKDOWN_KLUGE '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF) {
					global.lndown_kluge=($3==C_ON);
				} else {
					yyerror("bad qualifier in linkdown_kluge= option.");
					YYERROR;
				}
			}
		| MAX_TTL '=' NUMBER ';'
			{
				global.max_ttl=$3;
			}
		| MIN_TTL '=' NUMBER ';'
			{
				global.min_ttl=$3;
			}
		| RUN_AS '=' STRING ';'
			{
				strncpy(global.run_as,(char *)$3,20);
				global.run_as[19]='\0';
			}
		| STRICT_SETUID '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF) {
					global.strict_suid=($3==C_ON);
				} else {
					yyerror("bad qualifier in strict_setuid= option.");
					YYERROR;
				}
			}
		| PARANOID '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF) {
					global.paranoid=($3==C_ON);
				} else {
					yyerror("bad qualifier in paranoid= option.");
					YYERROR;
				}
			}
		| STATUS_CTL '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF) {
					stat_pipe=($3==C_ON);
				} else {
					yyerror("bad qualifier in status_pipe= option.");
					YYERROR;
				}
			}
		| DAEMON '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF) {
					daemon_p=($3==C_ON);
				} else {
					yyerror("bad qualifier in daemon= option.");
					YYERROR;
				}
			}
		| C_TCP_SERVER '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF) {
					notcp=($3==C_OFF);
				} else {
					yyerror("bad qualifier in tcp_server= option.");
					YYERROR;
				}
			}
		| PID_FILE '=' STRING ';'
			{
				strncpy(pidfile,(char *)$3,MAXPATH);
				pidfile[MAXPATH-1]='\0';
			}
		| C_VERBOSITY '=' NUMBER ';'
			{
				verbosity=$3;
			}
		| C_QUERY_METHOD '=' CONST ';'
			{
				if ($3==TCP_ONLY || $3==UDP_ONLY || $3==TCP_UDP) {
					query_method=$3;
				} else {
					yyerror("bad qualifier in query_method= option.");
					YYERROR;
				}
			}
		| RUN_IPV4 '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF) {
#if defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
					run_ipv4=($3==C_ON);
					run_ipv6=($3!=C_ON);
#else
					yyerror("the run_ipv4 option is only available when pdnsd is compiled with IPv4 AND IPv6 support.");
#endif
				} else {
					yyerror("bad qualifier in run_ipv4= option.");
					YYERROR;
				}
			}
		| C_DEBUG '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF) {
					debug_p=($3==C_ON);
				} else {
					yyerror("bad qualifier in debug= option.");
					YYERROR;
				}
			}
		| C_CTL_PERMS '=' NUMBER ';'
			{
				global.ctl_perms=$3;
			}
		| C_PROC_LIMIT '=' NUMBER ';'
			{
				global.proc_limit=$3;
			}
		| C_PROCQ_LIMIT '=' NUMBER ';'
			{
				global.procq_limit=$3;
			}
		| TCP_QTIMEOUT '=' NUMBER ';'
			{
				global.tcp_qtimeout=$3;
			}
		| C_PAR_QUERIES '=' NUMBER ';'
			{
				global.par_queries=$3;
			}
		| C_RAND_RECS '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF) {
					global.rnd_recs=($3==C_ON);
				} else {
					yyerror("bad qualifier in randomize_recs= option.");
					YYERROR;
				}
			}
		| NEG_TTL '=' NUMBER ';'
			{
				global.neg_ttl=$3;
			}
		| NEG_RRS_POL '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF || $3==C_AUTH) {
					global.neg_rrs_pol=$3;
				} else {
					yyerror("bad qualifier in neg_rrs_pol= option.");
					YYERROR;
				}
			}
		| NEG_DOMAIN_POL '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF || $3==C_AUTH) {
					global.neg_domain_pol=$3;
				} else {
					yyerror("bad qualifier in neg_domain_pol= option.");
					YYERROR;
				}
			}
		;

serv_s:		/* empty */		{}
		| serv_s serv_el	{}
		;

serv_el:	IP '=' STRING ';'
			{
				if (!str2pdnsd_a((char *)$3,&server.a)) {
					yyerror("bad ip in ip= option.");
					YYERROR;
				}
			}
		| PORT '=' NUMBER ';'
			{
				server.port=$3;
			}
		| SCHEME '=' STRING ';'
			{
				strncpy(server.scheme,(char *)$3,32);
				server.scheme[31]='\0';

			}
		| UPTEST '=' CONST ';'
			{
 				if ($3==C_PING || $3==C_NONE || $3==C_IF || $3==C_EXEC || $3==C_DEV || $3==C_DIALD) {
					server.uptest=$3;
				} else {
					yyerror("bad qualifier in uptest= option.");
					YYERROR;
				}
			}
		| TIMEOUT '=' NUMBER ';'
			{
				server.timeout=$3;
			}
		| PING_TIMEOUT '=' NUMBER ';'
			{
				server.ping_timeout=$3;
			}
		| PING_IP '=' STRING ';'
			{
				if (!str2pdnsd_a((char *)$3,&server.ping_a)) {
					yyerror("bad ip in ping_ip= option.");
					YYERROR;
				}
			}
		| UPTEST_CMD '=' STRING ';'
			{
				strncpy(server.uptest_cmd,(char *)$3,512);
				server.uptest_cmd[511]='\0';
			}
		| UPTEST_CMD '=' STRING ',' STRING ';'
			{
				strncpy(server.uptest_cmd,(char *)$3,512);
				strncpy(server.uptest_usr,(char *)$5,20);
				server.uptest_cmd[511]='\0';
				server.uptest_usr[19]='\0';
			}
		| INTERVAL '=' NUMBER ';'
			{
				server.interval=$3;
			}
		| INTERVAL '=' CONST ';'
			{
				if ($3==C_ONQUERY) {
					server.interval=-1;
				} else {
					yyerror("bad qualifier in interval= option.");
					YYERROR;
				}
			}
		| INTERFACE '=' STRING  ';'
			{
				strncpy(server.interface,(char *)$3,6);
				server.interface[6]='\0';
			}
 		| DEVICE '=' STRING  ';'
 			{
 				strncpy(server.device,(char *)$3,6);
 				server.device[6]='\0';
  			}
		| PURGE_CACHE '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF) {
					server.purge_cache=($3==C_ON);
				} else {
					yyerror("bad qualifier in purge_cache= option.");
					YYERROR;
				}
			}
		| CACHING '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF) {
					server.nocache=($3==C_OFF);
				} else {
					yyerror("bad qualifier in caching= option.");
					YYERROR;
				}
			}
		| LEAN_QUERY '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF) {
					server.lean_query=($3==C_ON);
				} else {
					yyerror("bad qualifier in lean_query= option.");
					YYERROR;
				}
			}
		| PRESET '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF) {
					server.is_up=($3==C_ON);
				} else {
					yyerror("bad qualifier in preset= option.");
					YYERROR;
				}
			}
		| PROXY_ONLY '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF) {
					server.is_proxy=($3==C_ON);
				} else {
					yyerror("bad qualifier in proxy_only= option.");
					YYERROR;
				}
			}
		| POLICY '=' CONST ';'
			{
				if ($3==C_INCLUDED || $3==C_EXCLUDED) {
					server.policy=$3;
				} else {
					yyerror("bad qualifier in policy= option.");
					YYERROR;
				}
			}
		| INCLUDE '=' STRING ';'
			{
				server.nalist++;
				if (!(server.alist=realloc(server.alist,sizeof(*server.alist)*server.nalist))) {
					yyerror("out of memory!.");
					YYERROR;
				}
				server.alist[server.nalist-1].rule=C_INCLUDED;
				if (strlen((char *)$3)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				strncpy(server.alist[server.nalist-1].domain,(char *)$3,256);
				server.alist[server.nalist-1].domain[255]='\0';
				if (server.alist[server.nalist-1].domain[strlen(server.alist[server.nalist-1].domain)-1]!='.') {
					yyerror("domain name must end in dot for include=/exclude=.");
					YYERROR;
				}
			}
		| EXCLUDE '=' STRING ';'
			{
				server.nalist++;
				if (!(server.alist=realloc(server.alist,sizeof(*server.alist)*server.nalist))) {
					yyerror("out of memory!.");
					YYERROR;
				}
				server.alist[server.nalist-1].rule=C_EXCLUDED;
				if (strlen((char *)$3)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				strncpy(server.alist[server.nalist-1].domain,(char *)$3,256);
				server.alist[server.nalist-1].domain[255]='\0';
				if (server.alist[server.nalist-1].domain[strlen(server.alist[server.nalist-1].domain)-1]!='.') {
					yyerror("domain name must end in dot for include=/exclude=.");
					YYERROR;
				}
			}
		;

rr_s:		/* empty */		{}
		| rr_s rr_el	{}
		;

rr_el:		NAME '=' STRING ';'
			{
				if (strlen((char *)$3)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				strcpy((char *)c_name,(char *)$3);
				if (c_owner[0]!='\0') {
					if (!init_cent(&c_cent, c_name, 0, time(NULL), 0)) {
						fprintf(stderr,"Out of memory.\n");
						YYERROR;
					}
				}
			}			
		| OWNER '=' STRING ';'
			{
				if (strlen((char *)$3)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				if (!str2rhn($3,c_owner)) {
					yyerror("bad domain name - must end in root domain.");
					YYERROR;
				}
				if (c_name[0]!='\0') {
					if (!init_cent(&c_cent, c_name, 0, time(NULL), 0)) {
						fprintf(stderr,"Out of memory.\n");
						YYERROR;
					}
				}
			}
		| TTL '=' NUMBER ';'
			{
				c_ttl=$3;
			}
		| A '=' STRING ';'
			{
				if (strlen((char *)c_owner)==0 || strlen((char *)c_name)==0) {
					yyerror("you must specify owner and name before a,ptr and soa records.");
					YYERROR;
				}
				if (inet_aton((char *)$3,&ina4)) {
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
					if (!inet_pton(AF_INET6,(char *)$3,&c_a.ipv6)) {
						yyerror("bad ip in a= option.");
						YYERROR;
					} else {
						tp=T_AAAA;
						sz=sizeof(struct in6_addr);
					}
#else
					yyerror("bad ip in a= option.");
					YYERROR;
#endif
				}
				add_cent_rr(&c_cent,c_ttl,0,CF_LOCAL,sz,&c_a,tp);
			}
		| PTR '=' STRING ';'
			{
				if (strlen((char *)c_owner)==0 || strlen((char *)c_name)==0) {
					yyerror("you must specify owner and name before a,ptr and soa records.");
					YYERROR;
				}
				if (strlen((char *)$3)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				if (!str2rhn($3,c_ptr)) {
					yyerror("bad domain name - must end in root domain.");
					YYERROR;
				}
				add_cent_rr(&c_cent,c_ttl,0,CF_LOCAL,strlen((char *)c_ptr)+1,c_ptr,T_PTR);
			}
		| SOA '=' STRING ',' STRING ',' NUMBER ',' NUMBER ',' NUMBER ',' NUMBER ',' NUMBER ';'
			{
				if (strlen((char *)c_owner)==0 || strlen((char *)c_name)==0) {
					yyerror("you must specify owner and name before a, ptr and soa records.");
					YYERROR;
				}
				if (!str2rhn($3,c_soa_owner)) {
					yyerror("bad domain name - must end in root domain.");
					YYERROR;
				}
				if (!str2rhn($5,c_soa_r)) {
					yyerror("bad domain name - must end in root domain.");
					YYERROR;
				}
				c_soa.serial=htonl($7);
				c_soa.refresh=htonl($9);
				c_soa.retry=htonl($11);
				c_soa.expire=htonl($13);
				c_soa.minimum=htonl($15);
				memset(buf,0,532);
				strcpy((char *)buf,(char *)c_soa_owner);
				idx=strlen((char *)c_soa_owner)+1;
				strcpy((char *)&buf[idx],(char *)c_soa_r);
				idx+=strlen((char *)c_soa_r)+1;
				memcpy(&buf[idx],&c_soa,sizeof(soa_r_t));
				idx+=sizeof(soa_r_t);
				add_cent_rr(&c_cent,c_ttl,0,CF_LOCAL,idx,buf,T_SOA);
			}			
		;

source_s:	/* empty */		{}
		| source_s source_el	{}
		;

source_el:	OWNER '=' STRING ';'
			{
				if (strlen((char *)$3)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				if (!str2rhn($3,c_owner)) {
					yyerror("bad domain name - must end in root domain.");
					YYERROR;
				}
			}
		| TTL '=' NUMBER ';'
			{
				c_ttl=$3;
			}
		| FILET '=' STRING ';'
			{
				if (strlen((char *)c_owner)==0) {
					yyerror("you must specify owner before file= in source records.");
					YYERROR;
				}
				if (!read_hosts((char *)$3, c_owner, c_ttl, c_aliases,errbuf,256))
					fprintf(stderr,errbuf);
			}
		| SERVE_ALIASES '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF) {
					c_aliases=($3==C_ON);
				} else {
					yyerror("Bad qualifier in serve_aliases= option.");
					YYERROR;
				}
			}
		;


rrneg_s:	/* empty */		{}
		| rrneg_s rrneg_el	{}
		;


rrneg_el:	NAME '=' STRING ';'
			{
				if (strlen((char *)$3)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				strcpy((char *)c_name,(char *)$3);
				if (c_owner[0]!='\0') {
					if (!init_cent(&c_cent, c_name, 0, time(NULL), 0)) {
						fprintf(stderr,"Out of memory.\n");
						YYERROR;
					}
				}
			}			
		| TTL '=' NUMBER ';'
			{
				c_ttl=$3;
			}
                | TYPES '=' NDOMAIN ';'
			{
				if (htp) {
					yyerror("You may not specify types=domain together with other types!.");
					YYERROR;
				}
				if (!c_name[0]) {
					yyerror("you must specify a name before the types= option.");
					YYERROR;
				}
				hdtp=1;
				if (!init_cent(&c_cent, (unsigned char *)c_name, DF_LOCAL|DF_NEGATIVE, time(NULL), c_ttl)) {
					fprintf(stderr,"Out of memory");
					YYERROR;
				}
				add_cache(c_cent);
			}
                | TYPES '=' rr_type_list ';'
			{
			}
		;

rr_type_list:   RRTYPE
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
				if (!init_cent(&c_cent, (unsigned char *)c_name, 0, time(NULL), 0)) {
					fprintf(stderr,"Out of memory");
					YYERROR;
				}
				if (!add_cent_rrset(&c_cent,$1,c_ttl,0,CF_LOCAL|CF_NEGATIVE,0)) {
					free_cent(c_cent);
					fprintf(stderr,"Out of memory");
					YYERROR;
				}
				add_cache(c_cent);
				
			}
                | rr_type_list ',' rr_type_list 
                        {}
                ; 

errnt:		ERROR		 	{YYERROR;}
%%

int yyerror (char *s)
{
#ifdef NO_YYLINENO
	printf("Error in config file: %s\n",s);
#else
	printf("Error in config file (line %i): %s\n",yylineno,s);
#endif
	return 0;
}
