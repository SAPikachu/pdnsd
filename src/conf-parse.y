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
*/

#define YYPARSE_LOCAL_DECL  \
servparm_t server;  \
dns_cent_t c_cent;  \
unsigned char c_owner[256];  \
unsigned char c_name[256];  \
time_t c_ttl;  \
int c_flags;  \
unsigned char c_aliases, hdtp, htp;


#ifndef NO_YYLINENO
/*
 * This comes from the generated lexer. It is an undocumented variable in lex, and in flex
 * we explicitely switch it on.
 */
extern int yylineno;
#endif

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
  if (!((servers || (servers=DA_CREATE(servparm_t))) && (servers=DA_GROW1(servers)))) {
    fprintf(stderr,"Error: out of memory.\n");
    exit(1);
  }
  DA_LAST(servers)=*serv;
}

static char *addr_add(servparm_t *sp, char *ipstr);
static char *slist_add(servparm_t *sp, char *nm, int tp);

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
%token <num> QUERY_PORT_START
%token <num> QUERY_PORT_END

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
%token <num> LABEL

%token <num> A
%token <num> PTR
%token <num> MX
%token <num> SOA
%token <num> CNAME
%token <num> NAME
%token <num> OWNER
%token <num> TTL
%token <num> TYPES
%token <num> FILET
%token <num> SERVE_ALIASES
%token <num> AUTHREC

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
%type <num>  ip_list;

%%
file:		/* nothing */		{}
		| file spec   		{}	
		;

spec:		GLOBAL '{' glob_s '}'	{}
		| SERVER '{' {server=serv_presets; } serv_s '}'
			{
				if (!server.atup_a) {
					yyerror("bad ip or no ip specified in section");
					YYERROR;
				}
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
		| RR '{' 
				{
					c_owner[0]='\0';
					c_name[0]='\0';
					c_ttl=86400;
					c_flags=DF_LOCAL;
					
				} 
			rr_s '}'
			{
				if (!c_owner[0] || !c_name[0]) {
				        yyerror("must specify owner and name in a rr record.");
					YYERROR;
				}

				/* add the authority */
				add_cent_rr(&c_cent, c_ttl,0,CF_LOCAL, strlen(c_owner)+1, c_owner, T_NS,0);
				add_cache(c_cent);
				free_cent(c_cent,0);
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
					c_flags=DF_LOCAL;
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
				YSTRASSIGN(global.cache_dir, $3);
			}
		| SERVER_PORT '=' NUMBER ';'
			{
				global.port=$3;
			}
		| SERVER_IP '=' STRING ';'
			{
				if (!str2pdnsd_a($3,&global.a)) {
					yyerror("bad ip in server_ip= option.");
					YYERROR;
				}
				free($3);
 			}
		| SCHEME_FILE '=' STRING ';'
                        {
				YSTRASSIGN(global.scheme_file, $3);
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
				YSTRNCP(global.run_as, $3, "run_as");
				free($3);
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
			  YSTRASSIGN(pidfile,$3);
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
		| QUERY_PORT_START '=' NUMBER ';'
			{
				if($3>65536||$3<1024) {
					yyerror("bad value for query_port_start.");
					YYERROR;
				} else if (global.query_port_end <= $3) {
					yyerror("query_port_end must be greater than query_port_start.");
					YYERROR;
				} else {
					global.query_port_start=$3;
				}
			}
		| QUERY_PORT_END '=' NUMBER ';'
			{
				if($3>65536||$3<1024) {
					yyerror("bad value for query_port_end.");
					YYERROR;
				} else if (global.query_port_start >= $3) {
					yyerror("query_port_end must be greater than query_port_start.");
					YYERROR;
				} else {
					global.query_port_end=$3;
				}
			}
		;

serv_s:		/* empty */		{}
		| serv_s serv_el	{}
		;

ip_list:	STRING
			{
			  char *e;

			  if ((e=addr_add(&server,$1))!=NULL) {
			    yyerror(e);
			    YYERROR;
			  }
			  free($1);
			}
		| ip_list ',' STRING
			{
			  char *e;

			  if ((e=addr_add(&server,$3))!=NULL) {
			    yyerror(e);
			    YYERROR;
			  }
			  free($3);
			}
		;


serv_el:	IP '=' ip_list ';'	{}

		| PORT '=' NUMBER ';'
			{
				server.port=$3;
			}
		| SCHEME '=' STRING ';'
			{
				YSTRNCP(server.scheme, $3, "scheme");
				free($3);
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
				if (!str2pdnsd_a($3,&server.ping_a)) {
					yyerror("bad ip in ping_ip= option.");
					YYERROR;
				}
				free($3);
			}
		| UPTEST_CMD '=' STRING ';'
			{
				YSTRASSIGN(server.uptest_cmd, $3);
			}
		| UPTEST_CMD '=' STRING ',' STRING ';'
			{
				YSTRASSIGN(server.uptest_cmd, $3);
				YSTRNCP(server.uptest_usr, $5, "uptest_cmd");
				free($5);
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
				YSTRNCP(server.interface, $3, "interface");
				free($3);
			}
 		| DEVICE '=' STRING  ';'
 			{
				YSTRNCP(server.device, $3, "device");
				free($3);
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
					server.preset=($3==C_ON);
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
				if ($3==C_INCLUDED || $3==C_EXCLUDED || $3==C_SIMPLE_ONLY || $3==C_FQDN_ONLY) {
					server.policy=$3;
				} else {
					yyerror("bad qualifier in policy= option.");
					YYERROR;
				}
			}
		| INCLUDE '=' STRING ';'
			{
				char *e;
				
				if ((e=slist_add(&server,$3,C_INCLUDED))!=NULL) {
					yyerror(e);
					YYERROR;
				}
				free($3);
			}
		| EXCLUDE '=' STRING ';'
			{
				char *e;
				
				if ((e=slist_add(&server,$3,C_EXCLUDED))!=NULL) {
					yyerror(e);
					YYERROR;
				}
				free($3);
			}
		| LABEL '=' STRING ';'
			{
				YSTRNCP(server.label, $3, "label");
				free($3);
			}
		;

rr_s:		/* empty */		{}
		| rr_s rr_el	{}
		;

rr_el:		NAME '=' STRING ';'
			{
				if (strlen($3)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				YSTRNCP(c_name, $3, "name");
				if (c_owner[0]) {
					if (!init_cent(&c_cent, c_name, c_flags, time(NULL), 0, 0)) {
						fprintf(stderr,"Out of memory.\n");
						YYERROR;
					}
				}
				free($3);
			}			
		| OWNER '=' STRING ';'
			{
				if (strlen($3)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				if (!str2rhn($3,c_owner)) {
					yyerror("bad domain name - must end in root domain.");
					YYERROR;
				}
				if (c_name[0]) {
					if (!init_cent(&c_cent, c_name, c_flags, time(NULL), 0, 0)) {
						fprintf(stderr,"Out of memory.\n");
						YYERROR;
					}
				}
				free($3);
			}
		| TTL '=' NUMBER ';'
			{
				c_ttl=$3;
			}
		| AUTHREC '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF) {
					c_flags=($3==C_ON)?DF_LOCAL:0;
				} else {
					yyerror("Bad qualifier in authrec= option.");
					YYERROR;
				}
			}
		| A '=' STRING ';'
			{
				int sz,tp;
				struct in_addr ina4;
				pdnsd_a c_a;

				if (!c_owner[0] || !c_name[0]) {
					yyerror("you must specify owner and name before a,ptr and soa records.");
					YYERROR;
				}
				if (inet_aton($3,&ina4)) {
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

					if ((err=inet_pton(AF_INET6,$3,&c_a.ipv6))!=1) {
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
				free($3);
			}
		| PTR '=' STRING ';'
			{
				unsigned char c_ptr[256];

				if (!c_owner[0] || !c_name[0]) {
					yyerror("you must specify owner and name before a,ptr and soa records.");
					YYERROR;
				}
				if (strlen($3)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				if (!str2rhn($3,c_ptr)) {
					yyerror("bad domain name - must end in root domain.");
					YYERROR;
				}
				add_cent_rr(&c_cent,c_ttl,0,CF_LOCAL,rhnlen(c_ptr),c_ptr,T_PTR,0);
				free($3);
			}
		| MX '=' STRING ',' NUMBER ';'
			{
				unsigned char c_ptr[256];
				unsigned char buf[532];
				uint16_t ts;

				if (!c_owner[0] || !c_name[0]) {
					yyerror("you must specify owner and name before mx records.");
					YYERROR;
				}
				if (strlen($3)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				if (!str2rhn($3,c_ptr)) {
					yyerror("bad domain name - must end in root domain.");
					YYERROR;
				}
				memset(buf,0,sizeof(buf));
				ts=htons($5);
				memcpy(buf,&ts,2);
				rhncpy(buf+2,c_ptr);
				add_cent_rr(&c_cent,c_ttl,0,CF_LOCAL,rhnlen(c_ptr)+2,buf,T_MX,0);
				free($3);
			}
		| CNAME '=' STRING ';'
			{
				unsigned char c_ptr[256];

				if (!c_owner[0] || !c_name[0]) {
					yyerror("you must specify owner and name before cname records.");
					YYERROR;
				}
				if (strlen($3)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				if (!str2rhn($3,c_ptr)) {
					yyerror("bad domain name - must end in root domain.");
					YYERROR;
				}
				add_cent_rr(&c_cent,c_ttl,0,CF_LOCAL,rhnlen(c_ptr),c_ptr,T_CNAME,0);
				free($3);
			}
		| SOA '=' STRING ',' STRING ',' NUMBER ',' NUMBER ',' NUMBER ',' NUMBER ',' NUMBER ';'
			{
				unsigned char c_soa_owner[256];
			        unsigned char c_soa_r[256];
				unsigned char buf[532];
				soa_r_t c_soa;
				int idx;

				if (!c_owner[0] || !c_name[0]) {
					yyerror("you must specify owner and name before a, ptr and soa records.");
					YYERROR;
				}
				if (strlen($3)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				if (!str2rhn($3,c_soa_owner)) {
					yyerror("bad domain name - must end in root domain.");
					YYERROR;
				}
				if (strlen($5)>255) {
					yyerror("name too long.");
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
				memset(buf,0,sizeof(buf));
				idx=rhncpy(buf,c_soa_owner);
				idx+=rhncpy(buf+idx,c_soa_r);
				memcpy(buf+idx,&c_soa,sizeof(soa_r_t));
				idx+=sizeof(soa_r_t);
				add_cent_rr(&c_cent,c_ttl,0,CF_LOCAL,idx,buf,T_SOA,0);
				free($3);
				free($5);
			}			
		;

source_s:	/* empty */		{}
		| source_s source_el	{}
		;

source_el:	OWNER '=' STRING ';'
			{
				if (strlen($3)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				if (!str2rhn($3,c_owner)) {
					yyerror("bad domain name - must end in root domain.");
					YYERROR;
				}
				free($3);
			}
		| TTL '=' NUMBER ';'
			{
				c_ttl=$3;
			}
		| FILET '=' STRING ';'
			{
				if (!c_owner[0]) {
					yyerror("you must specify owner before file= in source records.");
					YYERROR;
				}
				{
				  char *errstr;
				  if (!read_hosts($3, c_owner, c_ttl, c_flags, c_aliases,&errstr)) {
					fprintf(stderr,"%s\n",errstr?:"Out of memory");
					if(errstr) free(errstr);
				  }
				}
				free($3);
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
		| AUTHREC '=' CONST ';'
			{
				if ($3==C_ON || $3==C_OFF) {
					c_flags=($3==C_ON)?DF_LOCAL:0;
				} else {
					yyerror("Bad qualifier in authrec= option.");
					YYERROR;
				}
			}
		;


rrneg_s:	/* empty */		{}
		| rrneg_s rrneg_el	{}
		;


rrneg_el:	NAME '=' STRING ';'
			{
				if (strlen($3)>255) {
					yyerror("name too long.");
					YYERROR;
				}
				YSTRNCP(c_name,$3, "name");
				free($3);
			}			
		| TTL '=' NUMBER ';'
			{
				c_ttl=$3;
			}
                | TYPES '=' NDOMAIN ';'
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
					fprintf(stderr,"Out of memory.\n");
					YYERROR;
				}
				add_cache(c_cent);
				free_cent(c_cent,0);
			}
                | TYPES '=' rr_type_list ';'
			{
			}
		;

rr_type_list:	rr_type 			{}
		| rr_type ',' rr_type_list 	{}
		;

rr_type:   RRTYPE
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
					fprintf(stderr,"Out of memory.\n");
					YYERROR;
				}
				if (!add_cent_rrset(&c_cent,$1,c_ttl,0,CF_LOCAL|CF_NEGATIVE,0, 0)) {
					free_cent(c_cent,0);
					fprintf(stderr,"Out of memory.\n");
					YYERROR;
				}
				add_cache(c_cent);
				free_cent(c_cent, 0);
				
			}
                ; 

/* errnt:		ERROR		 	{YYERROR;} */
%%

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
  if (!((servers || (servers=DA_CREATE(servparm_t))) && (servers=DA_GROW1(servers)))) {
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

  if (!((sp->atup_a || (sp->atup_a=DA_CREATE(atup_t))) && (sp->atup_a=DA_GROW1(sp->atup_a)))) {
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
					
	if (!((sp->alist || (sp->alist=DA_CREATE(slist_t))) && (sp->alist=DA_GROW1(sp->alist)))) {
	  return "out of memory!";
	}
	sl=&DA_LAST(sp->alist);
	sl->rule=tp;
	if (strlen(nm)>255)
	  return "include/exclude: name too long!";
	if (!(sl->domain=strdup(nm)))
	  return "out of memory!";
	{
	  char *p=strchr(sl->domain,0);
	  if (p==sl->domain || *(p-1)!='.') 
	    return "domain name must end in dot for include=/exclude=.";
	}
	return NULL;
}
