/* conf-parser.c - Parser for pdnsd config files.
   Copyright (C) 2004 Paul A. Rombouts.

   Based on the files conf-lex.l and conf-parse.y written by 
   Thomas Moestl.
   This version was rewritten in C from scratch and doesn't require (f)lex
   or yacc/bison.


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
#include <errno.h>
#include <stdarg.h>
#include "conff.h"
#include "consts.h"
#include "cache.h"
#include "dns.h"
#include "dns_query.h"
#include "helpers.h"
#include "rr_types.h"
#include "conf-keywords.h"
#include "conf-parser.h"

static unsigned int linenr=0;


static void report_error (const char *msg)
{
  fprintf(stderr, "Error in config file (line %u): %s\n",linenr,msg);
}

static void report_errorf (const char *frm,...)
{
  va_list va;
  fprintf(stderr, "Error in config file (line %u): ",linenr);
  va_start(va,frm);
  vfprintf(stderr,frm,va);
  va_end(va);
  fputc('\n',stderr);
}

static void report_name_error (const char *msg,const char *name, size_t len)
{
  fprintf(stderr, "Error in config file (line %u): ",linenr);
  fputs(msg,stderr);
  fwrite(name,1,len,stderr);
  fputc('\n',stderr);
}

/* return pointer to next character in linebuffer after skipping blanks and comments */
static char* getnextp(char **buf,size_t *n, FILE* in, char *p)
{
  if(!p) goto nextline;
 tryagain:
  if(!*p) {
  nextline:
    do {
      if(getline(buf,n,in)<0)
	return NULL;
      ++linenr;
      p=*buf;
    } while(!*p);
  }
  if(isspace(*p)) {
    ++p; goto tryagain;
  }
  if(*p=='#')
    goto nextline;
  if(*p=='/') {
    if(*(p+1)=='/')
      goto nextline;
    if(*(p+1)=='*') {
      int lev=1;
      p +=2;
      for(;;) {
	while(*p) {
	  if(*p=='/' && *(p+1)=='*') {
	    ++lev;
	    p +=2;
	    continue;
	  }
	  else if(*p=='*' && *(p+1)=='/') {
	    p +=2;
	    if(--lev==0) goto tryagain;
	    continue;
	  }
	  ++p;
	}
	if(getline(buf,n,in)<0) {
	  report_error("comment without closing */");
	  return NULL;
	}
	++linenr;
	p=*buf;
      }
    }
  }

  return p;
}

static int scan_string(char **startp,char **curp,size_t *lenp)
{
  char *start,*cur=*curp;

  if(*cur=='"') {
    ++cur;
    start=cur;
    for(;;++cur) {
      if(!*cur) {
	report_error("string without closing quote");
	return 0;
      }
      if(*cur=='"') break;
    }
    *lenp=cur-start;
    ++cur;
  }
  else {
    start=cur;
    while(*cur &&
	  !(isspace(*cur) ||
	    *cur==',' || *cur==';' ||
	    *cur=='{' || *cur=='}' ||
	    *cur=='"' || *cur=='#' ||
	    (*cur=='/' && (*(cur+1)=='/'|| *(cur+1)=='*'))))
      ++cur;
    *lenp=cur-start;
  }

  *startp=start;
  *curp=cur;
  return 1;
}


#define lookup_keyword(name,len,dic) binsearch_keyword(name,len,dic,sizeof(dic)/sizeof(namevalue_t))
static const char *parse_ip(const char *ipstr,size_t len, pdnsd_a *a);
static const char *addr_add(atup_array *ata, const char *ipstr, size_t len);
static const char *slist_add(slist_array *sla, const char *nm, size_t len, int tp);
#define include_list_add(sla,nm,len) slist_add(sla,nm,len,C_INCLUDED)
#define exclude_list_add(sla,nm,len) slist_add(sla,nm,len,C_EXCLUDED)
static const char *zone_add(zone_array *za, const char *zone, size_t len);

#define CONCAT(a,b) a ## b
/* a macro for concatenating tokens that expands its arguments */
#define XCONCAT(a,b) CONCAT(a,b)
/* a macro for generating (mostly) unique labels using line number */
#define N_LABEL(pre) XCONCAT(pre,__LINE__)


#define SCAN_ALPHANUM(start,cur,len)			\
{							\
  (start)=(cur);					\
  do {							\
    ++(cur);						\
  } while(*(cur) && (isalnum(*(cur)) || *(cur)=='_'));	\
  (len)=(cur)-(start);					\
}

#define SCAN_STRING(start,cur,len)		\
{						\
  if(!scan_string(&(start),&(cur),&(len))) {	\
    PARSERROR;					\
  }						\
}

#define STRNDUP(dst,src,len)			\
{						\
  if(dst) free(dst);				\
  if(!((dst)=strndup(src,len))) {		\
    fprintf(stderr,"Error: out of memory.\n");	\
    PARSERROR;					\
  }						\
}

#define STRNCP(dst,src,len,errmsg)		\
{						\
  if ((len)<sizeof(dst)) {			\
    memcpy(dst,src,len);			\
    (dst)[len]=0;				\
  }						\
  else {					\
    report_error(errmsg ": string too long");	\
    PARSERROR;					\
  }						\
}

/* TEMPSTRNCPY declares dst as a variable length array */
#define TEMPSTRNCPY(dst,src,len)		\
  char dst[(len)+1];				\
  memcpy(dst,src,len);				\
  dst[len]=0;

#define SCAN_STRING_LIST(dst,cur,addfunc)	\
{						\
  for(;;) {					\
    char *_strbeg; const char *_err;		\
    unsigned int _len;				\
    SCAN_STRING(_strbeg,cur,_len);		\
    if((_err=addfunc(dst,_strbeg,_len))) {	\
      report_error(_err);			\
      PARSERROR;				\
    }						\
    SKIP_BLANKS(cur);				\
    if(*(cur)!=',') break;			\
    ++(cur);					\
    SKIP_BLANKS(cur);				\
  }						\
}

#define ASSIGN_ON_OFF(dst,cur,onoff,errmsg)	\
{						\
  if(isalpha(*(cur))) {				\
    char *_str;					\
    unsigned int _len;				\
    int _cnst;					\
    SCAN_ALPHANUM(_str,cur,_len);		\
    _cnst=lookup_const(_str,_len);		\
    if(_cnst==C_ON || _cnst==C_OFF) {		\
      (dst)=(_cnst==(onoff));			\
    }						\
    else {					\
      goto N_LABEL(ASSIGN_ON_OFF_) ;		\
    }						\
  }						\
  else {					\
  N_LABEL(ASSIGN_ON_OFF_) :			\
    report_error(errmsg);			\
    PARSERROR;					\
  }						\
}

#define ASSIGN_CONST(dst,cur,test,errmsg)	\
{						\
  if(isalpha(*(cur))) {				\
    char *_str;					\
    unsigned int _len;				\
    SCAN_ALPHANUM(_str,cur,_len);		\
    (dst)=lookup_const(_str,_len);		\
    if(!(test)) {				\
      goto N_LABEL(ASSIGN_CONST_) ;		\
    }						\
  }						\
  else {					\
  N_LABEL(ASSIGN_CONST_) :			\
    report_error(errmsg);			\
    PARSERROR;					\
  }						\
}

#define SCAN_UNSIGNED_NUM(dst,cur,errmsg)				\
{									\
  if(isdigit(*(cur))) {							\
    dst=strtol(cur,&(cur),0);						\
  }									\
  else {								\
    report_error("expected unsigned integer value for " errmsg);	\
    PARSERROR;								\
  }									\
}

#define PARSESTR2RHN(src,len,dst)		\
{						\
  const char *_err;				\
  if ((_err=parsestr2rhn(src,len,dst))) {	\
    report_error(_err);				\
    PARSERROR;					\
  }						\
}


/* Copy a domain name, adding a dot at the end if necessary
   The format of the name (including the length) is checked with parsestr2rhn()
*/
#define DOM_NAME_CPY(dst,src,len)		\
{						\
  unsigned char _buf[256];			\
  PARSESTR2RHN(src,len,_buf);			\
  memcpy(dst,src,len);				\
  (dst)[len]=0;					\
  if((len)==0 || (dst)[(len)-1]!='.') {		\
    (dst)[len]='.'; (dst)[(len)+1]=0;		\
  }						\
}

# define SKIP_COMMA(cur,errmsg)				\
{							\
  SKIP_BLANKS(cur);					\
  if(*(cur)!=',') {report_error(errmsg); PARSERROR;}	\
  ++(cur);						\
  SKIP_BLANKS(cur);					\
}


/* Parse configuration file.
   Return 1 on success, 0 on failure.
   Note: this code still leaks memory in some failure cases.
   This shouldn't be a problem, because pdnsd will then exit anyway.
*/
int confparse(FILE* in)
{
  char *linebuf,*p,*ps;
  size_t buflen=256,len;
  int retval=0,sechdr,option;
# define SKIP_BLANKS(cur) {if(!((cur)=getnextp(&linebuf,&buflen,in,cur))) goto unexpected_eof;}
# define PARSERROR goto free_linebuf_return

  linebuf=malloc(buflen);
  if(!linebuf) {
    fprintf(stderr,"Error: out of memory.\n");
    return 0;
  }

  p=NULL;
  while((p=getnextp(&linebuf,&buflen,in,p))) {
    if(isalpha(*p)) {
      SCAN_ALPHANUM(ps,p,len);
      sechdr=lookup_keyword(ps,len,section_headers);
      if(!sechdr) {
	report_name_error("invalid section header: ",ps,len);
	PARSERROR;
      }
      SKIP_BLANKS(p);
      if(*p!='{') goto expected_bropen;
      ++p;
      SKIP_BLANKS(p);

      switch(sechdr) {
      case GLOBAL:
	while(isalpha(*p)) {
	  SCAN_ALPHANUM(ps,p,len);
	  option=lookup_keyword(ps,len,global_options);
	  if(!option) {
	    report_name_error("invalid option for global section: ",ps,len);
	    PARSERROR;
	  }
	  SKIP_BLANKS(p);
	  if(*p!='=') goto expected_equals;
	  ++p;
	  SKIP_BLANKS(p);

	  switch(option) {
	  case PERM_CACHE:
	    if (isalpha(*p)) {
	      int cnst;
	      SCAN_ALPHANUM(ps,p,len);
	      cnst=lookup_const(ps,len);
	      if(cnst==C_OFF) {
		global.perm_cache=0;
	      }
	      else
		goto bad_perm_cache_option;
	    }
	    else if(isdigit(*p)) {
	      global.perm_cache=strtol(p,&p,0);
	    }
	    else {
	    bad_perm_cache_option:
	      report_error("bad qualifier in perm_cache= option.");
	      PARSERROR;
	    }
	    break;

	  case CACHE_DIR:
	    SCAN_STRING(ps,p,len);
	    STRNDUP(global.cache_dir,ps,len);
	    break;

	  case SERVER_PORT:
	    SCAN_UNSIGNED_NUM(global.port,p,"server_port option")
	    break;

	  case SERVER_IP:
	    SCAN_STRING(ps,p,len);
	    {
	      const char *err;
	      if ((err=parse_ip(ps,len,&global.a))) {
		report_errorf("%s for the server_ip= option.",err);
		PARSERROR;
	      }
	    }
	    break;

	  case SCHEME_FILE:
	    SCAN_STRING(ps,p,len);
	    STRNDUP(global.scheme_file, ps,len);
	    break;

	  case LINKDOWN_KLUGE:
	    ASSIGN_ON_OFF(global.lndown_kluge,p,C_ON,"bad qualifier in linkdown_kluge= option.");
	    break;

	  case MAX_TTL:
	    SCAN_UNSIGNED_NUM(global.max_ttl,p,"max_ttl option");
	    break;

	  case MIN_TTL:
	    SCAN_UNSIGNED_NUM(global.min_ttl,p,"min_ttl option");
	    break;

	  case RUN_AS:
	    SCAN_STRING(ps,p,len);
	    STRNCP(global.run_as, ps,len, "run_as");
	    break;

	  case STRICT_SETUID:
	    ASSIGN_ON_OFF(global.strict_suid, p,C_ON,"bad qualifier in strict_setuid= option.");
	    break;

	  case PARANOID:
	    ASSIGN_ON_OFF(global.paranoid, p,C_ON,"bad qualifier in paranoid= option.");
	    break;

	  case STATUS_CTL:
	    ASSIGN_ON_OFF(stat_pipe, p,C_ON,"bad qualifier in status_pipe= option.");
	    break;

	  case DAEMON:
	    ASSIGN_ON_OFF(daemon_p, p,C_ON,"bad qualifier in daemon= option.");
	    break;

	  case C_TCP_SERVER:
	    ASSIGN_ON_OFF(notcp, p,C_OFF,"bad qualifier in tcp_server= option.");
#ifdef NO_TCP_SERVER
	    if(!notcp)
	      fprintf(stderr,"pdnsd was compiled without TCP server support. tcp_server=on has no effect.\n");
#endif
	    break;

	  case PID_FILE:
	    SCAN_STRING(ps,p,len);
	    STRNDUP(pidfile,ps,len);
	    break;

	  case C_VERBOSITY:
	    SCAN_UNSIGNED_NUM(verbosity,p,"verbosity option");
	    break;

	  case C_QUERY_METHOD: {
	    int cnst;
	    ASSIGN_CONST(cnst,p,cnst==TCP_ONLY || cnst==UDP_ONLY || cnst==TCP_UDP,"bad qualifier in query_method= option.");
#ifdef NO_TCP_QUERIES
	    if (cnst==TCP_ONLY) {
	      report_error("the tcp_only option is only available when pdnsd is compiled with TCP support.");
	      PARSERROR;
	    }
	    else
#endif
#ifdef NO_UDP_QUERIES
	      if (cnst==UDP_ONLY) {
		report_error("the udp_only option is only available when pdnsd is compiled with UDP support.");
		PARSERROR;
	      }
	      else
#endif
#if defined(NO_TCP_QUERIES) || defined(NO_UDP_QUERIES)
		if (cnst==TCP_UDP) {
		  report_error("the tcp_udp option is only available when pdnsd is compiled with both TCP and UDP support.");
		  PARSERROR;
		}
		else
#endif
		  query_method=cnst;
	  }
	    break;

	  case RUN_IPV4: {
	    int cnst;
	    ASSIGN_CONST(cnst,p,cnst==C_ON || cnst==C_OFF,"bad qualifier in run_ipv4= option.");
#ifndef ENABLE_IPV4
	    if(cnst==C_ON) {
	      report_error("You can only set run_ipv4=on when pdnsd is compiled with IPv4 support.");
	      PARSERROR;
	    }
#endif
#ifndef ENABLE_IPV6
	    if(cnst==C_OFF) {
	      report_error("You can only set run_ipv4=off when pdnsd is compiled with IPv6 support.");
	      PARSERROR;
	    }
#endif
#if defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
	    if(!cmdlineipv) {
	      run_ipv4=(cnst==C_ON); cmdlineipv=-1;
	    }
	    else if(cmdlineipv<0 && run_ipv4!=(cnst==C_ON)) {
	      report_error(cmdlineipv==-1?
			   "IPv4/IPv6 conflict: you are trying to set run_ipv4 to a value that conflicts with a previous run_ipv4 setting.":
			   "You must set the run_ipv4 option before specifying IP addresses.");
	      PARSERROR;
	    }
#endif
	  }
	    break;

	  case IPV4_6_PREFIX:
	    SCAN_STRING(ps,p,len);
#ifdef ENABLE_IPV6
	    if(!cmdlineprefix) {
	      TEMPSTRNCPY(buf,ps,len);
	      if(inet_pton(AF_INET6,buf,&ipv4_6_prefix)<=0) {
		report_error("ipv4_6_prefix: argument not a valid IPv6 address.");
		PARSERROR;
	      }
	    }
#else
	    fprintf(stderr,"pdnsd was compiled without IPv6 support. ipv4_6_prefix option in config file will be ignored.\n");
#endif
	    break;

	  case C_DEBUG:
	    ASSIGN_ON_OFF(debug_p, p,C_ON,"bad qualifier in debug= option.");
#if !DEBUG
	    if(debug_p)
	      fprintf(stderr,"pdnsd was compiled without debugging support. debug=on has no effect.\n");
#endif
	    break;

	  case C_CTL_PERMS:
	    SCAN_UNSIGNED_NUM(global.ctl_perms, p,"ctl_perms option");
	    break;

	  case C_PROC_LIMIT:
	    SCAN_UNSIGNED_NUM(global.proc_limit, p,"proc_limit option");
	    break;

	  case C_PROCQ_LIMIT:
	    SCAN_UNSIGNED_NUM(global.procq_limit, p,"procq_limit option");
	    break;

	  case TCP_QTIMEOUT:
	    SCAN_UNSIGNED_NUM(global.tcp_qtimeout, p,"tcp_qtimeout option");
	    break;

	  case TIMEOUT:
	    SCAN_UNSIGNED_NUM(global.timeout, p,"global timeout option");
	    break;

	  case C_PAR_QUERIES: {
	    int val;
	    SCAN_UNSIGNED_NUM(val, p,"par_queries option");
	    if(val<=0) {
	      report_error("bad value for par_queries.");
	      PARSERROR;
	    } else {
	      global.par_queries=val;
	    }
	  }
	    break;

	  case C_RAND_RECS:
	    ASSIGN_ON_OFF(global.rnd_recs, p,C_ON,"bad qualifier in randomize_recs= option.");
	    break;

	  case NEG_TTL:
	    SCAN_UNSIGNED_NUM(global.neg_ttl, p,"neg_ttl option");
	    break;

	  case NEG_RRS_POL: {
	    int cnst;
	    ASSIGN_CONST(cnst,p,cnst==C_ON || cnst==C_OFF || cnst==C_AUTH,"bad qualifier in neg_rrs_pol= option.");
	    global.neg_rrs_pol=cnst;
	  }
	    break;

	  case NEG_DOMAIN_POL: {
	    int cnst;
	    ASSIGN_CONST(cnst,p,cnst==C_ON || cnst==C_OFF || cnst==C_AUTH,"bad qualifier in neg_domain_pol= option.");
	    global.neg_domain_pol=cnst;
	  }
	    break;

	  case QUERY_PORT_START: {
	    int val;
	    SCAN_UNSIGNED_NUM(val,p,"query_port_start option");
	    if(val<1024||val>65535) {
	      report_error("value for query_port_start out of range.");
	      PARSERROR;
	    }
	    else if (global.query_port_end <= val) {
	      report_error("query_port_end must be greater than query_port_start.");
	      PARSERROR;
	    }
	    else {
	      global.query_port_start=val;
	    }
	  }
	    break;

	  case QUERY_PORT_END: {
	    int val;
	    SCAN_UNSIGNED_NUM(val,p,"query_port_end option");
	    if(val<1024||val>65535) {
	      report_error("value for query_port_end out of range.");
	      PARSERROR;
	    }
	    else if (global.query_port_start >= val) {
	      report_error("query_port_end must be greater than query_port_start.");
	      PARSERROR;
	    }
	    else {
	      global.query_port_end=val;
	    }
	  }
	    break;

	  case DELEGATION_ONLY:
	    SCAN_STRING_LIST(&global.deleg_only_zones,p,zone_add)
	    break;

	  default: /* we should never get here */
	    goto internal_parse_error;
	  } /* end of switch(option) */

	  SKIP_BLANKS(p);
	  if(*p!=';') goto expected_semicolon;
	  ++p;
	  SKIP_BLANKS(p);
	}
	break;

      case SERVER: {
	servparm_t server=serv_presets;

	while(isalpha(*p)) {
	  SCAN_ALPHANUM(ps,p,len);
	  option=lookup_keyword(ps,len,server_options);
	  if(!option) {
	    report_name_error("invalid option for server section: ",ps,len);
	    PARSERROR;
	  }
	  SKIP_BLANKS(p);
	  if(*p!='=') goto expected_equals;
	  ++p;
	  SKIP_BLANKS(p);

	  switch(option) {
	  case IP:
	    SCAN_STRING_LIST(&server.atup_a,p,addr_add);
	    break;

	  case PORT:
	    SCAN_UNSIGNED_NUM(server.port,p,"port option");
	    break;

	  case SCHEME:
	    SCAN_STRING(ps,p,len);
	    STRNCP(server.scheme, ps,len, "scheme");
	    break;

	  case UPTEST: {
	    int cnst;
	    ASSIGN_CONST(cnst,p,cnst==C_PING || cnst==C_NONE || cnst==C_IF || cnst==C_EXEC || cnst==C_DEV || cnst==C_DIALD,"bad qualifier in uptest= option.");
	    server.uptest=cnst;
	  }
	    break;

	  case TIMEOUT:
	    SCAN_UNSIGNED_NUM(server.timeout,p,"timeout option");
	    break;

	  case PING_TIMEOUT:
	    SCAN_UNSIGNED_NUM(server.ping_timeout,p,"ping_timeout option");
	    break;

	  case PING_IP:
	    SCAN_STRING(ps,p,len);
	    {
	      const char *err;
	      if ((err=parse_ip(ps,len,&server.ping_a))) {
		report_errorf("%s for the ping_ip= option.",err);
		PARSERROR;
	      }
	    }
	    break;

	  case UPTEST_CMD:
	    SCAN_STRING(ps,p,len);
	    STRNDUP(server.uptest_cmd, ps,len);
	    SKIP_BLANKS(p);
	    if(*p==',') {
	      ++p;
	      SKIP_BLANKS(p);
	      SCAN_STRING(ps,p,len);
	      STRNCP(server.uptest_usr, ps,len, "second argument of uptest_cmd");
	    }
	    break;

	  case INTERVAL:
	    if(isalpha(*p)) {
	      int cnst;
	      SCAN_ALPHANUM(ps,p,len);
	      cnst=lookup_const(ps,len);
	      if(cnst==C_ONQUERY) {
		server.interval=-1;
	      }
	      else
		goto bad_interval_option;
	    }
	    else if(isdigit(*p)) {
	      server.interval=strtol(p,&p,0);
	    }
	    else {
	    bad_interval_option:
	      report_error("bad qualifier in interval= option.");
	      PARSERROR;
	    }
	    break;

	  case INTERFACE:
	    SCAN_STRING(ps,p,len);
	    STRNCP(server.interface, ps,len, "interface");
	    break;

	  case DEVICE:
	    SCAN_STRING(ps,p,len);
	    STRNCP(server.device, ps,len, "device");
	    break;

	  case PURGE_CACHE:
	    ASSIGN_ON_OFF(server.purge_cache,p,C_ON,"bad qualifier in purge_cache= option.");
	    break;

	  case CACHING:
	    ASSIGN_ON_OFF(server.nocache,p,C_OFF,"bad qualifier in caching= option.");
	    break;

	  case LEAN_QUERY:
	    ASSIGN_ON_OFF(server.lean_query,p,C_ON,"bad qualifier in lean_query= option.");
	    break;

	  case PRESET:
	    ASSIGN_ON_OFF(server.preset,p,C_ON,"bad qualifier in preset= option.");
	    break;

	  case PROXY_ONLY:
	    ASSIGN_ON_OFF(server.is_proxy,p,C_ON,"bad qualifier in proxy_only= option.");
	    break;

	  case POLICY: {
	    int cnst;
	    ASSIGN_CONST(cnst,p,cnst==C_INCLUDED || cnst==C_EXCLUDED || cnst==C_SIMPLE_ONLY || cnst==C_FQDN_ONLY,"bad qualifier in policy= option.");
	    server.policy=cnst;
	  }
	    break;

	  case INCLUDE:
	    SCAN_STRING_LIST(&server.alist,p,include_list_add)
	    break;

	  case EXCLUDE:
	    SCAN_STRING_LIST(&server.alist,p,exclude_list_add)
	    break;

	  case LABEL:
	    SCAN_STRING(ps,p,len);
	    STRNDUP(server.label,ps,len);
	    break;

	  default: /* we should never get here */
	    goto internal_parse_error;
	  } /* end of switch(option) */

	  SKIP_BLANKS(p);
	  if(*p!=';') goto expected_semicolon;
	  ++p;
	  SKIP_BLANKS(p);
	}

	if(*p!='}') goto expected_closing_brace;
	if (server.uptest==C_EXEC) {
	  if (!server.uptest_cmd) {
	    report_error("you must specify uptest_cmd if you specify uptest=exec!");
	    PARSERROR;
	  }
	}
	{
	  int j;
	  for(j=0;j<DA_NEL(server.atup_a);++j)
	    DA_INDEX(server.atup_a,j).is_up=server.preset;
	}
	if(server.interval<0) global.onquery=1;

	if (!(servers=DA_GROW1(servers))) {
	  fprintf(stderr,"Error: out of memory.\n");
	  exit(1);
	}
	DA_LAST(servers)= server;
      }
	break;

      case RR: {
	dns_cent_t c_cent;
	unsigned char c_owner[256];
	unsigned char c_name[256];
	time_t c_ttl;
	unsigned c_flags;

	c_owner[0]='\0';
	c_name[0]='\0';
	c_ttl=86400;
	c_flags=DF_LOCAL;

	while(isalpha(*p)) {
	  SCAN_ALPHANUM(ps,p,len);
	  option=lookup_keyword(ps,len,rr_options);
	  if(!option) {
	    report_name_error("invalid option for rr section: ",ps,len);
	    PARSERROR;
	  }
	  SKIP_BLANKS(p);
	  if(*p!='=') goto expected_equals;
	  ++p;
	  SKIP_BLANKS(p);

	  switch(option) {
	  case NAME:
	    SCAN_STRING(ps,p,len);
	    DOM_NAME_CPY(c_name,ps,len);
	    if (c_owner[0])
	      goto rr_init_cent;
	    break;

	  case OWNER:
	    SCAN_STRING(ps,p,len);
	    PARSESTR2RHN(ps,len,c_owner);
	    if (c_name[0]) {
	    rr_init_cent:
	      if (!init_cent(&c_cent, c_name, 0, time(NULL), c_flags  DBG0)) {
		goto out_of_memory;
	      }
	    }
	    break;

	  case TTL:
	    SCAN_UNSIGNED_NUM(c_ttl,p, "ttl option");
	    break;

	  case AUTHREC: {
	    int cnst;
	    ASSIGN_CONST(cnst,p,cnst==C_ON || cnst==C_OFF,"Bad qualifier in authrec= option.");
	    c_flags=(cnst==C_ON)?DF_LOCAL:0;
	  }
	    break;

	  case A: {
	    int sz,tp;
	    pdnsd_ca c_a;

	    if (!c_owner[0] || !c_name[0])
	      goto no_owner_name_spec;
	    SCAN_STRING(ps,p,len);
	    {
	      TEMPSTRNCPY(buf,ps,len);
	      if (inet_aton(buf,&c_a.ipv4)) {
		tp=T_A;
		sz=sizeof(struct in_addr);
	      }
	      else
#if defined(DNS_NEW_RRS) && defined(ENABLE_IPV6)
		if (inet_pton(AF_INET6,buf,&c_a.ipv6)>0) {
		  tp=T_AAAA;
		  sz=sizeof(struct in6_addr);
		}
		else
#endif
		  {
		    report_error("bad IP address in a= option.");
		    PARSERROR;
		  }
	    }
	    if(!add_cent_rr(&c_cent,tp,c_ttl,0,CF_LOCAL,sz,&c_a,0  DBG0))
	      goto add_cent_failed;
	  }
	    break;

	  case PTR: {
	    unsigned char c_ptr[256];

	    if (!c_owner[0] || !c_name[0])
	      goto no_owner_name_spec;
	    SCAN_STRING(ps,p,len);
	    PARSESTR2RHN(ps,len,c_ptr);
	    if(!add_cent_rr(&c_cent,T_PTR,c_ttl,0,CF_LOCAL,rhnlen(c_ptr),c_ptr,0  DBG0))
	      goto add_cent_failed;
	  }
	    break;

	  case MX: {
	    unsigned char c_mx[258];

	    if (!c_owner[0] || !c_name[0])
	      goto no_owner_name_spec;
	    SCAN_STRING(ps,p,len);
	    PARSESTR2RHN(ps,len,c_mx+2);
	    SKIP_COMMA(p,"missing second argument (preference level) of mx= option");
	    {
	      int pref; uint16_t ts;
	      SCAN_UNSIGNED_NUM(pref,p,"second argument of mx= option");
	      ts=htons(pref);
	      memcpy(c_mx,&ts,2);
	    }
	    if(!add_cent_rr(&c_cent,T_MX,c_ttl,0,CF_LOCAL,rhnlen(c_mx+2)+2,c_mx,0  DBG0))
	      goto add_cent_failed;
	  }
	    break;

	  case CNAME: {
	    unsigned char c_cname[256];

	    if (!c_owner[0] || !c_name[0])
	      goto no_owner_name_spec;
	    SCAN_STRING(ps,p,len);
	    PARSESTR2RHN(ps,len,c_cname);
	    if(!add_cent_rr(&c_cent,T_CNAME,c_ttl,0,CF_LOCAL,rhnlen(c_cname),c_cname,0  DBG0))
	      goto add_cent_failed;
	  }
	    break;

	  case SOA: {
	    unsigned char c_soa_owner[256];
	    unsigned char c_soa_r[256];
	    unsigned char buf[532];
	    soa_r_t c_soa;
	    int val,idx;

	    if (!c_owner[0] || !c_name[0])
	      goto no_owner_name_spec;
	    SCAN_STRING(ps,p,len);
	    PARSESTR2RHN(ps,len,c_soa_owner);
	    SKIP_COMMA(p,"missing 2nd argument of soa= option");
	    SCAN_STRING(ps,p,len);
	    PARSESTR2RHN(ps,len,c_soa_r);
	    SKIP_COMMA(p,"missing 3rd argument of soa= option");
	    SCAN_UNSIGNED_NUM(val,p,"3rd argument of soa= option");
	    c_soa.serial=htonl(val);
	    SKIP_COMMA(p,"missing 4th argument of soa= option");
	    SCAN_UNSIGNED_NUM(val,p,"4th argument of soa= option");
	    c_soa.refresh=htonl(val);
	    SKIP_COMMA(p,"missing 5th argument of soa= option");
	    SCAN_UNSIGNED_NUM(val,p,"5th argument of soa= option");
	    c_soa.retry=htonl(val);
	    SKIP_COMMA(p,"missing 6th argument of soa= option");
	    SCAN_UNSIGNED_NUM(val,p,"6th argument of soa= option");
	    c_soa.expire=htonl(val);
	    SKIP_COMMA(p,"missing 7th argument of soa= option");
	    SCAN_UNSIGNED_NUM(val,p,"7th argument of soa= option");
	    c_soa.minimum=htonl(val);
	    /* memset(buf,0,sizeof(buf)); */
	    idx=rhncpy(buf,c_soa_owner);
	    idx+=rhncpy(buf+idx,c_soa_r);
	    memcpy(buf+idx,&c_soa,sizeof(soa_r_t));
	    idx+=sizeof(soa_r_t);
	    if(!add_cent_rr(&c_cent,T_SOA,c_ttl,0,CF_LOCAL,idx,buf,0  DBG0))
	      goto add_cent_failed;
	  }
	    break;

	  default: /* we should never get here */
	    goto internal_parse_error;
	  } /* end of switch(option) */

	  SKIP_BLANKS(p);
	  if(*p!=';') goto expected_semicolon;
	  ++p;
	  SKIP_BLANKS(p);
	}

	if(*p!='}') goto expected_closing_brace;
	if (!c_owner[0] || !c_name[0]) {
	  report_error("must specify owner and name in a rr record.");
	  PARSERROR;
	}

	/* add the authority */
	if(!add_cent_rr(&c_cent, T_NS, c_ttl,0,CF_LOCAL, rhnlen(c_owner), c_owner,0  DBG0)) {
	add_cent_failed:
	  free_cent(&c_cent  DBG0);
	  goto out_of_memory;
	}
	add_cache(&c_cent);
	free_cent(&c_cent  DBG0);
      }
	break;

      case SOURCE: {
	unsigned char c_owner[256];
	time_t c_ttl;
	unsigned c_flags;
	unsigned char c_aliases;

	c_owner[0]='\0';
	c_ttl=86400;
	c_flags=DF_LOCAL;
	c_aliases=0;

	while(isalpha(*p)) {
	  SCAN_ALPHANUM(ps,p,len);
	  option=lookup_keyword(ps,len,source_options);
	  if(!option) {
	    report_name_error("invalid option for source section: ",ps,len);
	    PARSERROR;
	  }
	  SKIP_BLANKS(p);
	  if(*p!='=') goto expected_equals;
	  ++p;
	  SKIP_BLANKS(p);

	  switch(option) {
	  case OWNER:
	    SCAN_STRING(ps,p,len);
	    PARSESTR2RHN(ps,len,c_owner);
	    break;

	  case TTL:
	    SCAN_UNSIGNED_NUM(c_ttl,p,"ttl option");
	    break;

	  case FILET:
	    if (!c_owner[0]) {
	      report_error("you must specify owner before file= in source records.");
	      PARSERROR;
	    }
	    SCAN_STRING(ps,p,len);
	    {
	      char *errstr;
	      TEMPSTRNCPY(fn,ps,len);
	      if (!read_hosts(fn, c_owner, c_ttl, c_flags, c_aliases,&errstr)) {
		fprintf(stderr,"%s\n",errstr?:"Out of memory");
		if(errstr) free(errstr);
	      }
	    }
	    break;

	  case SERVE_ALIASES:
	    ASSIGN_ON_OFF(c_aliases,p,C_ON,"Bad qualifier in serve_aliases= option.");
	    break;

	  case AUTHREC: {
	    int cnst;
	    ASSIGN_CONST(cnst,p,cnst==C_ON || cnst==C_OFF,"Bad qualifier in authrec= option.");
	    c_flags=(cnst==C_ON)?DF_LOCAL:0;
	  }
	    break;

	  default: /* we should never get here */
	    goto internal_parse_error;
	  } /* end of switch(option) */

	  SKIP_BLANKS(p);
	  if(*p!=';') goto expected_semicolon;
	  ++p;
	  SKIP_BLANKS(p);
	}

	if(*p!='}') goto expected_closing_brace;
	if (c_owner[0]=='\0') {
	  report_error("you must specify owner in a source record.");
	  PARSERROR;
	}
      }
	break;

      case NEG: {
	unsigned char c_name[256];
	time_t c_ttl;
	unsigned char htp,hdtp;

	htp=0;
	hdtp=0;
	c_name[0]='\0';
	c_ttl=86400;

	while(isalpha(*p)) {
	  SCAN_ALPHANUM(ps,p,len);
	  option=lookup_keyword(ps,len,neg_options);
	  if(!option) {
	    report_name_error("invalid option for neg section: ",ps,len);
	    PARSERROR;
	  }
	  SKIP_BLANKS(p);
	  if(*p!='=') goto expected_equals;
	  ++p;
	  SKIP_BLANKS(p);

	  switch(option) {
	  case NAME:
	    SCAN_STRING(ps,p,len);
	    DOM_NAME_CPY(c_name,ps,len);
	    break;

	  case TTL:
	    SCAN_UNSIGNED_NUM(c_ttl,p, "ttl option");
	    break;

	  case TYPES:
	    if (!c_name[0]) {
	      report_error("you must specify a name before the types= option.");
	      PARSERROR;
	    }
	    if (isalpha(*p)) {
	      int cnst;
	      dns_cent_t c_cent;
	      SCAN_ALPHANUM(ps,p,len);
	      cnst=lookup_const(ps,len);
	      if(cnst==C_DOMAIN) {
		if (htp) {
		  report_error("You may not specify types=domain together with other types!");
		  PARSERROR;
		}
		hdtp=1;
		if (!init_cent(&c_cent, c_name, c_ttl, time(NULL), DF_LOCAL|DF_NEGATIVE  DBG0))
		  goto out_of_memory;
	      }
	      else if(cnst==0) {
		if (hdtp) {
		  report_error("You may not specify types=domain together with other types!.");
		  PARSERROR;
		}
		htp=1;
		if (!init_cent(&c_cent, c_name, 0, time(NULL), 0  DBG0))
		  goto out_of_memory;
		for(;;) {
		  {
		    TEMPSTRNCPY(buf,ps,len);
		    cnst=rr_tp_byname(buf);
		  }
		  if(cnst==-1) {
		    report_name_error("unrecognized rr type used as argument for types= option: ",ps,len);
		    PARSERROR;
		  }
		  if (!c_cent.rr[cnst-T_MIN] && !add_cent_rrset(&c_cent,cnst,c_ttl,0,CF_LOCAL|CF_NEGATIVE,0  DBG0)) {
		    free_cent(&c_cent  DBG0);
		    goto out_of_memory;
		  }
		  SKIP_BLANKS(p);
		  if(*p!=',') break;
		  ++p;
		  SKIP_BLANKS(p);
		  if (!isalpha(*p))
		    goto bad_types_option;
		  SCAN_ALPHANUM(ps,p,len);
		}
	      }
	      else
		goto bad_types_option;

	      add_cache(&c_cent);
	      free_cent(&c_cent  DBG0);
	    }
	    else {
	    bad_types_option:
	      report_error("Bad argument for types= option.");
	      PARSERROR;
	    }
	    break;

	  default: /* we should never get here */
	    goto internal_parse_error;
	  } /* end of switch(option) */

	  SKIP_BLANKS(p);
	  if(*p!=';') goto expected_semicolon;
	  ++p;
	  SKIP_BLANKS(p);
	}
      }
	break;

      default: /* we should never get here */
	goto internal_parse_error;
      } /* end of switch(sechdr) */

      if(*p!='}') goto expected_closing_brace;
      ++p;
    }
    else {
      report_error("expected section header");
      PARSERROR;
    }
  }

  if(feof(in))
    retval=1; /* success */
  else
    goto input_error;

  goto free_linebuf_return;

 expected_bropen:
  report_error("expected opening brace after section name");
  PARSERROR;

 expected_closing_brace:
  report_error("expected beginning of new option or closing brace");
  PARSERROR;

 expected_equals:
  report_error("expected equals sign after option name");
  PARSERROR;

 expected_semicolon:
  report_error("too many arguments to option or missing semicolon");
  PARSERROR;

 no_owner_name_spec:
  report_error("you must specify owner and name before a,ptr,cname,mx and soa records.");
  PARSERROR;

 internal_parse_error:
  fprintf(stderr,"Internal inconsistency detected while parsing line %u of config file.\n"
	         "Please consider reporting this error to one of the maintainers.\n",linenr);
  PARSERROR;

 out_of_memory:
  fprintf(stderr,"Error: out of memory.\n");
  PARSERROR;

 unexpected_eof:
  if(feof(in))
    report_error("unexpected end of file");
  else
    input_error: fprintf(stderr,"Error while reading config file: %s\n",strerror(errno));

 free_linebuf_return:
  free(linebuf);
  return retval;

#undef SKIP_BLANKS
#undef PARSERROR
}

static const char* parse_ip(const char *ipstr,size_t len, pdnsd_a *a)
{
#if defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
	if(!cmdlineipv) cmdlineipv=-2;
#endif
	{
		TEMPSTRNCPY(buf,ipstr,len);
		if(!str2pdnsd_a(buf,a)) {
#if defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
			if(run_ipv4 && inet_pton(AF_INET6,buf,&a->ipv6)>0) {
				return "You should set run_ipv4=off or use the command-line option -6"
					" before specifying an IPv6 address";
			}
#endif
			return "bad IP address";
		}
	}
	return NULL;
}

static const char *addr_add(atup_array *ata, const char *ipstr, size_t len)
{
	atup_t *at;
	pdnsd_a addr;

#if defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
	if(!cmdlineipv) cmdlineipv=-2;
#endif
	{
		TEMPSTRNCPY(buf,ipstr,len);
		if(!str2pdnsd_a(buf,&addr)) {
#if defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
			if(run_ipv4 && inet_pton(AF_INET6,buf,&addr.ipv6)>0) {
				fprintf(stderr,"IPv6 address in line %d of config file ignored while running in IPv4 mode.\n",linenr);
				return NULL;
			}
#endif
			return "bad IP address in ip= option.";
		}
	}

	if (!(*ata=DA_GROW1(*ata))) {
		return "out of memory!";
	}
	at=&DA_LAST(*ata);
	at->a = addr;
	at->is_up=0;
	at->i_ts=0;
	return NULL;
}

static const char *slist_add(slist_array *sla, const char *nm, size_t len, int tp)
{
 	slist_t *sl;
	unsigned int adddot=0;

	if (len==0 || nm[len-1]!='.') adddot=1;
	if (len+adddot>255)
		return "include/exclude: name too long!";
	if (!(*sla=DA_GROW1(*sla))) {
		return "out of memory!";
	}
	sl=&DA_LAST(*sla);
	sl->rule=tp;

	if (!(sl->domain=malloc(len+adddot+1)))
		return "out of memory!";
	memcpy(sl->domain,nm,len);
	if(adddot) {
		sl->domain[len++]='.';
	}
	sl->domain[len]='\0';
	return NULL;
}

static const char *zone_add(zone_array *za, const char *zone, size_t len)
{
	zone_t z;
	size_t rlen;
	const char *err;
	unsigned char rhn[256];

	if((err=parsestr2rhn(zone,len,rhn)))
	  return err;
	rlen=rhnlen(rhn);
	if(!(*za=DA_GROW1(*za)) || !(DA_LAST(*za)=z=malloc(rlen)))
	  return "out of memory!";
	memcpy(z,rhn,rlen);
	return NULL;
}
