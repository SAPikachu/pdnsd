/* conf-parser.c - Parser for pdnsd config files.
   Copyright (C) 2004, 2005 Paul A. Rombouts.

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
#if defined(HAVE_STRUCT_IFREQ)
#include <sys/ioctl.h>
#endif
#include "conff.h"
#include "consts.h"
#include "cache.h"
#include "dns.h"
#include "helpers.h"
#include "rr_types.h"
#include "netdev.h"
#include "conf-keywords.h"
#include "conf-parser.h"

static unsigned int linenr=0;


static char *report_error (const char *msg)
{
  char *retval;
  if(asprintf(&retval, "Error in config file (line %u): %s",linenr,msg)<0)
    retval=NULL;

  return retval;
}

static char *report_errorf (const char *frm,...) printfunc(1, 2);
static char *report_errorf (const char *frm,...)
{
  char *msg,*retval; int mlen;
  va_list va;
  va_start(va,frm);
  mlen=vasprintf(&msg,frm,va);
  va_end(va);
  if(mlen<0) return NULL;
  retval=report_error(msg);
  free(msg);
  return retval;
}

/* return pointer to next character in linebuffer after skipping blanks and comments */
static char* getnextp(char **buf, size_t *n, FILE* in, char *p, char **errstr)
{
  if(!p) goto nextline;
 tryagain:
  if(!*p) {
  nextline:
    do {
      if(getline(buf,n,in)<0) {
	*errstr=NULL;
	return NULL;
      }
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
	  *errstr=report_error("comment without closing */");
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
	/* string without closing quote */
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
static void check_localaddrs(servparm_t *serv);
static int read_resolv_conf(const char *fn, atup_array *ata, char **errstr);
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

#define SCAN_STRING(start,cur,len)			\
{							\
  if(!scan_string(&(start),&(cur),&(len))) {		\
    REPORT_ERROR("string without closing quote");	\
    PARSERROR;						\
  }							\
}

#define STRNDUP(dst,src,len)			\
{						\
  if(dst) free(dst);				\
  if(!((dst)=strndup(src,len))) {		\
    *errstr=NULL;				\
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
    REPORT_ERROR(errmsg ": string too long");	\
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
    size_t _len;				\
    SCAN_STRING(_strbeg,cur,_len);		\
    if((_err=addfunc(dst,_strbeg,_len))) {	\
      REPORT_ERROR(_err);			\
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
    size_t _len;				\
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
    REPORT_ERROR(errmsg);			\
    PARSERROR;					\
  }						\
}

#define ASSIGN_CONST(dst,cur,test,errmsg)	\
{						\
  if(isalpha(*(cur))) {				\
    char *_str;					\
    size_t _len;				\
    SCAN_ALPHANUM(_str,cur,_len);		\
    (dst)=lookup_const(_str,_len);		\
    if(!(test)) {				\
      goto N_LABEL(ASSIGN_CONST_) ;		\
    }						\
  }						\
  else {					\
  N_LABEL(ASSIGN_CONST_) :			\
    REPORT_ERROR(errmsg);			\
    PARSERROR;					\
  }						\
}

#define SCAN_UNSIGNED_NUM(dst,cur,errmsg)				\
{									\
  if(isdigit(*(cur))) {							\
    dst=strtol(cur,&(cur),0);						\
  }									\
  else {								\
    REPORT_ERROR("expected unsigned integer value for " errmsg);	\
    PARSERROR;								\
  }									\
}

#define PARSESTR2RHN(src,len,dst)		\
{						\
  const char *_err;				\
  if ((_err=parsestr2rhn(src,len,dst))) {	\
    REPORT_ERROR(_err);				\
    PARSERROR;					\
  }						\
}


/* Copy a domain name, adding a dot at the end if necessary.
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

# define SKIP_COMMA(cur,errmsg)			\
{						\
  SKIP_BLANKS(cur);				\
  if(*(cur)!=',') {				\
    REPORT_ERROR(errmsg);			\
    PARSERROR;					\
  }						\
  ++(cur);					\
  SKIP_BLANKS(cur);				\
}


/* Parse configuration file, adding data to the global section and servers array, and the cache.
   Return 1 on success, 0 on failure.
   In case of failure, *errstr will refer to a newly allocated string containing an error message.
*/
int confparse(FILE* in, globparm_t *global, servparm_array *servers, char **errstr)
{
  char *linebuf,*p,*ps;
  size_t buflen=256,len;
  int retval=0,sechdr,option;
# define CLEANUP_HANDLER
# define SKIP_BLANKS(cur) {if(!((cur)=getnextp(&linebuf,&buflen,in,cur,errstr))) {CLEANUP_HANDLER; goto unexpected_eof;}}
# define REPORT_ERROR(msg) (*errstr=report_error(msg))
# define PARSERROR {CLEANUP_HANDLER; goto free_linebuf_return;}
# define CLEANUP_GOTO(lab) {CLEANUP_HANDLER; goto lab;}

  *errstr=NULL;
  linebuf=malloc(buflen);
  if(!linebuf) {
    /* If malloc() just failed, allocating space for an error message is unlikely to succeed. */
    return 0;
  }

  linenr=0;
  p=NULL;
  while((p=getnextp(&linebuf,&buflen,in,p,errstr))) {
    if(isalpha(*p)) {
      SCAN_ALPHANUM(ps,p,len);
      sechdr=lookup_keyword(ps,len,section_headers);
      if(!sechdr) {
	*errstr=report_errorf("invalid section header: %.*s",(int)len,ps);
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
	    *errstr=report_errorf("invalid option for global section: %.*s",(int)len,ps);
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
		global->perm_cache=0;
	      }
	      else
		goto bad_perm_cache_option;
	    }
	    else if(isdigit(*p)) {
	      global->perm_cache=strtol(p,&p,0);
	    }
	    else {
	    bad_perm_cache_option:
	      *errstr=report_error("bad qualifier in perm_cache= option.");
	      PARSERROR;
	    }
	    break;

	  case CACHE_DIR:
	    SCAN_STRING(ps,p,len);
	    STRNDUP(global->cache_dir,ps,len);
	    break;

	  case SERVER_PORT:
	    SCAN_UNSIGNED_NUM(global->port,p,"server_port option")
	    break;

	  case SERVER_IP:
	    SCAN_STRING(ps,p,len);
	    {
	      const char *err;
	      if ((err=parse_ip(ps,len,&global->a))) {
#if defined(HAVE_STRUCT_IFREQ) && defined(IFNAMSIZ) && defined(SIOCGIFADDR)
		if(!strcmp(err,"bad IP address") && len<IFNAMSIZ) {
		  /* Treat the string argument as the name of an interface
		     and try to find its IP address.
		  */
		  int fd;
		  struct ifreq req;
		  memcpy(req.ifr_name, ps, len);
		  req.ifr_name[len]=0;
		  req.ifr_addr.sa_family = PDNSD_AF_INET;


		  if ((fd = socket(PDNSD_PF_INET, SOCK_DGRAM, 0))!=-1 && ioctl(fd, SIOCGIFADDR, &req)!=-1) {
# ifdef ENABLE_IPV4
		    if (run_ipv4)
		      global->a.ipv4= ((struct sockaddr_in *)&req.ifr_addr)->sin_addr;
# endif
# ifdef ENABLE_IPV6
		    ELSE_IPV6
		      global->a.ipv6= ((struct sockaddr_in6 *)&req.ifr_addr)->sin6_addr;
# endif
		    close(fd);
		  }
		  else {
		    *errstr=report_errorf("Failed to get IP address of %s: %s",req.ifr_name,strerror(errno));
		    if(fd!=-1) close(fd);
		    PARSERROR;
		  }
		}
		else
#endif
		  {
		    *errstr=report_errorf("%s for the server_ip= option.",err);
		    PARSERROR;
		  }
	      }
	    }
	    break;

	  case SCHEME_FILE:
	    SCAN_STRING(ps,p,len);
	    STRNDUP(global->scheme_file, ps,len);
	    break;

	  case LINKDOWN_KLUGE:
	    ASSIGN_ON_OFF(global->lndown_kluge,p,C_ON,"bad qualifier in linkdown_kluge= option.");
	    break;

	  case MAX_TTL:
	    SCAN_UNSIGNED_NUM(global->max_ttl,p,"max_ttl option");
	    break;

	  case MIN_TTL:
	    SCAN_UNSIGNED_NUM(global->min_ttl,p,"min_ttl option");
	    break;

	  case RUN_AS:
	    SCAN_STRING(ps,p,len);
	    STRNCP(global->run_as, ps,len, "run_as");
	    break;

	  case STRICT_SETUID:
	    ASSIGN_ON_OFF(global->strict_suid, p,C_ON,"bad qualifier in strict_setuid= option.");
	    break;

	  case PARANOID:
	    ASSIGN_ON_OFF(global->paranoid, p,C_ON,"bad qualifier in paranoid= option.");
	    break;

	  case STATUS_CTL: {
	    int cnst;
	    ASSIGN_CONST(cnst, p,cnst==C_ON || cnst==C_OFF ,"bad qualifier in status_pipe= option.");
	    if(!cmdline.stat_pipe) global->stat_pipe=(cnst==C_ON);
	  }
	    break;

	  case DAEMON: {
	    int cnst;
	    ASSIGN_CONST(cnst, p,cnst==C_ON || cnst==C_OFF ,"bad qualifier in daemon= option.");
	    if(!cmdline.daemon) global->daemon=(cnst==C_ON);
	  }
	    break;

	  case C_TCP_SERVER: {
	    int cnst;
	    ASSIGN_CONST(cnst, p,cnst==C_ON || cnst==C_OFF ,"bad qualifier in tcp_server= option.");
	    if(!cmdline.notcp) {
	      global->notcp=(cnst==C_OFF);
#ifdef NO_TCP_SERVER
	      if(!global->notcp) {
		*errstr=report_error("pdnsd was compiled without TCP server support. tcp_server=on is not allowed.");
		PARSERROR;
	      }
#endif
	    }
	  }
	    break;

	  case PID_FILE:
	    SCAN_STRING(ps,p,len);
	    if(!cmdline.pidfile) {STRNDUP(global->pidfile,ps,len);}
	    break;

	  case C_VERBOSITY: {
	    int val;
	    SCAN_UNSIGNED_NUM(val,p,"verbosity option");
	    if(!cmdline.verbosity) global->verbosity=val;
	  }
	    break;

	  case C_QUERY_METHOD: {
	    int cnst;
	    ASSIGN_CONST(cnst,p,cnst==TCP_ONLY || cnst==UDP_ONLY || cnst==TCP_UDP,"bad qualifier in query_method= option.");
#ifdef NO_TCP_QUERIES
	    if (cnst==TCP_ONLY) {
	      *errstr=report_error("the tcp_only option is only available when pdnsd is compiled with TCP support.");
	      PARSERROR;
	    }
	    else
#endif
#ifdef NO_UDP_QUERIES
	      if (cnst==UDP_ONLY) {
		*errstr=report_error("the udp_only option is only available when pdnsd is compiled with UDP support.");
		PARSERROR;
	      }
	      else
#endif
#if defined(NO_TCP_QUERIES) || defined(NO_UDP_QUERIES)
		if (cnst==TCP_UDP) {
		  *errstr=report_error("the tcp_udp option is only available when pdnsd is compiled with both TCP and UDP support.");
		  PARSERROR;
		}
		else
#endif
		  if(!cmdline.query_method) global->query_method=cnst;
	  }
	    break;

	  case RUN_IPV4: {
	    int cnst;
	    ASSIGN_CONST(cnst,p,cnst==C_ON || cnst==C_OFF,"bad qualifier in run_ipv4= option.");
#ifndef ENABLE_IPV4
	    if(cnst==C_ON) {
	      *errstr=report_error("You can only set run_ipv4=on when pdnsd is compiled with IPv4 support.");
	      PARSERROR;
	    }
#endif
#ifndef ENABLE_IPV6
	    if(cnst==C_OFF) {
	      *errstr=report_error("You can only set run_ipv4=off when pdnsd is compiled with IPv6 support.");
	      PARSERROR;
	    }
#endif
#if defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
	    if(!cmdlineipv) {
	      run_ipv4=(cnst==C_ON); cmdlineipv=-1;
	    }
	    else if(cmdlineipv<0 && run_ipv4!=(cnst==C_ON)) {
	      *errstr=report_error(cmdlineipv==-1?
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
	    if(!cmdline.prefix) {
	      TEMPSTRNCPY(buf,ps,len);
	      if(inet_pton(AF_INET6,buf,&global->ipv4_6_prefix)<=0) {
		*errstr=report_error("ipv4_6_prefix: argument not a valid IPv6 address.");
		PARSERROR;
	      }
	    }
#else
	    fprintf(stderr,"pdnsd was compiled without IPv6 support. ipv4_6_prefix option in config file will be ignored.\n");
#endif
	    break;

	  case C_DEBUG: {
	    int cnst;
	    ASSIGN_CONST(cnst, p,cnst==C_ON || cnst==C_OFF ,"bad qualifier in debug= option.");
	    if(!cmdline.debug) {
	      global->debug=(cnst==C_ON);
#if !DEBUG
	      if(global->debug)
		fprintf(stderr,"pdnsd was compiled without debugging support. debug=on has no effect.\n");
#endif
	    }
	  }
	    break;

	  case C_CTL_PERMS:
	    SCAN_UNSIGNED_NUM(global->ctl_perms, p,"ctl_perms option");
	    break;

	  case C_PROC_LIMIT:
	    SCAN_UNSIGNED_NUM(global->proc_limit, p,"proc_limit option");
	    break;

	  case C_PROCQ_LIMIT:
	    SCAN_UNSIGNED_NUM(global->procq_limit, p,"procq_limit option");
	    break;

	  case TCP_QTIMEOUT:
	    SCAN_UNSIGNED_NUM(global->tcp_qtimeout, p,"tcp_qtimeout option");
	    break;

	  case TIMEOUT:
	    SCAN_UNSIGNED_NUM(global->timeout, p,"global timeout option");
	    break;

	  case C_PAR_QUERIES: {
	    int val;
	    SCAN_UNSIGNED_NUM(val, p,"par_queries option");
	    if(val<=0) {
	      *errstr=report_error("bad value for par_queries.");
	      PARSERROR;
	    } else {
	      global->par_queries=val;
	    }
	  }
	    break;

	  case C_RAND_RECS:
	    ASSIGN_ON_OFF(global->rnd_recs, p,C_ON,"bad qualifier in randomize_recs= option.");
	    break;

	  case NEG_TTL:
	    SCAN_UNSIGNED_NUM(global->neg_ttl, p,"neg_ttl option");
	    break;

	  case NEG_RRS_POL: {
	    int cnst;
	    ASSIGN_CONST(cnst,p,cnst==C_ON || cnst==C_OFF || cnst==C_AUTH,"bad qualifier in neg_rrs_pol= option.");
	    global->neg_rrs_pol=cnst;
	  }
	    break;

	  case NEG_DOMAIN_POL: {
	    int cnst;
	    ASSIGN_CONST(cnst,p,cnst==C_ON || cnst==C_OFF || cnst==C_AUTH,"bad qualifier in neg_domain_pol= option.");
	    global->neg_domain_pol=cnst;
	  }
	    break;

	  case QUERY_PORT_START: {
	    int val;
	    SCAN_UNSIGNED_NUM(val,p,"query_port_start option");
	    if(val<1024||val>65535) {
	      *errstr=report_error("value for query_port_start out of range.");
	      PARSERROR;
	    }
	    else if (global->query_port_end <= val) {
	      *errstr=report_error("query_port_end must be greater than query_port_start.");
	      PARSERROR;
	    }
	    else {
	      global->query_port_start=val;
	    }
	  }
	    break;

	  case QUERY_PORT_END: {
	    int val;
	    SCAN_UNSIGNED_NUM(val,p,"query_port_end option");
	    if(val<1024||val>65535) {
	      *errstr=report_error("value for query_port_end out of range.");
	      PARSERROR;
	    }
	    else if (global->query_port_start >= val) {
	      *errstr=report_error("query_port_end must be greater than query_port_start.");
	      PARSERROR;
	    }
	    else {
	      global->query_port_end=val;
	    }
	  }
	    break;

	  case DELEGATION_ONLY:
	    SCAN_STRING_LIST(&global->deleg_only_zones,p,zone_add)
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
#	undef  CLEANUP_HANDLER
#	define CLEANUP_HANDLER (free_servparm(&server))

	while(isalpha(*p)) {
	  SCAN_ALPHANUM(ps,p,len);
	  option=lookup_keyword(ps,len,server_options);
	  if(!option) {
	    *errstr=report_errorf("invalid option for server section: %.*s",(int)len,ps);
	    PARSERROR;
	  }
	  SKIP_BLANKS(p);
	  if(*p!='=') CLEANUP_GOTO(expected_equals);
	  ++p;
	  SKIP_BLANKS(p);

	  switch(option) {
	  case IP:
	    SCAN_STRING_LIST(&server.atup_a,p,addr_add);
	    break;

	  case FILET:
	    SCAN_STRING(ps,p,len);
	    {
	      TEMPSTRNCPY(fn,ps,len);
	      if (!read_resolv_conf(fn, &server.atup_a, errstr)) {
		PARSERROR;
	      }
	    }
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
	    ASSIGN_CONST(cnst,p,cnst==C_PING || cnst==C_NONE || cnst==C_IF || cnst==C_EXEC || cnst==C_DEV || cnst==C_DIALD || cnst==C_QUERY,"bad qualifier in uptest= option.");
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
		*errstr=report_errorf("%s for the ping_ip= option.",err);
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
	      else if(cnst==C_ONTIMEOUT) {
		server.interval=-2;
	      }
	      else {
		goto bad_interval_option;
	      }
	    }
	    else if(isdigit(*p)) {
	      server.interval=strtol(p,&p,0);
	    }
	    else {
	    bad_interval_option:
	      *errstr=report_error("bad qualifier in interval= option.");
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

	  case ROOT_SERVER:
	    ASSIGN_ON_OFF(server.rootserver,p,C_ON,"bad qualifier in root_server= option.");
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
	    CLEANUP_GOTO(internal_parse_error);
	  } /* end of switch(option) */

	  SKIP_BLANKS(p);
	  if(*p!=';') CLEANUP_GOTO(expected_semicolon);
	  ++p;
	  SKIP_BLANKS(p);
	}

	if(*p!='}') CLEANUP_GOTO(expected_closing_brace);
	if (server.uptest==C_EXEC) {
	  if (!server.uptest_cmd) {
	    *errstr=report_error("you must specify uptest_cmd if you specify uptest=exec!");
	    PARSERROR;
	  }
	}
	if (server.is_proxy && server.rootserver) {
	  *errstr=report_error("A server may not be specified as both a proxy and a root-server.");
	  PARSERROR;
	}
	if (DA_NEL(server.atup_a)) {
	  check_localaddrs(&server);
	  if(!DA_NEL(server.atup_a)) {
	    *errstr=report_error("Server section contains only local IP addresses.\n"
				 "Bind pdnsd to a different local IP address or specify different port numbers"
				 " in global section and server section if you want pdnsd to query servers on"
				 " the same machine.");
	    PARSERROR;
	  }
	}
	{
	  int j,n=DA_NEL(server.atup_a);
	  for(j=0;j<n;++j) {
	    atup_t *at= &DA_INDEX(server.atup_a,j);
	    at->is_up=server.preset;
	    /* A negative test interval means don't test at startup or reconfig. */
	    if(server.interval<0) at->i_ts=time(NULL);
	  }
	}
	if(server.interval==-1) global->onquery=1;

	if (!(*servers=DA_GROW1_F(*servers,(void(*)(void*))free_servparm))) {
	  CLEANUP_GOTO(out_of_memory);
	}
	DA_LAST(*servers)= server;
#	undef  CLEANUP_HANDLER
#	define CLEANUP_HANDLER
      }
	break;

      case RR: {
	 /* Initialize c_cent to all zeros.
	    Then it should be safe to call free_cent() on it, even before calling init_cent(). */
	dns_cent_t c_cent={0};
	time_t c_ttl=86400;
	unsigned c_flags=DF_LOCAL;
	unsigned char reverse=0;

#	undef  CLEANUP_HANDLER
#	define CLEANUP_HANDLER (free_cent(&c_cent DBG0))

	while(isalpha(*p)) {
	  SCAN_ALPHANUM(ps,p,len);
	  option=lookup_keyword(ps,len,rr_options);
	  if(!option) {
	    *errstr=report_errorf("invalid option for rr section: %.*s",(int)len,ps);
	    PARSERROR;
	  }
	  SKIP_BLANKS(p);
	  if(*p!='=') CLEANUP_GOTO(expected_equals);
	  ++p;
	  SKIP_BLANKS(p);

	  switch(option) {
	    int tp;
	  case NAME: {
	    unsigned char c_name[256];
	    if (c_cent.qname) {
	      *errstr=report_error("You may specify only one name in a rr section.");
	      PARSERROR;
	    }
	    SCAN_STRING(ps,p,len);
	    PARSESTR2RHN(ps,len,c_name);
	    if (!init_cent(&c_cent, c_name, 0, 0, c_flags  DBG0))
	      goto out_of_memory;
	  }
	    break;

	  case TTL:
	    SCAN_UNSIGNED_NUM(c_ttl,p, "ttl option");
	    break;

	  case AUTHREC: {
	    int cnst;
	    if (c_cent.qname) {
	      *errstr=report_error("The authrec= option has no effect unless it precedes name= in a rr section.");
	      PARSERROR;
	    }
	    ASSIGN_CONST(cnst,p,cnst==C_ON || cnst==C_OFF,"Bad qualifier in authrec= option.");
	    c_flags=(cnst==C_ON)?DF_LOCAL:0;
	  }
	    break;

	  case REVERSE:
	    ASSIGN_ON_OFF(reverse,p,C_ON,"bad qualifier in reverse= option.");
	    break;

	  case A: {
	    int sz;
	    pdnsd_ca c_a;

	    if (!c_cent.qname)
	      goto no_name_spec;
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
		    *errstr=report_error("bad IP address in a= option.");
		    PARSERROR;
		  }
	    }
	    if(!add_cent_rr(&c_cent,tp,c_ttl,0,CF_LOCAL,sz,&c_a  DBG0))
	      goto add_cent_failed;
	  }
	    break;

	  case OWNER:
	    tp=T_NS;
	    goto scan_name;
	  case CNAME:
	    tp=T_CNAME;
	    goto scan_name;
	  case PTR:
	    tp=T_PTR;
	  scan_name:
	    {
	      unsigned char c_name[256];

	      if (!c_cent.qname)
		goto no_name_spec;
	      SCAN_STRING(ps,p,len);
	      PARSESTR2RHN(ps,len,c_name);
	      if(!add_cent_rr(&c_cent,tp,c_ttl,0,CF_LOCAL,rhnlen(c_name),c_name  DBG0))
		goto add_cent_failed;
	    }
	    break;

	  case MX: {
	    unsigned char *cp;
	    unsigned pref;
	    unsigned char c_mx[258];

	    if (!c_cent.qname)
	      goto no_name_spec;
	    cp=c_mx+2;
	    SCAN_STRING(ps,p,len);
	    PARSESTR2RHN(ps,len,cp);
	    SKIP_COMMA(p,"missing second argument (preference level) of mx= option");
	    SCAN_UNSIGNED_NUM(pref,p,"second argument of mx= option");
	    cp=c_mx;
	    PUTINT16(pref,cp);
	    if(!add_cent_rr(&c_cent,T_MX,c_ttl,0,CF_LOCAL,2+rhnlen(cp),c_mx  DBG0))
	      goto add_cent_failed;
	  }
	    break;

	  case SOA: {
	    int blen,rlen;
	    unsigned char *bp;
	    uint32_t val;
	    unsigned char buf[2*256+20];

	    if (!c_cent.qname)
	      goto no_name_spec;
	    SCAN_STRING(ps,p,len);
	    PARSESTR2RHN(ps,len,buf);
	    rlen=rhnlen(buf);
	    blen=rlen;
	    bp=buf+rlen;
	    SKIP_COMMA(p,"missing 2nd argument of soa= option");
	    SCAN_STRING(ps,p,len);
	    PARSESTR2RHN(ps,len,bp);
	    rlen=rhnlen(bp);
	    blen += rlen;
	    bp += rlen;
	    SKIP_COMMA(p,"missing 3rd argument of soa= option");
	    SCAN_UNSIGNED_NUM(val,p,"3rd argument of soa= option");
	    PUTINT32(val,bp);
	    SKIP_COMMA(p,"missing 4th argument of soa= option");
	    SCAN_UNSIGNED_NUM(val,p,"4th argument of soa= option");
	    PUTINT32(val,bp);
	    SKIP_COMMA(p,"missing 5th argument of soa= option");
	    SCAN_UNSIGNED_NUM(val,p,"5th argument of soa= option");
	    PUTINT32(val,bp);
	    SKIP_COMMA(p,"missing 6th argument of soa= option");
	    SCAN_UNSIGNED_NUM(val,p,"6th argument of soa= option");
	    PUTINT32(val,bp);
	    SKIP_COMMA(p,"missing 7th argument of soa= option");
	    SCAN_UNSIGNED_NUM(val,p,"7th argument of soa= option");
	    PUTINT32(val,bp);
	    blen += 20;
	    if(!add_cent_rr(&c_cent,T_SOA,c_ttl,0,CF_LOCAL,blen,buf  DBG0))
	      goto add_cent_failed;
	  }
	    break;

	  default: /* we should never get here */
	    CLEANUP_GOTO(internal_parse_error);
	  } /* end of switch(option) */

	  SKIP_BLANKS(p);
	  if(*p!=';') CLEANUP_GOTO(expected_semicolon);
	  ++p;
	  SKIP_BLANKS(p);
	}

	if(*p!='}') CLEANUP_GOTO(expected_closing_brace);
	if (!c_cent.qname)
	  goto no_name_spec;
	if(c_cent.qname[0]==1 && c_cent.qname[1]=='*') {
	  /* Wild card record. Set the DF_WILD flag for the name with '*.' removed. */
	  if(!set_cent_flags(&c_cent.qname[2],DF_WILD)) {
	    char buf[256];
	    rhn2str(c_cent.qname,buf,sizeof(buf));
	    *errstr=report_errorf("You must define some records for '%s'"
				  " before you can define records for the wildcard name '%s'",
				  &buf[2],buf);
	    PARSERROR;
	  }
	}

	add_cache(&c_cent);
	if(reverse) {
	  if(!add_reverse_cache(&c_cent)) {
		    *errstr=report_error("Can't convert IP address in a= option"
					 " into form suitable for reverse resolving.");
		    PARSERROR;
	  }
	}
	CLEANUP_HANDLER;
	break;

      add_cent_failed:
	CLEANUP_HANDLER;
	goto out_of_memory;
#	undef  CLEANUP_HANDLER
#	define CLEANUP_HANDLER
      }

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
	    *errstr=report_errorf("invalid option for source section: %.*s",(int)len,ps);
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
	      *errstr=report_error("you must specify owner before file= in source records.");
	      PARSERROR;
	    }
	    SCAN_STRING(ps,p,len);
	    {
	      char *errmsg;
	      TEMPSTRNCPY(fn,ps,len);
	      if (!read_hosts(fn, c_owner, c_ttl, c_flags, c_aliases, &errmsg)) {
		if(errmsg) { *errstr=report_error(errmsg); free(errmsg); }
		else *errstr=NULL;
		PARSERROR;
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
	    *errstr=report_errorf("invalid option for neg section: %.*s",(int)len,ps);
	    PARSERROR;
	  }
	  SKIP_BLANKS(p);
	  if(*p!='=') goto expected_equals;
	  ++p;
	  SKIP_BLANKS(p);

	  switch(option) {
	  case NAME:
	    SCAN_STRING(ps,p,len);
	    PARSESTR2RHN(ps,len,c_name);
	    break;

	  case TTL:
	    SCAN_UNSIGNED_NUM(c_ttl,p, "ttl option");
	    break;

	  case TYPES:
	    if (!c_name[0]) {
	      *errstr=report_error("you must specify a name before the types= option.");
	      PARSERROR;
	    }
	    if (isalpha(*p)) {
	      int cnst;
	      dns_cent_t c_cent /* ={0} */;
	      SCAN_ALPHANUM(ps,p,len);
	      cnst=lookup_const(ps,len);
	      if(cnst==C_DOMAIN) {
		if (htp) {
		  *errstr=report_error("You may not specify types=domain together with other types!");
		  PARSERROR;
		}
		hdtp=1;
		if (!init_cent(&c_cent, c_name, c_ttl, 0, DF_LOCAL|DF_NEGATIVE  DBG0))
		  goto out_of_memory;
	      }
	      else if(cnst==0) {
		if (hdtp) {
		  *errstr=report_error("You may not specify types=domain together with other types!");
		  PARSERROR;
		}
		htp=1;
		if (!init_cent(&c_cent, c_name, 0, 0, 0  DBG0))
		  goto out_of_memory;
#		undef  CLEANUP_HANDLER
#		define CLEANUP_HANDLER (free_cent(&c_cent DBG0))
		for(;;) {
		  {
		    TEMPSTRNCPY(buf,ps,len);
		    cnst=rr_tp_byname(buf);
		  }
		  if(cnst==-1) {
		    *errstr=report_errorf("unrecognized rr type '%.*s' used as argument for types= option.",(int)len,ps);
		    PARSERROR;
		  }
		  if (!c_cent.rr[cnst-T_MIN] && !add_cent_rrset(&c_cent,cnst,c_ttl,0,CF_LOCAL|CF_NEGATIVE  DBG0)) {
		    CLEANUP_GOTO(out_of_memory);
		  }
		  SKIP_BLANKS(p);
		  if(*p!=',') break;
		  ++p;
		  SKIP_BLANKS(p);
		  if (!isalpha(*p))
		    {CLEANUP_GOTO(bad_types_option);}
		  SCAN_ALPHANUM(ps,p,len);
		}
	      }
	      else
		goto bad_types_option;

	      add_cache(&c_cent);
	      CLEANUP_HANDLER;
#	      undef  CLEANUP_HANDLER
#	      define CLEANUP_HANDLER
	    }
	    else {
	    bad_types_option:
	      *errstr=report_error("Bad argument for types= option.");
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
      *errstr=report_error("expected section header");
      PARSERROR;
    }
  }

  if(feof(in)) {
    if(*errstr) {
      PARSERROR;
    }
    retval=1; /* success */
  }
  else
    goto input_error;

  goto free_linebuf_return;

 expected_bropen:
  *errstr=report_error("expected opening brace after section name");
  PARSERROR;

 expected_closing_brace:
  *errstr=report_error("expected beginning of new option or closing brace");
  PARSERROR;

 expected_equals:
  *errstr=report_error("expected equals sign after option name");
  PARSERROR;

 expected_semicolon:
  *errstr=report_error("too many arguments to option or missing semicolon");
  PARSERROR;

 no_name_spec:
  *errstr=report_error("you must specify a name before a,ptr,cname,mx,ns(owner) and soa records.");
  PARSERROR;

 internal_parse_error:
  if(asprintf(errstr,"Internal inconsistency detected while parsing line %u of config file.\n"
	      "Please consider reporting this error to one of the maintainers.\n",linenr)<0)
    *errstr=NULL;
  PARSERROR;

 out_of_memory:
  /* If malloc() just failed, allocating space for an error message is unlikely to succeed. */
  *errstr=NULL;
  PARSERROR;

 unexpected_eof:
  if(feof(in)) {
    if(!(*errstr))
      *errstr=report_error("unexpected end of file");
  }
  else
    input_error: {
    if(*errstr) free(*errstr);
    if(asprintf(errstr,"Error while reading config file: %s",strerror(errno))<0)
      *errstr=NULL;
  }

 free_linebuf_return:
  free(linebuf);
  return retval;

#undef SKIP_BLANKS
#undef REPORT_ERROR
#undef PARSERROR
#undef CLEANUP_GOTO
}

static const char* parse_ip(const char *ipstr,size_t len, pdnsd_a *a)
{
#if defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
  if(!cmdlineipv) cmdlineipv=-2;
#endif
  {
    TEMPSTRNCPY(buf,ipstr,len);
    if(!strcmp(buf,"any")) {
#ifdef ENABLE_IPV4
      if (run_ipv4)
	a->ipv4.s_addr=INADDR_ANY;
#endif
#ifdef ENABLE_IPV6
      ELSE_IPV6
	a->ipv6=in6addr_any;
#endif
    }
    else if(!str2pdnsd_a(buf,a)) {
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
	fprintf(stderr,"IPv6 address \"%s\" in line %u of config file ignored while running in IPv4 mode.\n",buf,linenr);
	return NULL;
      }
#endif
      return "bad IP address";
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

/* Try to avoid the possibility that pdnsd will query itself. */
static void check_localaddrs(servparm_t *serv)
{
  if(serv->port == global.port) {
    atup_array ata=serv->atup_a;
    int i,j=0,n=DA_NEL(ata);
    for(i=0;i<n;++i) {
      atup_t *at=&DA_INDEX(ata,i);
      if(is_inaddr_any(&global.a)) {
	if(is_local_addr(&at->a)) {
	  char buf[ADDRSTR_MAXLEN];
	  fprintf(stderr,"Local name-server address \"%s\" ignored in config file.\n",
		  pdnsd_a2str(&at->a,buf,ADDRSTR_MAXLEN));
	  continue;
	}
      }
      else {
	if(ADDR_EQUIV(&global.a,&at->a)) {
	  char buf[ADDRSTR_MAXLEN];
	  fprintf(stderr,"Ignoring name-server address \"%s\" in config file (identical to server_ip address).\n",
		  pdnsd_a2str(&at->a,buf,ADDRSTR_MAXLEN));
	  continue;
	}
      }
      if(j<i)
	DA_INDEX(ata,j)=*at;
      ++j;
    }      
    if(j<n)
      serv->atup_a=DA_RESIZE(ata,j);
  }
}

/* Read the name server addresses from a resolv.conf-style file. */
static int read_resolv_conf(const char *fn, atup_array *ata, char **errstr)
{
  int rv=0;
  FILE *f;
  char *buf;
  size_t buflen=256;
  unsigned linenr=0;

  if (!(f=fopen(fn,"r"))) {
    *errstr=report_errorf("Failed to open %s: %s", fn, strerror(errno));
    return 0;
  }
  buf=malloc(buflen);
  if(!buf) {
    *errstr=NULL;
    goto fclose_return;
  }
  while(getline(&buf,&buflen,f)>=0) {
    size_t len;
    char *p,*ps;
    ++linenr;
    p=buf;
    for(;; ++p) {
      if(!*p) goto nextline;
      if(!isspace(*p)) break;
    }
    ps=p;
    do {
      if(!*++p) goto nextline;
    } while(!isspace(*p));
    len=p-ps;
    if(len==strlitlen("nameserver") && !strncmp(ps,"nameserver",len)) {
      const char *errmsg;
      do {
	if(!*++p) goto nextline;
      } while (isspace(*p));
      ps=p;
      do {
	++p;
      } while(*p && !isspace(*p));
      len=p-ps;
      if((errmsg=addr_add(ata, ps, len))) {
	*errstr=report_errorf("%s in line %u of file %s", errmsg,linenr,fn);
	goto cleanup_return;
      }
    }
  nextline:;
  }
  if (feof(f))
    rv=1;
  else
    *errstr=report_errorf("Failed to read %s: %s", fn, strerror(errno));
 cleanup_return:
  free(buf);
 fclose_return:
  fclose(f);
  return rv;
}

static const char *slist_add(slist_array *sla, const char *nm, size_t len, int tp)
{
  slist_t *sl;
  int exact=1;
  const char *err;
  size_t sz;
  unsigned char rhn[256];

  if (len>1 && *nm=='.') {
    exact=0;
    ++nm;
    --len;
  }
  if((err=parsestr2rhn(nm,len,rhn)))
    return err;
  sz=rhnlen(rhn);
  if (!(*sla=DA_GROW1_F(*sla,free_slist_domain))) {
    return "out of memory!";
  }
  sl=&DA_LAST(*sla);

  if (!(sl->domain=malloc(sz)))
    return "out of memory!";
  memcpy(sl->domain,rhn,sz);
  sl->exact=exact;
  sl->rule=tp;
  return NULL;
}

static const char *zone_add(zone_array *za, const char *zone, size_t len)
{
  zone_t z;
  const char *err;
  size_t sz;
  unsigned char rhn[256];

  if((err=parsestr2rhn(zone,len,rhn)))
    return err;
  sz=rhnlen(rhn);
  if(!(*za=DA_GROW1_F(*za,free_zone)) || !(DA_LAST(*za)=z=malloc(sz)))
    return "out of memory!";
  memcpy(z,rhn,sz);
  return NULL;
}

