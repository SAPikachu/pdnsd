/* conf-parser.c - Parser for pdnsd config files.
   Based on the files conf-lex.l and conf-parse.y written by 
   Thomas Moestl.
   This version was rewritten in C from scratch by Paul A. Rombouts
   and doesn't require (f)lex or yacc/bison.

   Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009 Paul A. Rombouts.

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


/* Check that include files are not nested deeper than MAXINCLUDEDEPTH,
   as a precaution against infinite recursion. */
#define MAXINCLUDEDEPTH 100

static char *report_error (const char *conftype, unsigned linenr, const char *msg)
{
  char *retval;
  if(linenr) {
    if(asprintf(&retval, "Error in %s (line %u): %s",conftype,linenr,msg)<0)
      retval=NULL;
  }
  else {
    if(asprintf(&retval, "Error in %s: %s",conftype,msg)<0)
      retval=NULL;
  }

  return retval;
}

static char *report_errorf (const char *conftype, unsigned linenr, const char *frm,...) printfunc(3, 4);
static char *report_errorf (const char *conftype, unsigned linenr, const char *frm,...)
{
  char *msg,*retval; int mlen;
  va_list va;
  va_start(va,frm);
  mlen=vasprintf(&msg,frm,va);
  va_end(va);
  if(mlen<0) return NULL;
  retval=report_error(conftype,linenr,msg);
  free(msg);
  return retval;
}

/* return pointer to next character in linebuffer after skipping blanks and comments */
static char* getnextp(char **buf, size_t *n, FILE* in, char *p, unsigned *linenr, char **errstr)
{
  if(!p) goto nextline;
 tryagain:
  if(!*p) {
  nextline:
    do {
      if(!in || getline(buf,n,in)<0) {
	*errstr=NULL;
	return NULL;
      }
      ++*linenr;
      p=*buf;
    } while(!*p);
  }
  if(isspace(*p)) {
    ++p; goto tryagain;
  }
  if(*p=='#') {
  skip_rest_of_line:
    if(*linenr)
      goto nextline;
    else {
      p=strchr(p,'\n');
      if(p) {
	++p;
	goto tryagain;
      }
      else
	goto nextline;
    }
  }
  if(*p=='/') {
    if(*(p+1)=='/')
      goto skip_rest_of_line;
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
	if(!in || getline(buf,n,in)<0) {
	  *errstr="comment without closing */";
	  return NULL;
	}
	++*linenr;
	p=*buf;
      }
    }
  }

  return p;
}


/* Scan a buffer for a string.

   A string either begins after and ends before a double-quote ("),
   or simply consists of a sequence of "non-special" characters,
   starting at the current position.

   char **curp should point to the position in the buffer where
               the scanning should begin. It will be updated to point
               to the first character past the scanned string.

   char **startp is used to return the position in the buffer where the scanned
               string starts.

   size_t *lenp is used to return the length of the scanned string.
*/
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


/* Convert a string to a time value in seconds.
   The string referred to by nptr is scanned for a sequence of components,
   where each component contains a non-empty sequence of digits followed
   by a possible one-letter suffix.
   The position where the scanning stops is returned in endptr.
   If an error is detected during scanning, a pointer to a
   (static) error message is returned in errstr.
*/
static time_t strtotime(char *nptr, char **endptr, char **errstr)
{
  time_t retval=0,t;
  char c;

  *errstr=NULL;
  while(isalnum(c=*nptr)) {
    if(!isdigit(c)) {
	*errstr="no digits before suffix.";
	break;
    }

    t=strtol(nptr,&nptr,10);

    if(isalpha(c=*nptr)) {
      if(c=='s') /* seconds */
	;
      else if(c=='m') /* minutes */
	t *= 60;
      else if(c=='h') /* hours */
	t *= 60*60;
      else if(c=='d') /* days */
	t *= 24*60*60;
      else if(c=='w') /* weeks */
	t *= 7*24*60*60;
      else {
	*errstr="allowed suffixes are w,d,h,m,s.";
	break;
      }
      ++nptr;
    }

    retval += t;
  }

  if(endptr) *endptr=nptr;
  return retval;
}


#define lookup_keyword(name,len,dic) binsearch_keyword(name,len,dic,sizeof(dic)/sizeof(namevalue_t))
static const char *parse_ip(const char *ipstr,size_t len, pdnsd_a *a);
static const char *addr_add(atup_array *ata, const char *ipstr, size_t len);
static const char *reject_add(servparm_t *serv, const char *ipstr, size_t len);
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

#define SCAN_TIMESECS(dst,cur,errmsg)						\
{										\
  if(isdigit(*(cur))) {								\
    char *_err;									\
    dst=strtotime(cur,&(cur),&_err);						\
    if(_err) {									\
      REPORT_ERRORF("invalid time specification for %s: %s",errmsg,_err);	\
      PARSERROR;								\
    }										\
  }										\
  else {									\
    REPORT_ERROR("expected a time specification for " errmsg);			\
    PARSERROR;									\
  }										\
}

#define PARSESTR2RHN(src,len,dst)		\
{						\
  const char *_err;				\
  if ((_err=parsestr2rhn(src,len,dst))) {	\
    REPORT_ERROR(_err);				\
    PARSERROR;					\
  }						\
}


#if 0
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
#endif

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


/* Parse a configuration file, adding data to a (separate) global section and servers array,
   and the cache.

   FILE *in should point to the input stream. It may be NULL, in which case no file is read.

   char *prestr may be NULL or point to a string which will be parsed before the input file.

   globparm_t *global should point to a struct which will be used to store the data of the
                      global section(s). If it is NULL, no global sections are allowed in the
		      input.

   servparm_array *servers should point to a dynamic array which will be grown to store the data
                           of the server sections. If it is NULL, no server sections are allowed
			   in the input.

   int includedepth is used to track how deeply recursive calls of confparse are nested.
                    Should be 0 for a top-level call.

   char **errstr is used to return a possible error message.
                 In case of failure, *errstr will refer to a newly allocated string.

   confparse returns 1 on success, 0 on failure.
*/
int confparse(FILE* in, char *prestr, globparm_t *global, servparm_array *servers, int includedepth, char **errstr)
{
  char *linebuf=NULL,*p,*ps,*getnextperr=NULL;
  const char *conftype;
  size_t buflen=256,len;
  unsigned linenr=0;
  int retval=0,sechdr,option;
# define CLEANUP_HANDLER
# define SKIP_BLANKS(cur) {if(!((cur)=getnextp(&linebuf,&buflen,in,cur,&linenr,&getnextperr))) {CLEANUP_HANDLER; goto unexpected_eof;}}
# define REPORT_ERROR(msg) (*errstr=report_error(conftype,linenr,msg))
# if !defined(CPP_C99_VARIADIC_MACROS)
   /* GNU C Macro Varargs style. */
#  define REPORT_ERRORF(args...) (*errstr=report_errorf(conftype,linenr,args))
#else
   /* ANSI C99 style. */
#  define REPORT_ERRORF(...) (*errstr=report_errorf(conftype,linenr,__VA_ARGS__))
# endif
# define PARSERROR {CLEANUP_HANDLER; goto free_linebuf_return;}
# define CLEANUP_GOTO(lab) {CLEANUP_HANDLER; goto lab;}

  *errstr=NULL;
  if(in) {
    linebuf=malloc(buflen);
    if(!linebuf) {
      /* If malloc() just failed, allocating space for an error message is unlikely to succeed. */
      return 0;
    }
    if(global)
      conftype="config file";
    else
      conftype="include file";
  }
  else
    conftype="config string";

  p=prestr;
  while((p=getnextp(&linebuf,&buflen,in,p,&linenr,&getnextperr))) {
    if(isalpha(*p)) {
      SCAN_ALPHANUM(ps,p,len);
      sechdr=lookup_keyword(ps,len,section_headers);
      if(!sechdr) {
	REPORT_ERRORF("invalid section header: %.*s",(int)len,ps);
	PARSERROR;
      }
      SKIP_BLANKS(p);
      if(*p!='{') goto expected_bropen;
      ++p;
      SKIP_BLANKS(p);

      switch(sechdr) {
      case GLOBAL:
	if(!global) {
	  REPORT_ERROR(in?"global section not allowed in include file":
		       "global section not allowed in eval string");
	  PARSERROR;
	}

	while(isalpha(*p)) {
	  SCAN_ALPHANUM(ps,p,len);
	  option=lookup_keyword(ps,len,global_options);
	  if(!option) {
	    REPORT_ERRORF("invalid option for global section: %.*s",(int)len,ps);
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
	      REPORT_ERROR("bad qualifier in perm_cache= option.");
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
		    REPORT_ERRORF("Failed to get IP address of %s: %s",req.ifr_name,strerror(errno));
		    if(fd!=-1) close(fd);
		    PARSERROR;
		  }
		}
		else
#endif
		  {
		    REPORT_ERRORF("%s for the server_ip= option.",err);
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
	    SCAN_TIMESECS(global->max_ttl,p,"max_ttl option");
	    break;

	  case MIN_TTL:
	    SCAN_TIMESECS(global->min_ttl,p,"min_ttl option");
	    break;

	  case RUN_AS:
	    SCAN_STRING(ps,p,len);
	    STRNCP(global->run_as, ps,len, "run_as");
	    break;

	  case STRICT_SETUID:
	    ASSIGN_ON_OFF(global->strict_suid, p,C_ON,"bad qualifier in strict_setuid= option.");
	    break;

	  case USE_NSS:
	    ASSIGN_ON_OFF(global->use_nss, p,C_ON,"bad qualifier in use_nss= option.");
	    break;

	  case PARANOID:
	    ASSIGN_ON_OFF(global->paranoid, p,C_ON,"bad qualifier in paranoid= option.");
	    break;

	  case IGNORE_CD:
	    ASSIGN_ON_OFF(global->ignore_cd, p,C_ON,"bad qualifier in ignore_cd= option.");
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
		REPORT_ERROR("pdnsd was compiled without TCP server support. tcp_server=on is not allowed.");
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
	    ASSIGN_CONST(cnst,p,cnst==TCP_ONLY || cnst==UDP_ONLY || cnst==TCP_UDP || cnst==UDP_TCP,"bad qualifier in query_method= option.");
#ifdef NO_TCP_QUERIES
	    if (cnst==TCP_ONLY) {
	      REPORT_ERROR("the tcp_only option is only available when pdnsd is compiled with TCP support.");
	      PARSERROR;
	    }
	    else
#endif
#ifdef NO_UDP_QUERIES
	      if (cnst==UDP_ONLY) {
		REPORT_ERROR("the udp_only option is only available when pdnsd is compiled with UDP support.");
		PARSERROR;
	      }
	      else
#endif
#if defined(NO_TCP_QUERIES) || defined(NO_UDP_QUERIES)
		if (cnst==TCP_UDP) {
		  REPORT_ERROR("the tcp_udp option is only available when pdnsd is compiled with both TCP and UDP support.");
		  PARSERROR;
		}
		else if (cnst==UDP_TCP) {
		  REPORT_ERROR("the udp_tcp option is only available when pdnsd is compiled with both TCP and UDP support.");
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
	      REPORT_ERROR("You can only set run_ipv4=on when pdnsd is compiled with IPv4 support.");
	      PARSERROR;
	    }
#endif
#ifndef ENABLE_IPV6
	    if(cnst==C_OFF) {
	      REPORT_ERROR("You can only set run_ipv4=off when pdnsd is compiled with IPv6 support.");
	      PARSERROR;
	    }
#endif
#if defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
	    if(!cmdlineipv) {
	      run_ipv4=(cnst==C_ON); cmdlineipv=-1;
	    }
	    else if(cmdlineipv<0 && run_ipv4!=(cnst==C_ON)) {
	      REPORT_ERROR(cmdlineipv==-1?
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
		REPORT_ERROR("ipv4_6_prefix: argument not a valid IPv6 address.");
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
	    SCAN_TIMESECS(global->tcp_qtimeout, p,"tcp_qtimeout option");
	    break;

	  case TIMEOUT:
	    SCAN_TIMESECS(global->timeout, p,"global timeout option");
	    break;

	  case C_PAR_QUERIES: {
	    int val;
	    SCAN_UNSIGNED_NUM(val, p,"par_queries option");
	    if(val<=0) {
	      REPORT_ERROR("bad value for par_queries.");
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
	    SCAN_TIMESECS(global->neg_ttl, p,"neg_ttl option");
	    break;

	  case NEG_RRS_POL: {
	    int cnst;
	    ASSIGN_CONST(cnst,p,cnst==C_ON || cnst==C_OFF || cnst==C_DEFAULT || cnst==C_AUTH,
			 "bad qualifier in neg_rrs_pol= option.");
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
	    if(isalpha(*p)) {
	      int cnst;
	      SCAN_ALPHANUM(ps,p,len);
	      cnst=lookup_const(ps,len);
	      if(cnst==C_NONE)
		val=-1;
	      else
		goto bad_port_start_option;
	    }
	    else if(isdigit(*p)) {
	      val=strtol(p,&p,0);
	      if(val>65535) {
		REPORT_ERROR("value for query_port_start out of range.");
		PARSERROR;
	      }
	      else if(val<1024)
		fprintf(stderr,"Warning: query_port_start=%i but source ports <1204 can only be used as root.\n",
			val);
	    }
	    else {
	    bad_port_start_option:
	      REPORT_ERROR("bad qualifier in query_port_start= option.");
	      PARSERROR;
	    }
	    global->query_port_start=val;
	  }
	    break;

	  case QUERY_PORT_END: {
	    int val;
	    SCAN_UNSIGNED_NUM(val,p,"query_port_end option");
	    if(val>65535) {
	      REPORT_ERROR("value for query_port_end out of range.");
	      PARSERROR;
	    }
	    global->query_port_end=val;
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

	if(*p!='}') goto expected_closing_brace;
	if (global->query_port_end < global->query_port_start) {
	  REPORT_ERROR("query_port_end may not be smaller than query_port_start.");
	  PARSERROR;
	}
	break;

      case SERVER: {
	servparm_t server;

	if(!servers) {
	  REPORT_ERROR(in?"server section not allowed in include file":
		       "server section not allowed in eval string");
	  PARSERROR;
	}

	server=serv_presets;
#	undef  CLEANUP_HANDLER
#	define CLEANUP_HANDLER (free_servparm(&server))

	while(isalpha(*p)) {
	  SCAN_ALPHANUM(ps,p,len);
	  option=lookup_keyword(ps,len,server_options);
	  if(!option) {
	    REPORT_ERRORF("invalid option for server section: %.*s",(int)len,ps);
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
	      char *errmsg;
	      TEMPSTRNCPY(fn,ps,len);
	      if (!read_resolv_conf(fn, &server.atup_a, &errmsg)) {
		if(errmsg) {REPORT_ERROR(errmsg); free(errmsg);}
		else *errstr=NULL;
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
	    SCAN_TIMESECS(server.timeout,p,"timeout option");
	    break;

	  case PING_TIMEOUT:
	    SCAN_UNSIGNED_NUM(server.ping_timeout,p,"ping_timeout option");
	    break;

	  case PING_IP:
	    SCAN_STRING(ps,p,len);
	    {
	      const char *err;
	      if ((err=parse_ip(ps,len,&server.ping_a))) {
		REPORT_ERRORF("%s for the ping_ip= option.",err);
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
	      char *err;
	      server.interval=strtotime(p,&p,&err);
	      if(err) {
		REPORT_ERRORF("bad time specification in interval= option: %s",err);
		PARSERROR;
	      }
	    }
	    else {
	    bad_interval_option:
	      REPORT_ERROR("bad qualifier in interval= option.");
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

	  case ROOT_SERVER: {
	    int cnst;
	    ASSIGN_CONST(cnst,p,cnst==C_ON || cnst==C_OFF || cnst==C_DISCOVER,"bad qualifier in root_server= option.");
	    server.rootserver= (cnst==C_DISCOVER? 2: cnst==C_ON);
	  }
	    break;

	  case RANDOMIZE_SERVERS:
	    ASSIGN_ON_OFF(server.rand_servers,p,C_ON,"bad qualifier in randomize_servers= option.");
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

	  case REJECTLIST:
	    SCAN_STRING_LIST(&server,p,reject_add);
	    break;

	  case REJECTPOLICY: {
	    int cnst;
	    ASSIGN_CONST(cnst,p,cnst==C_FAIL || cnst==C_NEGATE,"bad qualifier in reject_policy= option.");
	    server.rejectpolicy=cnst;
	  }
	    break;

	  case REJECTRECURSIVELY:
	    ASSIGN_ON_OFF(server.rejectrecursively,p,C_ON,"bad qualifier in reject_recursively= option.");
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
	    REPORT_ERROR("you must specify uptest_cmd if you specify uptest=exec!");
	    PARSERROR;
	  }
	}
	if (server.is_proxy && server.rootserver) {
	  REPORT_ERROR("A server may not be specified as both a proxy and a root-server.");
	  PARSERROR;
	}
	if(server.rootserver && (server.policy==C_SIMPLE_ONLY || server.policy==C_FQDN_ONLY))
	  fprintf(stderr,"Warning: using policy=%s with a root-server usually makes no sense.",
		  const_name(server.policy));
	if (DA_NEL(server.atup_a)) {
	  check_localaddrs(&server);
	  if(!DA_NEL(server.atup_a)) {
	    REPORT_ERROR("Server section contains only local IP addresses.\n"
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
	    REPORT_ERRORF("invalid option for rr section: %.*s",(int)len,ps);
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
	      REPORT_ERROR("You may specify only one name in a rr section.");
	      PARSERROR;
	    }
	    SCAN_STRING(ps,p,len);
	    PARSESTR2RHN(ucharp ps,len,c_name);
	    if (!init_cent(&c_cent, c_name, 0, 0, c_flags  DBG0))
	      goto out_of_memory;
	  }
	    break;

	  case TTL:
	    SCAN_TIMESECS(c_ttl,p, "ttl option");
	    break;

	  case AUTHREC: {
	    int cnst;
	    if (c_cent.qname) {
	      REPORT_ERROR("The authrec= option has no effect unless it precedes name= in a rr section.");
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
#if ALLOW_LOCAL_AAAA
		if (inet_pton(AF_INET6,buf,&c_a.ipv6)>0) {
		  tp=T_AAAA;
		  sz=sizeof(struct in6_addr);
		}
		else
#endif
		  {
		    REPORT_ERROR("bad IP address in a= option.");
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
	      PARSESTR2RHN(ucharp ps,len,c_name);
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
	    PARSESTR2RHN(ucharp ps,len,cp);
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
	    PARSESTR2RHN(ucharp ps,len,buf);
	    rlen=rhnlen(buf);
	    blen=rlen;
	    bp=buf+rlen;
	    SKIP_COMMA(p,"missing 2nd argument of soa= option");
	    SCAN_STRING(ps,p,len);
	    PARSESTR2RHN(ucharp ps,len,bp);
	    rlen=rhnlen(bp);
	    blen += rlen;
	    bp += rlen;
	    SKIP_COMMA(p,"missing 3rd argument of soa= option");
	    SCAN_UNSIGNED_NUM(val,p,"3rd argument of soa= option");
	    PUTINT32(val,bp);
	    SKIP_COMMA(p,"missing 4th argument of soa= option");
	    SCAN_TIMESECS(val,p,"4th argument of soa= option");
	    PUTINT32(val,bp);
	    SKIP_COMMA(p,"missing 5th argument of soa= option");
	    SCAN_TIMESECS(val,p,"5th argument of soa= option");
	    PUTINT32(val,bp);
	    SKIP_COMMA(p,"missing 6th argument of soa= option");
	    SCAN_TIMESECS(val,p,"6th argument of soa= option");
	    PUTINT32(val,bp);
	    SKIP_COMMA(p,"missing 7th argument of soa= option");
	    SCAN_TIMESECS(val,p,"7th argument of soa= option");
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
	    unsigned char buf[256];
	    rhn2str(c_cent.qname,buf,sizeof(buf));
	    REPORT_ERRORF("You must define some records for '%s'"
			  " before you can define records for the wildcard name '%s'",
			  &buf[2],buf);
	    PARSERROR;
	  }
	}

	add_cache(&c_cent);
	if(reverse) {
	  if(!add_reverse_cache(&c_cent)) {
		    REPORT_ERROR("Can't convert IP address in a= option"
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
	    REPORT_ERRORF("invalid option for source section: %.*s",(int)len,ps);
	    PARSERROR;
	  }
	  SKIP_BLANKS(p);
	  if(*p!='=') goto expected_equals;
	  ++p;
	  SKIP_BLANKS(p);

	  switch(option) {
	  case OWNER:
	    SCAN_STRING(ps,p,len);
	    PARSESTR2RHN(ucharp ps,len,c_owner);
	    break;

	  case TTL:
	    SCAN_TIMESECS(c_ttl,p,"ttl option");
	    break;

	  case FILET:
	    if (!c_owner[0]) {
	      REPORT_ERROR("you must specify owner before file= in source records.");
	      PARSERROR;
	    }
	    SCAN_STRING(ps,p,len);
	    {
	      char *errmsg;
	      TEMPSTRNCPY(fn,ps,len);
	      if (!read_hosts(fn, c_owner, c_ttl, c_flags, c_aliases, &errmsg)) {
		if(errmsg) { REPORT_ERROR(errmsg); free(errmsg); }
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
      }
	break;

      case INCLUDE_F: {
	while(isalpha(*p)) {
	  SCAN_ALPHANUM(ps,p,len);
	  option=lookup_keyword(ps,len,include_options);
	  if(!option) {
	    REPORT_ERRORF("invalid option for include section: %.*s",(int)len,ps);
	    PARSERROR;
	  }
	  SKIP_BLANKS(p);
	  if(*p!='=') goto expected_equals;
	  ++p;
	  SKIP_BLANKS(p);

	  switch(option) {
	  case FILET:
	    if(includedepth>=MAXINCLUDEDEPTH) {
	      REPORT_ERRORF("maximum include depth (%d) exceeded.",MAXINCLUDEDEPTH);
	      PARSERROR;
	    }
	    SCAN_STRING(ps,p,len);
	    {
	      char *errmsg;
	      TEMPSTRNCPY(fn,ps,len);
	      if (!read_config_file(fn, NULL, NULL, includedepth+1, &errmsg)) {
		if(errmsg) {
		  if(linenr) {
		    if(asprintf(errstr, "In file %s included at line %u:\n%s",fn,linenr,errmsg)<0)
		      *errstr=NULL;
		  }
		  else {
		    if(asprintf(errstr, "In file %s:\n%s",fn,errmsg)<0)
		      *errstr=NULL;
		  }
		  free(errmsg);
		}
		else
		  *errstr=NULL;
		PARSERROR;
	      }
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
	    REPORT_ERRORF("invalid option for neg section: %.*s",(int)len,ps);
	    PARSERROR;
	  }
	  SKIP_BLANKS(p);
	  if(*p!='=') goto expected_equals;
	  ++p;
	  SKIP_BLANKS(p);

	  switch(option) {
	  case NAME:
	    SCAN_STRING(ps,p,len);
	    PARSESTR2RHN(ucharp ps,len,c_name);
	    break;

	  case TTL:
	    SCAN_TIMESECS(c_ttl,p, "ttl option");
	    break;

	  case TYPES:
	    if (!c_name[0]) {
	      REPORT_ERROR("you must specify a name before the types= option.");
	      PARSERROR;
	    }
	    if (isalpha(*p)) {
	      int cnst;
	      dns_cent_t c_cent /* ={0} */;
	      SCAN_ALPHANUM(ps,p,len);
	      cnst=lookup_const(ps,len);
	      if(cnst==C_DOMAIN) {
		if (htp) {
		  REPORT_ERROR("You may not specify types=domain together with other types!");
		  PARSERROR;
		}
		hdtp=1;
		if (!init_cent(&c_cent, c_name, c_ttl, 0, DF_LOCAL|DF_NEGATIVE  DBG0))
		  goto out_of_memory;
	      }
	      else if(cnst==0) {
		if (hdtp) {
		  REPORT_ERROR("You may not specify types=domain together with other types!");
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
		    REPORT_ERRORF("unrecognized rr type '%.*s' used as argument for types= option.",(int)len,ps);
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
	      REPORT_ERROR("Bad argument for types= option.");
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
      REPORT_ERROR("expected section header");
      PARSERROR;
    }
  }

  if(!in || feof(in)) {
    if(getnextperr) {
      REPORT_ERROR(getnextperr);
      PARSERROR;
    }
    retval=1; /* success */
  }
  else
    goto input_error;

  goto free_linebuf_return;

 expected_bropen:
  REPORT_ERROR("expected opening brace after section name");
  PARSERROR;

 expected_closing_brace:
  REPORT_ERROR("expected beginning of new option or closing brace");
  PARSERROR;

 expected_equals:
  REPORT_ERROR("expected equals sign after option name");
  PARSERROR;

 expected_semicolon:
  REPORT_ERROR("too many arguments to option or missing semicolon");
  PARSERROR;

 no_name_spec:
  REPORT_ERROR("you must specify a name before a,ptr,cname,mx,ns(owner) and soa records.");
  PARSERROR;

 internal_parse_error:
  if(asprintf(errstr,"Internal inconsistency detected while parsing line %u of %s.\n"
	      "Please consider reporting this error to one of the maintainers.\n",linenr,conftype)<0)
    *errstr=NULL;
  PARSERROR;

 out_of_memory:
  /* If malloc() just failed, allocating space for an error message is unlikely to succeed. */
  *errstr=NULL;
  PARSERROR;

 unexpected_eof:
  if(!in || feof(in)) {
    REPORT_ERROR(getnextperr?getnextperr:in?"unexpected end of file":"unexpected end of input string");
  }
  else
    input_error: {
    if(asprintf(errstr,"Error while reading config file: %s",strerror(errno))<0)
      *errstr=NULL;
  }

 free_linebuf_return:
  free(linebuf);
  return retval;

#undef SKIP_BLANKS
#undef REPORT_ERROR
#undef REPORT_ERRORF
#undef PARSERROR
#undef CLEANUP_GOTO
}


/* Convert a string representation of an IP address into a binary format. */
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

/* Add an IP address to the list of name servers. */
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
	fprintf(stderr,"IPv6 address \"%s\" in config file ignored while running in IPv4 mode.\n",buf);
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
  SET_PDNSD_A2(&at->a, &addr);
  at->is_up=0;
  at->i_ts=0;
  return NULL;
}


/* Helper functions for making netmasks */
inline static uint32_t mk_netmask4(int len)
{
  uint32_t m;

  if(len<=0)
    return 0;

  m= ~(uint32_t)0;
  return (len<32)? htonl(m<<(32-len)): m;
}

#if ALLOW_LOCAL_AAAA
inline static void mk_netmask6(struct in6_addr *m, int len)
{
  uint32_t *ma = (uint32_t *)m;
  ma[0] = mk_netmask4(len);
  ma[1] = mk_netmask4(len -= 32);
  ma[2] = mk_netmask4(len -= 32);
  ma[3] = mk_netmask4(len -= 32);
}
#endif

/* Add an IP address/mask to the reject lists. */
static const char *reject_add(servparm_t *serv, const char *ipstr, size_t len)
{
  TEMPSTRNCPY(buf,ipstr,len);
  {
    char *slash=strchr(buf,'/'); int mlen=0;

    if(slash) {
      *slash++=0;

      if(*slash && isdigit(*slash)) {
	char *endptr;
	int l = strtol(slash,&endptr,10);
	if(!*endptr) {
	  mlen=l;
	  slash=NULL;
	}
      }
    }
    else
      mlen=128; /* Works for both IPv4 and IPv6 */

    {
      addr4maskpair_t am;

      am.mask.s_addr = mk_netmask4(mlen);
      if(inet_aton(buf,&am.a) && (!slash || inet_aton(slash,&am.mask))) {
	if(!(serv->reject_a4=DA_GROW1(serv->reject_a4)))
	  return "out of memory!";

	DA_LAST(serv->reject_a4) = am;
	return NULL;
      }
    }
#if ALLOW_LOCAL_AAAA
    {
      addr6maskpair_t am;

      mk_netmask6(&am.mask,mlen);
      if(inet_pton(AF_INET6,buf,&am.a)>0 && (!slash || inet_pton(AF_INET6,slash,&am.mask)>0)) {
	if(!(serv->reject_a6=DA_GROW1(serv->reject_a6)))
	  return "out of memory!";

	DA_LAST(serv->reject_a6) = am;
	return NULL;
      }
    }
#endif
  }
  return "bad IP address";
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
	if(is_local_addr(PDNSD_A2_TO_A(&at->a))) {
	  char buf[ADDRSTR_MAXLEN];
	  fprintf(stderr,"Local name-server address \"%s\" ignored in config file.\n",
		  pdnsd_a2str(PDNSD_A2_TO_A(&at->a),buf,ADDRSTR_MAXLEN));
	  continue;
	}
      }
      else {
	if(equiv_inaddr2(&global.a,&at->a)) {
	  char buf[ADDRSTR_MAXLEN];
	  fprintf(stderr,"Ignoring name-server address \"%s\" in config file (identical to server_ip address).\n",
		  pdnsd_a2str(PDNSD_A2_TO_A(&at->a),buf,ADDRSTR_MAXLEN));
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
    if(asprintf(errstr, "Failed to open %s: %s", fn, strerror(errno))<0)
      *errstr=NULL;
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
	if(asprintf(errstr, "%s in line %u of file %s", errmsg,linenr,fn)<0)
	  *errstr=NULL;
	goto cleanup_return;
      }
    }
  nextline:;
  }
  if (feof(f))
    rv=1;
  else if(asprintf(errstr, "Failed to read %s: %s", fn, strerror(errno))<0)
    *errstr=NULL;
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
  if((err=parsestr2rhn(ucharp nm,len,rhn)))
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

  if((err=parsestr2rhn(ucharp zone,len,rhn)))
    return err;
  sz=rhnlen(rhn);
  if(!(*za=DA_GROW1_F(*za,free_zone)) || !(DA_LAST(*za)=z=malloc(sz)))
    return "out of memory!";
  memcpy(z,rhn,sz);
  return NULL;
}

