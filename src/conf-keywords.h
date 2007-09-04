/* conf-keywords.h - Tables used by parser of configuration file.
   Based on information previously contained in conf-lex.y and conf-parse.y

   Copyright (C) 2004,2005,2006,2007 Paul A. Rombouts

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

enum {
	ERROR,
	
	GLOBAL,
	SERVER,
	RR,
	NEG,
	SOURCE,
	
	PERM_CACHE,
	CACHE_DIR,
	SERVER_PORT,
	SERVER_IP,
	SCHEME_FILE,
	LINKDOWN_KLUGE,
	MAX_TTL,
	MIN_TTL,
	RUN_AS,
	STRICT_SETUID,
	USE_NSS,
	PARANOID,
	STATUS_CTL,
	DAEMON,
	C_TCP_SERVER,
	PID_FILE,
	C_VERBOSITY,
	C_QUERY_METHOD,
	RUN_IPV4,
	IPV4_6_PREFIX,
	C_DEBUG,
	C_CTL_PERMS,
	C_PROC_LIMIT,
	C_PROCQ_LIMIT,
	TCP_QTIMEOUT,
	C_PAR_QUERIES,
	C_RAND_RECS,
	NEG_TTL,
	NEG_RRS_POL,
	NEG_DOMAIN_POL,
	QUERY_PORT_START,
	QUERY_PORT_END,
	DELEGATION_ONLY,
	
	IP,
	PORT,
	SCHEME,
	UPTEST,
	TIMEOUT,
	PING_TIMEOUT,
	PING_IP,
	UPTEST_CMD,
	INTERVAL,
	INTERFACE,
	DEVICE,
	PURGE_CACHE,
	CACHING,
	LEAN_QUERY,
	PRESET,
	PROXY_ONLY,
	ROOT_SERVER,
	RANDOMIZE_SERVERS,
	INCLUDE,
	EXCLUDE,
	POLICY,
	REJECTLIST,
	REJECTPOLICY,
	REJECTRECURSIVELY,
	LABEL,
	
	A,
	PTR,
	MX,
	SOA,
	CNAME,
	NAME,
	OWNER,
	TTL,
	TYPES,
	FILET,
	SERVE_ALIASES,
	AUTHREC,
	REVERSE
};


/* Table for looking up section headers. Order alphabetically! */
static const namevalue_t section_headers[]= {
	{"global", GLOBAL},
	{"neg",    NEG},
	{"rr",     RR},
	{"server", SERVER},
	{"source", SOURCE}
};

/* Table for looking up global options. Order alphabetically! */
static const namevalue_t global_options[]= {
	{"cache_dir",        CACHE_DIR},
	{"ctl_perms",        C_CTL_PERMS},
	{"daemon",           DAEMON},
	{"debug",            C_DEBUG},
	{"delegation_only",  DELEGATION_ONLY},
	{"interface",        SERVER_IP},
	{"ipv4_6_prefix",    IPV4_6_PREFIX},
	{"linkdown_kluge",   LINKDOWN_KLUGE},
	{"max_ttl",          MAX_TTL},
	{"min_ttl",          MIN_TTL},
	{"neg_domain_pol",   NEG_DOMAIN_POL},
	{"neg_rrs_pol",      NEG_RRS_POL},
	{"neg_ttl",          NEG_TTL},
	{"par_queries",      C_PAR_QUERIES},
	{"paranoid",         PARANOID},
	{"perm_cache",       PERM_CACHE},
	{"pid_file",         PID_FILE},
	{"proc_limit",       C_PROC_LIMIT},
	{"procq_limit",      C_PROCQ_LIMIT},
	{"query_method",     C_QUERY_METHOD},
	{"query_port_end",   QUERY_PORT_END},
	{"query_port_start", QUERY_PORT_START},
	{"randomize_recs",   C_RAND_RECS},
	{"run_as",           RUN_AS},
	{"run_ipv4",         RUN_IPV4},
	{"scheme_file",      SCHEME_FILE},
	{"server_ip",        SERVER_IP},
	{"server_port",      SERVER_PORT},
	{"status_ctl",       STATUS_CTL},
	{"strict_setuid",    STRICT_SETUID},
	{"tcp_qtimeout",     TCP_QTIMEOUT},
	{"tcp_server",       C_TCP_SERVER},
	{"timeout",          TIMEOUT},
	{"use_nss",          USE_NSS},
	{"verbosity",        C_VERBOSITY}
};

/* Table for looking up server options. Order alphabetically! */
static const namevalue_t server_options[]= {
	{"caching",            CACHING},
	{"device",             DEVICE},
	{"exclude",            EXCLUDE},
	{"file",               FILET},
	{"include",            INCLUDE},
	{"interface",          INTERFACE},
	{"interval",           INTERVAL},
	{"ip",                 IP},
	{"label",              LABEL},
	{"lean_query",         LEAN_QUERY},
	{"ping_ip",            PING_IP},
	{"ping_timeout",       PING_TIMEOUT},
	{"policy",             POLICY},
	{"port",               PORT},
	{"preset",             PRESET},
	{"proxy_only",         PROXY_ONLY},
	{"purge_cache",        PURGE_CACHE},
	{"randomize_servers",  RANDOMIZE_SERVERS},
	{"reject",             REJECTLIST},
	{"reject_policy",      REJECTPOLICY},
	{"reject_recursively", REJECTRECURSIVELY},
	{"root_server",        ROOT_SERVER},
	{"scheme",             SCHEME},
	{"timeout",            TIMEOUT},
	{"uptest",             UPTEST},
	{"uptest_cmd",         UPTEST_CMD}
};

/* Table for looking up rr options. Order alphabetically! */
static const namevalue_t rr_options[]= {
	{"a",       A},
	{"authrec", AUTHREC},
	{"cname",   CNAME},
	{"mx",      MX},
	{"name",    NAME},
	{"ns",      OWNER},
	{"owner",   OWNER},
	{"ptr",     PTR},
	{"reverse", REVERSE},
	{"soa",     SOA},
	{"ttl",     TTL}
};

/* Table for looking up source options. Order alphabetically! */
static const namevalue_t source_options[]= {
	{"authrec",       AUTHREC},
	{"file",          FILET},
	{"ns",            OWNER},
	{"owner",         OWNER},
	{"serve_aliases", SERVE_ALIASES},
	{"ttl",           TTL}
};

/* Table for looking up neg options. Order alphabetically! */
static const namevalue_t neg_options[]= {
	{"name",  NAME},
	{"ttl",   TTL},
	{"types", TYPES}
};
