#ifndef BISON_Y_TAB_H
# define BISON_Y_TAB_H

#ifndef YYSTYPE
typedef union {
long 	      num;
unsigned char *nm;
} yystype;
# define YYSTYPE yystype
# define YYSTYPE_IS_TRIVIAL 1
#endif
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


extern YYSTYPE yylval;

#endif /* not BISON_Y_TAB_H */
