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
# define	IP	295
# define	PORT	296
# define	SCHEME	297
# define	UPTEST	298
# define	TIMEOUT	299
# define	PING_TIMEOUT	300
# define	PING_IP	301
# define	UPTEST_CMD	302
# define	INTERVAL	303
# define	INTERFACE	304
# define	DEVICE	305
# define	PURGE_CACHE	306
# define	CACHING	307
# define	LEAN_QUERY	308
# define	PRESET	309
# define	PROXY_ONLY	310
# define	INCLUDE	311
# define	EXCLUDE	312
# define	POLICY	313
# define	LABEL	314
# define	A	315
# define	PTR	316
# define	MX	317
# define	SOA	318
# define	CNAME	319
# define	NAME	320
# define	OWNER	321
# define	TTL	322
# define	TYPES	323
# define	FILET	324
# define	SERVE_ALIASES	325
# define	AUTHREC	326
# define	NDOMAIN	327
# define	CONST	328
# define	RRTYPE	329


extern YYSTYPE yylval;

#endif /* not BISON_Y_TAB_H */
