#ifndef _CONFIG_H_
#define _CONFIG_H_

/* $Id: acconfig.h,v 1.10 2000/10/17 20:34:44 thomas Exp $ */

/* ONLY EDIT config.h.in, NEVER config.h!
 * config.h MAY BE OVERWRITTEN BY make! */

/* -- Target Selection ------------------------------------------------------ */

/* Define your Target here. Currently defined are TARGET_LINUX (any 
 * architecture) and TARGET_BSD (experimental; tested on FreeBSD, hopefully 
 * works for other BSD variants) */
#define TARGET TARGET_LINUX 

/* -- Feature Options -------------------------------------------------------- */

/* change the #undef to #define if you do not want to compile with special 
 * ISDN support for Linux. Note that the ISDN support will not compile ok on 
 * unpatched kernerls earlier than 2.2.12 (if you did apply newer isdn patches,
 * it may work fine). This is not on by default because it will cause compile 
 * problems on some systems */
#undef ISDN_SUPPORT

/* The following regulates the IP Protocol support. Supported types are IPv4
 * and IPv6 (aka IPng). You may enable either or both of these protocols. 
 * Enabling in this context means that support for the respective protocol
 * will be in the binary. When running the binary, one of the protocols may
 * be activated via command line switches. Note that activating both IPv4 and
 * IPv6 is pointless (and will not work because two UDP and two TCP threads
 * will be started that concur for ports). Because of that, it is not allowed.
 * When pdnsd runs with IPv6 activated it should be able to service queries
 * from IPv6 as well as from IPv4 hosts, provided that you host is configured
 * properly.
 * For each of the protocols there are two options: ENABLE_IPV4 and ENABLE_IPV6
 * control whether support for the respective protocol is available in the 
 * binary. DEFAULT_IPV4 and DEFAULT_IPV6 select whether is enabled on pdnsd
 * startup by default. 1 means enabled, while 0 means disabled. If support for
 * a protocol was included in the executable, you can specify command line
 * parameters to activate or deactivate that protocol (the options are -4 and 
 * -6).
 * Make your choice. Note that IPv6 support is experimental in pdnsd. 
 * In normal operation, you will currently only need IPv4. 
 * If you activete IPv6, you should also activate DNS_NEW_RRS below. */
#undef ENABLE_IPV4
#define DEFAULT_IPV4 0
#undef ENABLE_IPV6
#define DEFAULT_IPV6 0

/* In all pdnsd versions before 1.0.6, DNS queries were always done over
 * TCP. Now, you have the choice. You can control that behaviour using 
 * the -m command line switch, and you can give a preset here. There
 * are 3 different modes:
 * UDP_ONLY: This is undoubtedly the fastest query method, because
 *       no TCP negotiation needs to be done.
 * TCP_ONLY: This is slower than uo, but generally more secure
 *       against DNS spoofing. Note that some name servers on the 
 *       internet do not support TCP queries, notably dnscache.
 * TCP_UDP: TCP, then UDP. If the TCP query fails with a "connection refused"-
 *       error, the query is retried using UDP. */
#define M_PRESET UDP_ONLY

/* In addition to choosing the presets, you may also completely disable
 * one of the protocols (TCP for preset UDP_ONLY and UDP for preset TCP_ONLY).
 * This saves some executable space. */
#undef NO_UDP_QUERIES
#undef NO_TCP_QUERIES

/* With the following option, you can disable the TCP server functionality
 * of pdnsd. Nearly no program does TCP queries, so you probably can do
 * this safely and save some executable space and one thread.
 * You also can turn off the TCP server at runtimu with the -t option. */
#undef NO_TCP_SERVER

/* By undefining the following, you can disable the UDP source address
 * discovery code. This is not recommended, but you may need it when
 * running into compilation problems. */
#undef SRC_ADDR_DISC

/* NO_POLL specifies not to use poll(2), but select(2) instead. If you are
 * unsure about what this means, just leave this as it is.*/
#undef NO_POLL

/* Define this if you want to compile with support for the new
 * rrs defined in various rfcs (see rfc1700 for an (incomplete) 
 * listing and pointers). These are normally not needed and consume 
 * some memory even if no records are present. You should delete the cache
 * files before you use a version with this option changed.
 * If you consider using IPv6, you will probably need the AAAA
 * (IPv6 address) record type and should enable this option. 
 * See dns.h for the definitions.
 * In short, these RRs are:
 * RP, AFSDB, X25, ISDN, RT, NSAP, PX, GPOS, AAAA, LOC,
 * EID, NIMLOC, SRV, ATMA, NAPTR and KX*/
#undef DNS_NEW_RRS

/* Define this for "hard" RFC 2181 compliance: this RFC states that
 * implementations should discard answers whose RR sets have multiple
 * different time stamps. While correct answers are generated, incorrect
 * ones are normally tolerated and corrected. Full RFC compliance is
 * however only achieved by deactivating this behaviour and thus being
 * intolerant. */
#undef RFC2181_ME_HARDER

/* Define this to the device you want to use for getting random numbers.
 * Leave this undefined if you wand to use the standard C library random
 * function, which basically should be sufficient.
 * Linux and FreeBSD have two random number devices: /dev/random and
 * /dev/urandom. /dev/urandom might be less secure in some cases, but
 * should still be more than sufficient. The use of /dev/random is 
 * discouraged, as reading from this device blocks when new random bits
 * need to be gathered. */
#undef RANDOM_DEVICE
/*#define RANDOM_DEVICE "/dev/urandom"*/

/* Designate which database manager to use for cacheing.
 * default: native; others: gdbm */
#define CACHE_DBM DBM_NATIVE

#define CACHEDIR "/var/cache/pdnsd"

#define TEMPDIR "/tmp";

/* yylineno not provided by flex */
#undef NO_YYLINENO

/* -- Debugging Options ------------------------------------------------------ */

/* This is for various debugging facilities that produce debug output and
 * double-check some values. You can enable debug messages with the -g option.
 * Normally, you can switch this off safely by setting the number after DEBUG
 * to 0. This will increase speed (although only marginally) and save space 
 * in the executable (only about 5kB).
 * However, it may be an aid when debugging config files. 
 * The only defined debug levels by now are 0 (off) and 1 (on).
 * Defining this larger than 1 does no harm.
 * When in doubt, leave it defined to 1. */
#define DEBUG 9 

/* This defines the default verbosity of informational messages you will get. 
   This has nothing to to with the debug option (-g), but may be set with -v 
   option. 0 is for normal operation, up to 3 for debugging.
   Unlike the debug messages, these messages will also be written to the syslog.*/
#define VERBOSITY 0

/* Set this to debug the hash tables. Turn this off normally, or you will get
 * flooded with diagnostic messages */
#undef DEBUG_HASH

/* Define this if you need to debug the config file parser. Will generate lots
 * of diagnostic messages.  */
#undef DEBUG_YY

/* Defining NO_RCSIDS will exclude the CVS/RCS Id tags from the executables.
 * This is normally a good idea when you build pdnsd only for yourself (saves
 * executable space) but should be left enable when you build binaries for
 * distributions as it makes error-tracking easier. */
#undef NO_RCSIDS

/* Define if system has not packet info structure
 * (previously done by a-conf.sh/a-conf.h) */
 
#undef NO_IN_PKTINFO

/* Lock the UDP socket before using it? */
#define SOCKET_LOCKING

/* Default TCP timeout when receiving queries */
#define TCP_TIMEOUT 30

/* Allow subsequent TCP queries on one connection? */
#undef TCP_SUBSEQ

/*default value for parallel query number */
#define PAR_QUERIES   2 

/* -- End of User-Configureable Options ------------------------------------- */

/* These are the possible targets. Normally no need to touch these 
 * definitions. */
#define TARGET_LINUX 0
#define TARGET_BSD   1

/* Possible dbm's for cacheing */
#define DBM_NATIVE   0
#define DBM_GDBM     1
 
/* The following is needed for using LinuxThreads. Better don't touch. */
#define _REENTRANT
#define _THREAD_SAFE

/* pdnsd version. DO NOT TOUCH THIS! It is replaced automatically by the
 * contents of ./version */
#define VERSION @VERSION@
#endif
