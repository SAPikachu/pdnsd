/* config.h.  Generated automatically by configure.  */
/* config.h.in.  Generated automatically from configure.in by autoheader.  */

/* Define if using alloca.c.  */
/* #undef C_ALLOCA */

/* Define to empty if the keyword does not work.  */
/* #undef const */

/* Define to one of _getb67, GETB67, getb67 for Cray-2 and Cray-YMP systems.
   This function is required for alloca.c support on those systems.  */
/* #undef CRAY_STACKSEG_END */

/* Define if you have alloca, as a function or macro.  */
#define HAVE_ALLOCA 1

/* Define if you have <alloca.h> and it should be used (not on Ultrix).  */
#define HAVE_ALLOCA_H 1

/* Define if you don't have vprintf but do have _doprnt.  */
/* #undef HAVE_DOPRNT */

/* Define if you have <sys/wait.h> that is POSIX.1 compatible.  */
#define HAVE_SYS_WAIT_H 1

/* Define if you have the vprintf function.  */
#define HAVE_VPRINTF 1

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef pid_t */

/* Define as the return type of signal handlers (int or void).  */
#define RETSIGTYPE void

/* Define to `unsigned' if <sys/types.h> doesn't define.  */
/* #undef size_t */

/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at run-time.
 STACK_DIRECTION > 0 => grows toward higher addresses
 STACK_DIRECTION < 0 => grows toward lower addresses
 STACK_DIRECTION = 0 => direction of growth unknown
 */
/* #undef STACK_DIRECTION */

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
#define TIME_WITH_SYS_TIME 1

/* Define if your <sys/time.h> declares struct tm.  */
/* #undef TM_IN_SYS_TIME */

/* Define if lex declares yytext as a char * by default, not a char[].  */
#define YYTEXT_POINTER 1

/* Define your Target here. Currently defined are TARGET_LINUX (any 
 * architecture) and TARGET_BSD (experimental; tested on FreeBSD, hopefully 
 * works for other BSD variants) */
#define TARGET TARGET_LINUX 

/* change the #undef to #define if you do not want to compile with special 
 * ISDN support for Linux. Note that the ISDN support will not compile ok on 
 * unpatched kernerls earlier than 2.2.12 (if you did apply newer isdn patches,
 * it may work fine). This is not on by default because it will cause compile 
 * problems on some systems */
#define ISDN_SUPPORT 1

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
#define ENABLE_IPV4 1
#define DEFAULT_IPV4 1
/* #undef ENABLE_IPV6 */
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
/* #undef NO_UDP_QUERIES */
#define NO_TCP_QUERIES 1

/* With the following option, you can disable the TCP server functionality
 * of pdnsd. Nearly no program does TCP queries, so you probably can do
 * this safely and save some executable space and one thread.
 * You also can turn off the TCP server at runtimu with the -t option. */
/* #undef NO_TCP_SERVER */

/* By undefining the following, you can disable the UDP source address
 * discovery code. This is not recommended, but you may need it when
 * running into compilation problems. */
#define SRC_ADDR_DISC 1

/* NO_POLL specifies not to use poll(2), but select(2) instead. If you are
 * unsure about what this means, just leave this as it is.*/
#define NO_POLL 1

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
#define DNS_NEW_RRS 1

/* Define this for "hard" RFC 2181 compliance: this RFC states that
 * implementations should discard answers whose RR sets have multiple
 * different time stamps. While correct answers are generated, incorrect
 * ones are normally tolerated and corrected. Full RFC compliance is
 * however only achieved by deactivating this behaviour and thus being
 * intolerant. */
/* #undef RFC2181_ME_HARDER */

/* Define this to the device you want to use for getting random numbers.
 * Leave this undefined if you wand to use the standard C library random
 * function, which basically should be sufficient.
 * Linux and FreeBSD have two random number devices: /dev/random and
 * /dev/urandom. /dev/urandom might be less secure in some cases, but
 * should still be more than sufficient. The use of /dev/random is 
 * discouraged, as reading from this device blocks when new random bits
 * need to be gathered. */
/* #undef RANDOM_DEVICE */
#define R_DEFAULT 1
/* #undef R_RANDOM */
/* #undef R_ARC4RANDOM */
/*#define RANDOM_DEVICE "/dev/urandom"*/

#define CACHEDIR "/var/cache/pdnsd"

/* yylineno not provided by flex */
/* #undef NO_YYLINENO */

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
/* #undef DEBUG_HASH */

/* Define this if you need to debug the config file parser. Will generate lots
 * of diagnostic messages.  */
/* #undef DEBUG_YY */

/* Defining NO_RCSIDS will exclude the CVS/RCS Id tags from the executables.
 * This is normally a good idea when you build pdnsd only for yourself (saves
 * executable space) but should be left enable when you build binaries for
 * distributions as it makes error-tracking easier. */
#define NO_RCSIDS 1

 
/* #undef NO_IN_PKTINFO */

/* Lock the UDP socket before using it? */
/* #undef SOCKET_LOCKING */

/* Default TCP timeout when receiving queries */
#define TCP_TIMEOUT 30

/* Allow subsequent TCP queries on one connection? */
/* #undef TCP_SUBSEQ */

/*default value for parallel query number */
#define PAR_QUERIES   2 

/* These are the possible targets. Normally no need to touch these 
 * definitions. */
#define TARGET_LINUX 0
#define TARGET_BSD   1

/* Allow _ in domain names? */
/* #undef UNDERSCORE */

/* Define if you have the gettimeofday function.  */
#define HAVE_GETTIMEOFDAY 1

/* Define if you have the mkfifo function.  */
#define HAVE_MKFIFO 1

/* Define if you have the poll function.  */
#define HAVE_POLL 1

/* Define if you have the select function.  */
#define HAVE_SELECT 1

/* Define if you have the snprintf function.  */
#define HAVE_SNPRINTF 1

/* Define if you have the socket function.  */
#define HAVE_SOCKET 1

/* Define if you have the strerror function.  */
#define HAVE_STRERROR 1

/* Define if you have the uname function.  */
#define HAVE_UNAME 1

/* Define if you have the usleep function.  */
#define HAVE_USLEEP 1

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have the <malloc.h> header file.  */
#define HAVE_MALLOC_H 1

/* Define if you have the <netinet/in.h> header file.  */
#define HAVE_NETINET_IN_H 1

/* Define if you have the <sys/ioctl.h> header file.  */
#define HAVE_SYS_IOCTL_H 1

/* Define if you have the <sys/time.h> header file.  */
#define HAVE_SYS_TIME_H 1

/* Define if you have the <syslog.h> header file.  */
#define HAVE_SYSLOG_H 1

/* Define if you have the <unistd.h> header file.  */
#define HAVE_UNISTD_H 1

/* Define if you have the pthread library (-lpthread).  */
#define HAVE_LIBPTHREAD 1

/* Name of package */
#define PACKAGE "pdnsd"

/* Version number of package */
#define VERSION "1.1.7a-par"

