/* This include file added by Paul Rombouts.
   I had terrible difficulties with cyclic dependencies of the include files
   written by Thomas Moestl. The only way I knew how to break the cycle was to
   put some declarations in a seperate file.
*/

#ifndef PDNSD_ASSERT_H
#define PDNSD_ASSERT_H

/* Originally in helpers.h */

/* format string checking for printf-like functions */
#ifdef __GNUC__
#define printfunc(fmt, firstva) __attribute__((__format__(__printf__, fmt, firstva)))
#else
#define printfunc(fmt, firstva)
#endif

void pdnsd_exit(void);


/* Originally in error.h */

void log_error(char *s,...) printfunc(1, 2);

/*
 * Assert macro, used in some places. For now, it should be always defined, not
 * only in the DEBUG case, to be on the safe side security-wise.
 */
#define PDNSD_ASSERT(cond, msg)						\
	{ if (!(cond)) {						\
		log_error("%s:%d: %s", __FILE__, __LINE__, msg);	\
		pdnsd_exit();						\
 	} }

#endif
