#include <config.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include "../helpers.h"
#include "../conff.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: random.c,v 1.1 2000/07/20 20:03:25 thomas Exp $";
#endif

short int daemon_p=0;
short int debug_p=0;
short int verbosity=VERBOSITY;
#if defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
short int run_ipv4=DEFAULT_IPV4;
#endif
#ifdef ENABLE_IPV6
struct in6_addr ipv4_6_prefix;
#endif
pthread_t main_thread;
#if DEBUG>0
FILE *dbg_file;
#endif
globparm_t global;


int main(void) 
{
	init_rng();
	printf("%i\n",(int)get_rand16());
	free_rng();
	return 0;
}
