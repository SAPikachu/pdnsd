#include <config.h>
#include <stdio.h>
#include <pthread.h>
#include "../helpers.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: random.c,v 1.1 2000/07/20 20:03:25 thomas Exp $";
#endif

int daemon_p=0;
int debug_p=0;
int verbosity=VERBOSITY;
pthread_t main_thread;

int run_ipv4=DEFAULT_IPV4;
int run_ipv6=DEFAULT_IPV6;

int main(void) 
{
	init_rng();
	printf("%i\n",(int)get_rand16());
	free_rng();
	return 0;
}
