#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include "../helpers.h"
#include "../conff.h"
#include "../icmp.h"
#include "../ipvers.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: tping.c,v 1.2 2000/10/18 16:21:37 thomas Exp $";
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


int main(int argc, char *argv[]) 
{
	pdnsd_a a;

	if (argc!=2) {
		printf("Usage: %s <address>\n",argv[0]);
		exit(1);
	}
#ifdef ENABLE_IPV4
	if (inet_aton(argv[1],&a.ipv4)) {
# ifdef ENABLE_IPV6
		run_ipv4=1;
# endif
		init_ping_socket();
		printf("ping (v4) echo from %s: %i\n",argv[1],ping(&a,100,2));
		return 0;
	}
#endif
#ifdef ENABLE_IPV6
	if (inet_pton(AF_INET6,argv[1],&a.ipv6)) {
# ifdef ENABLE_IPV4
		run_ipv4=0;
# endif
		init_ping_socket();
		printf("ping (v6) echo from %s: %i\n",argv[1],ping(&a,100,2));
		return 0;
	}
#endif
	printf("Adress invalid.\n");
	return 0;
}
