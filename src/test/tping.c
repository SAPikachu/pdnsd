#include <config.h>
#include <stdio.h>
#include <pthread.h>
#include "../icmp.h"
#include "../ipvers.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: tping.c,v 1.2 2000/10/18 16:21:37 thomas Exp $";
#endif

int daemon_p=0;
int debug_p=0;
int verbosity=VERBOSITY;
pthread_t main_thread;

int run_ipv4=DEFAULT_IPV4;
int run_ipv6=DEFAULT_IPV6;

int main(int argc, char *argv[]) 
{
	pdnsd_a a;

	if (argc!=2) {
		printf("Usage: %s <address>\n",argv[0]);
		exit(1);
	}
#ifdef ENABLE_IPV4
	if (inet_aton(argv[1],&a.ipv4)) {
		run_ipv4=1;
		run_ipv6=0;
		init_ping_socket();
		printf("ping (v4) echo from %s: %i\n",argv[1],ping(&a,100,2));
		return 0;
	}
#endif
#ifdef ENABLE_IPV6
	if (inet_pton(AF_INET6,argv[1],&a.ipv4)) {
		run_ipv4=0;
		run_ipv6=1;
		init_ping_socket();
		printf("ping (v6) echo from %s: %i\n",argv[1],ping(&a,100,2));
		return 0;
	}
#endif
	printf("Adress invalid.\n");
	return 0;
}
