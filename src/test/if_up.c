#include <config.h>
#include <pthread.h>
#include <stdio.h>
#include "../netdev.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: if_up.c,v 1.1 2000/07/20 20:03:25 thomas Exp $";
#endif

int daemon_p=0;
int debug_p=0;
int verbosity=VERBOSITY;
pthread_t main_thread;

int run_ipv4=DEFAULT_IPV4;
int run_ipv6=DEFAULT_IPV6;

int main(int argc, char *argv[]) 
{
	if (argc!=2) {
		printf("Usage: %s <interface>\n",argv[0]);
		exit(1);
	}
	printf("if_up: %s - %s\n",argv[1],if_up(argv[1])?"up":"down");
	return 0;
}
