/* main.c - Command line parsing, intialisation and server start
   Copyright (C) 2000, 2001 Thomas Moestl

This file is part of the pdnsd package.

pdnsd is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

pdnsd is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pdsnd; see the file COPYING.  If not, write to
the Free Software Foundation, 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

/* in order to use O_NOFOLLOW on Linux: */
#define _GNU_SOURCE

#include "config.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include <pwd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "consts.h"
#include "cacheing/cache.h"
#include "status.h"
#include "servers.h"
#include "dns_answer.h"
#include "dns_query.h"
#include "error.h"
#include "helpers.h"
#include "icmp.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: main.c,v 1.26 2001/01/24 19:47:01 thomas Exp $";
#endif

#ifdef DEBUG_YY
extern int yydebug;
#endif

int daemon_p=0;
int debug_p=0;
int verbosity=VERBOSITY;
pthread_t main_thread;
#if DEBUG>0
FILE *dbg;
#endif
#ifdef ENABLE_IPV4
int run_ipv4=DEFAULT_IPV4;
#endif
#ifdef ENABLE_IPV6
int run_ipv6=DEFAULT_IPV6;
#endif
int tcp_socket=-1;
int udp_socket=-1;
sigset_t sigs_msk;
char pidfile[MAXPATH]="\0";
int stat_pipe=0;
int notcp=0;
int sigr=0;

/*
#if TARGET==TARGET_BSD
void bsd_sighnd (int sig) {
	sigr=sig;
}
#endif
*/

/* These are some init steps we have to call before we get daemon on linux, but need
 * do call after daemonizing on other OSes.
 * Theay are also the last steps before we drop privileges. */
int final_init()
{
#ifndef NO_TCP_SERVER
	if (!notcp)
		tcp_socket=init_tcp_socket();
#endif
	udp_socket=init_udp_socket();
	if (tcp_socket==-1 && udp_socket==-1) {
		log_error("tcp and udp initialization failed. Exiting.");
		exit(1);
	}
	if (global.strict_suid) {
		if (!run_as(global.run_as)) {
			log_error("Could not change user and group id to those of run_as user %s",global.run_as);
			return 0;
		}
	}
	return 1;
}

/* Print version and licensing information */
void print_info (void)
{
	printf("pdnsd - dns proxy daemon, version %s\n\n",VERSION);
	printf("pdnsd is free software; you can redistribute it and/or modify\n");
	printf("it under the terms of the GNU General Public License as published by\n");
	printf("the Free Software Foundation; either version 2, or (at your option)\n");
	printf("any later version.\n\n");
	printf("pdnsd is distributed in the hope that it will be useful,\n");
	printf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
	printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
	printf("GNU General Public License for more details.\n\n");
	printf("You should have received a copy of the GNU General Public License\n");
	printf("along with pdsnd; see the file COPYING.  If not, write to\n");
	printf("the Free Software Foundation, 59 Temple Place - Suite 330,\n");
	printf("Boston, MA 02111-1307, USA.\n");
}

/* Print the help page */
void print_help (void)
{
	printf("\n\nUsage: pdnsd [-h] [-V] [-s] [-d] [-g] [-vn] [-mxx] [-c file]");
#ifdef ENABLE_IPV4
	printf(" [-4]");
#endif
#ifdef ENABLE_IPV6
	printf(" [-6]");
#endif
	printf("\n\n");
	printf("Options:\n");
	printf("-h\t\t--or--\n");
	printf("--help\t\tprint this help page and exit.\n");
	printf("-V\t\t--or--\n");
	printf("--version\tprint version information and exit.\n");
	printf("--pdnsd-user\tprint the user pdnsd will run as and exit.\n");
	printf("-s\t\t--or--\n");
	printf("--status\tEnable status control socket the temp directory\n");
	printf("-d\t\t--or--\n");
	printf("--daemon\tStart pdnsd in daemon mode (as background process.)\n");
	printf("-g\t\t--or--\n");
	printf("--debug\t\tPrint some debug messages on the console or to the\n");
	printf("\t\tfile pdnsd.debug in your cache directory (in daemon mode).\n");
	printf("-t\t\t--or--\n");
	printf("--tcp\t\tEnables the TCP server thread. pdnsd will then serve\n");
	printf("\t\tTCP and UDP queries.\n");
	printf("-p\t\tWrites the pid the server runs as to a specified filename.\n");
	printf("\t\tWorks only in daemon mode.\n");
	printf("-vn\t\tsets the verbosity of pdnsd. n is a numeric argument from 0\n");
	printf("\t\t(normal operation) to 3 (many messages for debugging).\n");
	printf("\t\tUse like -v2\n");
	printf("-mxx\t\tsets the query method pdnsd uses. Possible values for xx are:\n");
	printf("\t\tuo (UDP only), to (TCP only), and tu (TCP or, if the server\n");
	printf("\t\tdoes not support this, UDP). Use like -muo. Preset: %s\n", 
	       M_PRESET==UDP_ONLY?"-muo":(M_PRESET==TCP_ONLY?"-mto":"mtu"));
	printf("-c\t\t--or--\n");
	printf("--config-file\tspecifies the file the configuration is read from.\n");
	printf("\t\tDefault is %s/pdnsd.conf\n",CONFDIR);
#ifdef ENABLE_IPV4
	printf("-4\t\tenables IPv4 support. IPv6 support is automatically\n");
	printf("\t\tdisabled (should it be available). %s by default.\n",DEFAULT_IPV4?"On":"Off");
#endif
#ifdef ENABLE_IPV6
	printf("-6\t\tenables IPv6 support. IPv4 support is automatically\n");
	printf("\t\tdisabled (should it be available). %s by default.\n",DEFAULT_IPV6?"On":"Off");
#endif
	printf("\n\n\"no\" can be prepended to the --status, --daemon, --debug and --tcp\n");
	printf("options (e.g. --notcp) to reverse their effect.\n");
}

/*
 * Argument parsing, init, server startup
 */
int main(int argc,char *argv[])
{
	int i,sig,pfd,np=0;
	struct passwd *pws;
	char *conf_file=CONFDIR"/pdnsd.conf";
#if DEBUG>0
	char dbgdir[1024];
#endif
	FILE *pf;

	main_thread=pthread_self();
	
#ifdef DEBUG_YY
	yydebug=1;
#endif

	/* We parse the command line two times, because the command-line options shall override the ones
	 * given in the config file */
	for (i=1;i<argc;i++) {
		if (strcmp(argv[i],"-h")==0 || strcmp(argv[i],"--help")==0) {
			print_info();
			print_help();
			exit(1);
		} else if (strcmp(argv[i],"-V")==0 || strcmp(argv[i],"--version")==0) {
			print_info();
			exit(1);
		} else if (strcmp(argv[i],"-c")==0 || strcmp(argv[i],"--config-file")==0) {
			if (i<argc-1) {
				i++;
				conf_file=argv[i];
			} else {
				fprintf(stderr,"Error: file name expected after -c option.\n");
				exit(1);
			}
		}
	}

	init_cache();
	read_config_file(conf_file);

	for (i=1;i<argc;i++) {
		if (strcmp(argv[i],"-s")==0 || strcmp(argv[i],"--status")==0) {
			stat_pipe=1;
		} else if (strcmp(argv[i],"--nostatus")==0) {
			stat_pipe=0;
		} else if (strcmp(argv[i],"-d")==0 || strcmp(argv[i],"--daemon")==0) {
			daemon_p=1;
		} else if (strcmp(argv[i],"--nodaemon")==0) {
			daemon_p=0;
		} else if (strcmp(argv[i],"-t")==0 || strcmp(argv[i],"--tcp")==0) {
			notcp=0;
		} else if (strcmp(argv[i],"--notcp")==0) {
			notcp=1;
		} else if (strcmp(argv[i],"-p")==0) {
			if (i<argc-1) {
				i++;
				strncpy(pidfile,argv[i],1024);
				pidfile[1023]='\0';
			} else {
				fprintf(stderr,"Error: file name expected after -p option.\n");
				exit(1);
			}
		} else if (strncmp(argv[i],"-v",2)==0) {
			if (strlen(argv[i])!=3 || !isdigit(argv[i][2])) {
				fprintf(stderr,"Error: one digit expected after -v option (like -v2).\n");
				exit(1);
			}
			verbosity=argv[i][2]-'0';
		} else if (strncmp(argv[i],"-m",2)==0) {
			if (strlen(argv[i])!=4) {
				fprintf(stderr,"Error: uo, to or tu expected after the  -m option (like -muo).\n");
				exit(1);
			}
			if (strcmp(&argv[i][2],"uo")==0) {
#ifdef NO_UDP_QUERIES
				fprintf(stderr,"Error: pdnsd was compiled without UDP support.\n");
				exit(1);
#else
				query_method=UDP_ONLY;
#endif
			} else if (strcmp(&argv[i][2],"to")==0) {
#ifdef NO_TCP_QUERIES
				fprintf(stderr,"Error: pdnsd was compiled without TCP support.\n");
				exit(1);
#else
				query_method=TCP_ONLY;
#endif
			} else if (strcmp(&argv[i][2],"tu")==0) {
#if !defined(NO_UDP_QUERIES) || !defined(NO_TCP_QUERIES)
				fprintf(stderr,"Error: pdnsd was not compiled with UDP  and TCP support.\n");
				exit(1);
#else
				query_method=TCP_UDP;
#endif
			} else {
				fprintf(stderr,"Error: uo, to or tu expected after the  -m option (like -muo).\n");
				exit(1);
			}
		} else if (strcmp(argv[i],"-4")==0) {
#ifdef ENABLE_IPV4
			run_ipv4=1;
# ifdef ENABLE_IPV6
			run_ipv6=0;
# endif
#else
			fprintf(stderr,"Error: -4: pdnsd was compiled without IPv4 support.\n");
			exit(1);
#endif
		} else if (strcmp(argv[i],"-6")==0) {
#ifdef ENABLE_IPV6
			run_ipv6=1;
# ifdef ENABLE_IPV4
			run_ipv4=0;
# endif
#else
			fprintf(stderr,"Error: -6: pdnsd was compiled without IPv6 support.\n");
			exit(1);
#endif
		} else if (strcmp(argv[i],"-g")==0 || strcmp(argv[i],"--debug")==0) {
#if DEBUG>0
			debug_p=1;
#else
			fprintf(stderr,"pdnsd was compiled without debugging support. -g has no effect.\n");
#endif
		} else if (strcmp(argv[i],"--nodebug")==0) {
			debug_p=0;
		} else if (strcmp(argv[i],"--pdnsd-user")==0) {
			if (global.run_as[0]) {
				printf("%s\n",global.run_as);
			} else {
				if ((pws=getpwuid(getuid()))) {
					printf("%s\n",pws->pw_name);
				} else {
					printf("%i\n",getuid());
				}
			}
			exit(0);
		} else if (strcmp(argv[i],"-c")!=0 || strcmp(argv[i],"--config-file")!=0) {
			/* at this point, it is already checked that a file name arg follows. */
			i++;
		} else {
			fprintf(stderr,"Error: unknown option: %s\n",argv[i]);
			exit(1);
		}
	}
	
	if (!(global.run_as[0] && global.strict_suid)) {
		struct passwd *pws=getpwuid(getuid());
		char *un=pws?pws->pw_name:"(unknown)";
		for (i=0; i<serv_num; i++) {
			if (server.uptest==C_EXEC && server.uptest_usr[0]=='\0') {
				/* No explicit uptest user given. If we run_as and strict_suid, we assume that
				 * this is safe. If not - warn. */
				fprintf(stderr,"Warning: uptest command \"%s\" will implicitely be executed as user %s!\n",server.uptest_cmd, un);
			}
		}
	}

	/* init_log() initializes a mutex. This is done best once we are daemon.
	 * so this initialization is deferred, and log_* can now do without a mutex
	 * initially */
	/*init_log();*/
	if (daemon_p && pidfile[0]) {
		unlink(pidfile);
#ifdef O_NOFOLLOW		
		if (!(pfd=open(pidfile,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0600))) {
#else
		if (!(pfd=open(pidfile,O_WRONLY|O_CREAT|O_EXCL, 0600))) {
#endif
			log_error("Error: could not open pid file %s: %s\n",pidfile, strerror(errno));
			exit(1);
		}
		if (!(pf=fdopen(pfd,"w"))) {
			log_error("Error: could not open pid file %s: %s\n",pidfile, strerror(errno));
			exit(1);
		}
	}
	for (i=0;i<serv_num;i++) {
		if (servers[i].uptest==C_PING)
			np=1;
	}
	if (np)
		init_ping_socket();
	init_rng();
#if TARGET==TARGET_LINUX
	if (!final_init())
		exit(1);
#endif
	signal(SIGPIPE, SIG_IGN);
	umask(0077); /* for security reasons */
	if (daemon_p) {
		/* become a daemon */
		i=fork();
		if (i==-1) {
			log_error("Could not become a daemon: fork failed: %s\n",strerror(errno));
			exit(1);
		}
		if (i!=0)
			exit(0); /* exit parent */
		/* dissociate from controlling terminal */
		if (setsid()==-1) {
			log_error("Could not become a daemon: setsid failed: %s",strerror(errno));
			_exit(1);
		}
		i=fork();
		if (i==-1) {
			log_error("Could not become a daemon: fork failed: %s",strerror(errno));
			_exit(1);
		}
		if (i!=0)
			_exit(0); /* exit parent, so we are no session group leader */
		signal(SIGPIPE, SIG_IGN);
		chdir("/");
		if (pidfile[0]) {
			fprintf(pf,"%i\n",getpid());
			fclose(pf);
		}
		if ((i=open("/dev/null",O_RDONLY))==-1) {
			log_error("Could not become a daemon: open for /dev/null failed: %s",strerror(errno));
			_exit(1);
		}
		dup2(i,0);
		close(i);
		if ((i=open("/dev/null",O_WRONLY))==-1) {
			log_error("Could not become a daemon: open for /dev/null failed: %s",strerror(errno));
			_exit(1);
		}
		dup2(i,1);
		dup2(i,2);
		close(i);
		openlog("pdnsd",LOG_PID,LOG_DAEMON);
		syslog(LOG_INFO,"pdnsd-%s starting.",VERSION);
		closelog();
#if DEBUG>0
		if (debug_p) {
			strncpy(dbgdir,global.cache_dir,1024);
			strncat(dbgdir,"/pdnsd.debug",1023-strlen(dbgdir));
			dbgdir[1023]='\0';
			if (!(dbg=fopen(dbgdir,"w")))
				debug_p=0;
		}
#endif
	} else {
#if DEBUG>0
		dbg=stdout;
#endif
		printf("pdnsd-%s starting.\n",VERSION);
		DEBUG_MSG1("Debug messages activated\n");
	}
#if TARGET!=TARGET_LINUX
	if (!final_init())
		_exit(1);
#endif
#ifdef ENABLE_IPV4
	if (run_ipv4)
		DEBUG_MSG1("Using IPv4.\n");
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6)
		DEBUG_MSG1("Using IPv6.\n");
#endif
	init_log();

	/* Before this point, cache accesses are not locked because we are single-threaded. */
	init_cache_lock();

	read_disk_cache();

	sigemptyset(&sigs_msk);
	sigaddset(&sigs_msk,SIGILL);
	sigaddset(&sigs_msk,SIGABRT);
	sigaddset(&sigs_msk,SIGFPE);
	sigaddset(&sigs_msk,SIGSEGV);
	sigaddset(&sigs_msk,SIGTERM);
	if (!daemon_p) {
		sigaddset(&sigs_msk,SIGINT);
		sigaddset(&sigs_msk,SIGQUIT);
	}
#if TARGET==TARGET_LINUX
	pthread_sigmask(SIG_BLOCK,&sigs_msk,NULL);
#endif

	start_servstat_thread();

#if TARGET==TARGET_LINUX
	if (!global.strict_suid) {
		if (!run_as(global.run_as)) {
			log_error("Could not change user and group id to those of run_as user %s",global.run_as);
			_exit(1);
		}
	}
#endif

	if (stat_pipe)
		init_stat_fifo();

	start_dns_servers();

	DEBUG_MSG1("All threads started successfully.\n");

#if TARGET==TARGET_LINUX
	pthread_sigmask(SIG_BLOCK,&sigs_msk,NULL);
	waiting=1;
	sigwait(&sigs_msk,&sig);
#else
/*	signal(SIGILL,bsd_sighnd);
	signal(SIGABRT,bsd_sighnd);
	signal(SIGFPE,bsd_sighnd);
	signal(SIGSEGV,bsd_sighnd);
	signal(SIGTERM,bsd_sighnd);
	if (!daemon_p) {
		signal(SIGINT,bsd_sighnd);
		signal(SIGQUIT,bsd_sighnd);
	}
	while (!sigr) usleep_r(250000);
	sig=sigr;*/
	waiting=1;
	sigwait(&sigs_msk,&sig);
#endif
	DEBUG_MSG1("Signal caught, writing disk cache.\n");
	write_disk_cache();
	destroy_cache();
	log_warn("Caught signal %i. Exiting.",sig);
	if (sig==SIGSEGV || sig==SIGILL || sig==SIGBUS)
		crash_msg("This is a fatal signal probably triggered by a bug.");
#if DEBUG>0
	if (debug_p && daemon_p)
		fclose(dbg);
#endif
	if (ping_isocket!=-1)
		close(ping_isocket);
#ifdef ENABLE_IPV6
	if (ping6_isocket!=-1)
		close(ping6_isocket);
#endif
	if (stat_pipe)
		unlink(sock_path); /* Delete the socket */
	free_rng();
	_exit(0);
}
