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
/* #define _GNU_SOURCE */

#include <config.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
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
#include "cache.h"
#include "status.h"
#include "servers.h"
#include "dns_answer.h"
#include "dns_query.h"
#include "error.h"
#include "helpers.h"
#include "icmp.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: main.c,v 1.42 2001/05/30 21:04:15 tmm Exp $";
#endif

#ifdef DEBUG_YY
extern int yydebug;
#endif

int daemon_p=0;
int debug_p=0;
int verbosity=VERBOSITY;
pthread_t main_thread;
#if DEBUG>0
FILE *dbg_file;
#endif
#if defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
int run_ipv4=DEFAULT_IPV4;
#endif
#ifdef ENABLE_IPV6
int run_ipv6=DEFAULT_IPV6;
#endif
volatile int tcp_socket=-1;
volatile int udp_socket=-1;
sigset_t sigs_msk;
char *pidfile=NULL;
int stat_pipe=0;
int notcp=0;
int sigr=0;


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

/* version and licensing information */
static const char info_message[] =
	
	"pdnsd - dns proxy daemon, version " VERSION "\n\n"
	"pdnsd is free software; you can redistribute it and/or modify\n"
	"it under the terms of the GNU General Public License as published by\n"
	"the Free Software Foundation; either version 2, or (at your option)\n"
	"any later version.\n\n"
	"pdnsd is distributed in the hope that it will be useful,\n"
	"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
	"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
	"GNU General Public License for more details.\n\n"
	"You should have received a copy of the GNU General Public License\n"
	"along with pdsnd; see the file COPYING.  If not, write to\n"
	"the Free Software Foundation, 59 Temple Place - Suite 330,\n"
	"Boston, MA 02111-1307, USA.\n";


/* the help page */
static const char help_message[] =

	"\n\nUsage: pdnsd [-h] [-V] [-s] [-d] [-g] [-vn] [-mxx] [-c file]"
#ifdef ENABLE_IPV4
	" [-4]"
#endif
#ifdef ENABLE_IPV6
	" [-6]"
#endif
	"\n\n"
	"Options:\n"
	"-h\t\t--or--\n"
	"--help\t\tprint this help page and exit.\n"
	"-V\t\t--or--\n"
	"--version\tprint version information and exit.\n"
	"--pdnsd-user\tprint the user pdnsd will run as and exit.\n"
	"-s\t\t--or--\n"
	"--status\tEnable status control socket the temp directory\n"
	"-d\t\t--or--\n"
	"--daemon\tStart pdnsd in daemon mode (as background process.)\n"
	"-g\t\t--or--\n"
	"--debug\t\tPrint some debug messages on the console or to the\n"
	"\t\tfile pdnsd.debug in your cache directory (in daemon mode).\n"
	"-t\t\t--or--\n"
	"--tcp\t\tEnables the TCP server thread. pdnsd will then serve\n"
	"\t\tTCP and UDP queries.\n"
	"-p\t\tWrites the pid the server runs as to a specified filename.\n"
	"\t\tWorks only in daemon mode.\n"
	"-vn\t\tsets the verbosity of pdnsd. n is a numeric argument from 0\n"
	"\t\t(normal operation) to 3 (many messages for debugging).\n"
	"\t\tUse like -v2\n"
	"-mxx\t\tsets the query method pdnsd uses. Possible values for xx are:\n"
	"\t\tuo (UDP only), to (TCP only), and tu (TCP or, if the server\n"
	"\t\tdoes not support this, UDP). Use like -muo. Preset: "
#if M_PRESET==UDP_ONLY
	"-muo"
#elif M_PRESET==TCP_ONLY
	"-mto"
#else
	"mtu"
#endif
	"\n"
	"-c\t\t--or--\n"
	"--config-file\tspecifies the file the configuration is read from.\n"
	"\t\tDefault is " CONFDIR "/pdnsd.conf\n"
#ifdef ENABLE_IPV4
	"-4\t\tenables IPv4 support. IPv6 support is automatically\n"
	"\t\tdisabled (should it be available). "
#  if DEFAULT_IPV4
	"On"
#  else
	"Off"
#  endif
#endif
	" by default.\n"
#ifdef ENABLE_IPV6
	"-6\t\tenables IPv6 support. IPv4 support is automatically\n"
	"\t\tdisabled (should it be available). "
#  if DEFAULT_IPV6
	"On"
#  else
	"Off"
#  endif
	" by default.\n"
#endif
	"\n\n\"no\" can be prepended to the --status, --daemon, --debug and --tcp\n"
	"options (e.g. --notcp) to reverse their effect.\n";


/*
 * Argument parsing, init, server startup
 */
int main(int argc,char *argv[])
{
	int i,sig,pfd=-1;  /* Initialized to inhibit compiler warning */
	char *conf_file=NULL;

	main_thread=pthread_self();
	
#ifdef DEBUG_YY
	yydebug=1;
#endif

	/* We parse the command line two times, because the command-line options shall override the ones
	 * given in the config file */
	for (i=1;i<argc;i++) {
		if (strcmp(argv[i],"-h")==0 || strcmp(argv[i],"--help")==0) {
			fputs(info_message,stdout);
			fputs(help_message,stdout);
			exit(1);
		} else if (strcmp(argv[i],"-V")==0 || strcmp(argv[i],"--version")==0) {
			fputs(info_message,stdout);
			exit(1);
		} else if (strcmp(argv[i],"-c")==0 || strcmp(argv[i],"--config-file")==0) {
			if (++i<argc) {
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
			if (++i<argc) {
				if(pidfile) free(pidfile);
				pidfile=strdup(argv[i]);
				if(!pidfile) {
				  fprintf(stderr,"Error: out of memory.\n");
				  exit(1);
				}
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
#if defined(NO_UDP_QUERIES) || defined(NO_TCP_QUERIES)
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
# ifdef ENABLE_IPV6
			run_ipv4=1;
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
				uid_t uid=getuid();
				struct passwd *pws=getpwuid(uid);
				if (pws)
					printf("%s\n",pws->pw_name);
				else
					printf("%i\n",uid);
			}
			exit(0);
		} else if (strcmp(argv[i],"-c")==0 || strcmp(argv[i],"--config-file")==0) {
			/* at this point, it is already checked that a file name arg follows. */
			i++;
		} else {
			fprintf(stderr,"Error: unknown option: %s\n",argv[i]);
			exit(1);
		}
	}
	
	if(!global.cache_dir)   global.cache_dir = CACHEDIR;
	if(!global.scheme_file) global.scheme_file = "/var/lib/pcmcia/scheme";

	if (!(global.run_as[0] && global.strict_suid)) {
		for (i=0; i<DA_NEL(servers); i++) {
			servparm_t *sp=&DA_INDEX(servers,i);
			if (sp->uptest==C_EXEC && sp->uptest_usr[0]=='\0') {
				uid_t uid=getuid();
				struct passwd *pws=getpwuid(uid);
		
				/* No explicit uptest user given. If we run_as and strict_suid, we assume that
				 * this is safe. If not - warn. */
				fprintf(stderr,"Warning: uptest command \"%s\" will implicitely be executed as user ", sp->uptest_cmd);
				if (pws)
					fprintf(stderr,"%s\n",pws->pw_name);
				else
					fprintf(stderr,"%i\n",uid);

			}
		}
	}

	if (daemon_p && pidfile) {
		if (unlink(pidfile)!=0 && errno!=ENOENT) {
			log_error("Error: could not unlink pid file %s: %s",pidfile, strerror(errno));
			exit(1);
		}
#ifdef O_NOFOLLOW		
		if ((pfd=open(pidfile,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0600))==-1) {
#else
		/* 
		 * No O_NOFOLLOW. Nevertheless, this not a hole, since the 
		 * directory for pidfiles should not be world writeable. 
		 * OS's that do not support O_NOFOLLOW are currently not 
		 * supported, this is just-in-case code.
		 */
		if ((pfd=open(pidfile,O_WRONLY|O_CREAT|O_EXCL, 0600))==-1) {
#endif
			log_error("Error: could not open pid file %s: %s",pidfile, strerror(errno));
			exit(1);
		}
	}
	for (i=0;i<DA_NEL(servers);i++) {
		if (DA_INDEX(servers,i).uptest==C_PING) {
			init_ping_socket();
			break;
		}
	}

	if (!init_rng())
		exit(1);
#if TARGET==TARGET_LINUX
	if (!final_init())
		exit(1);
#endif
	signal(SIGPIPE, SIG_IGN);
	umask(0077); /* for security reasons */
	if (daemon_p) {
		pid_t pid;
		int fd;

		/* become a daemon */
		pid=fork();
		if (pid==-1) {
			log_error("Could not become a daemon: fork #1 failed: %s",strerror(errno));
			exit(1);
		}
		if (pid!=0)
			exit(0); /* exit parent */
		/* dissociate from controlling terminal */
		if (setsid()==-1) {
			log_error("Could not become a daemon: setsid failed: %s",strerror(errno));
			_exit(1);
		}
		pid=fork();
		if (pid==-1) {
			log_error("Could not become a daemon: fork #2 failed: %s",strerror(errno));
			_exit(1);
		}
		if (pid!=0) {
			if (pidfile) {
				FILE *pf=fdopen(pfd,"w");
				if (pf) {
					fprintf(pf,"%i\n",pid);
					fclose(pf);
				}
				else {
					log_error("Error: could not open pid file %s: %s",pidfile, strerror(errno));
					_exit(1);
				}
			}
			_exit(0); /* exit parent, so we are no session group leader */
		}

		if (pidfile) close(pfd);
		chdir("/");
		if ((fd=open("/dev/null",O_RDONLY))==-1) {
			log_error("Could not become a daemon: open for /dev/null failed: %s",strerror(errno));
			_exit(1);
		}
		dup2(fd,0);
		close(fd);
		if ((fd=open("/dev/null",O_WRONLY))==-1) {
			log_error("Could not become a daemon: open for /dev/null failed: %s",strerror(errno));
			_exit(1);
		}
		dup2(fd,1);
		dup2(fd,2);
		close(fd);
		openlog("pdnsd",LOG_PID,LOG_DAEMON);
		syslog(LOG_INFO,"pdnsd-%s starting.",VERSION);
		closelog();
#if DEBUG>0
		if (debug_p) {
		  char dbgdir[strlen(global.cache_dir)+sizeof("/pdnsd.debug")];
		  stpcpy(stpcpy(dbgdir,global.cache_dir),"/pdnsd.debug");
		  if (!(dbg_file=fopen(dbgdir,"w")))
		    debug_p=0;
		}
#endif
	} else {
#if DEBUG>0
		dbg_file=stdout;
#endif
		printf("pdnsd-%s starting.\n",VERSION);
		DEBUG_MSGC("Debug messages activated\n");
	}
#if TARGET!=TARGET_LINUX
	if (!final_init())
		_exit(1);
#endif
#ifdef ENABLE_IPV4
	if (run_ipv4)
		DEBUG_MSGC("Using IPv4.\n");
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6)
		DEBUG_MSGC("Using IPv6.\n");
#endif
	init_log();

	/* Before this point, cache accesses are not locked because we are single-threaded. */
	init_cache_lock();

	read_disk_cache();

	/* This must be done before any other thread is started to avoid races. */
	if (stat_pipe)
		init_stat_sock();

	sigemptyset(&sigs_msk);
	sigaddset(&sigs_msk,SIGHUP);
	sigaddset(&sigs_msk,SIGINT);
#ifndef THREADLIB_NPTL
	sigaddset(&sigs_msk,SIGILL);
#endif
	sigaddset(&sigs_msk,SIGABRT);
	sigaddset(&sigs_msk,SIGFPE);
#ifndef THREADLIB_NPTL
	sigaddset(&sigs_msk,SIGSEGV);
#endif
	sigaddset(&sigs_msk,SIGTERM);
	/* if (!daemon_p) {
		sigaddset(&sigs_msk,SIGQUIT);
	} */
#if TARGET==TARGET_LINUX
	pthread_sigmask(SIG_BLOCK,&sigs_msk,NULL);
#endif

	/* Generate a key for storing our thread id's */
	if (pthread_key_create(&thrid_key, NULL) != 0) {
		log_error("pthread_key_create failed.");
		_exit(1);
	}

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
		start_stat_sock();

	start_dns_servers();

	DEBUG_MSGC("All threads started successfully.\n");

#if TARGET==TARGET_LINUX && !defined(THREADLIB_NPTL)
	pthread_sigmask(SIG_BLOCK,&sigs_msk,NULL);
#endif
	waiting=1;
	sigwait(&sigs_msk,&sig);
	DEBUG_MSGC("Signal %i caught.\n",sig);
	write_disk_cache();
	destroy_cache();
	log_warn("Caught signal %i. Exiting.",sig);
	if (sig==SIGSEGV || sig==SIGILL || sig==SIGBUS)
		crash_msg("This is a fatal signal probably triggered by a bug.");
	if (ping_isocket!=-1)
		close(ping_isocket);
#ifdef ENABLE_IPV6
	if (ping6_isocket!=-1)
		close(ping6_isocket);
#endif
	/* Close and delete the status socket */
	if(stat_pipe) close(stat_sock);
	if (sock_path && unlink(sock_path))
		log_warn("Failed to unlink %s: %s",sock_path, strerror(errno));

	free_rng();
#if DEBUG>0
	if (debug_p && daemon_p)
		fclose(dbg_file);
#endif
	_exit(0);
}
