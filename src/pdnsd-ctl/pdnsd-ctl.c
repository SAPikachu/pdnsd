/* pdnsd-ctl.c - Control pdnsd through a pipe
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <ctype.h>
#include "../status.h"
#include "../conff.h"
#include "../list.h"
#include "../dns.h"
#include "../rr_types.h"
#include "../cache.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: pdnsd-ctl.c,v 1.19 2001/12/30 15:29:43 tmm Exp $";
#endif

char cache_dir[MAXPATH]=CACHEDIR;
char buf[1024];

typedef struct {
	char *cmd;
	int  val;
} cmd_s;

#define CTL_AUX_LISTRRT 16

cmd_s top_cmds[]={{"status",CTL_STATS},{"server",CTL_SERVER},{"record",CTL_RECORD},
		   {"source",CTL_SOURCE},{"add",CTL_ADD},{"neg",CTL_NEG}, {NULL,0}};
cmd_s server_cmds[]= {{"up",CTL_S_UP},{"down",CTL_S_DOWN},{"retest",CTL_S_RETEST},{NULL,0}};
cmd_s record_cmds[]= {{"delete",CTL_R_DELETE},{"invalidate",CTL_R_INVAL},{NULL,0}};
cmd_s onoff_cmds[]= {{"off",0},{"on",1},{NULL,0}};
#ifdef ENABLE_IPV6
cmd_s rectype_cmds[]= {{"a",T_A},{"aaaa",T_AAAA},{"ptr",T_PTR},{"cname",T_CNAME},{"mx",T_MX},{NULL,0}};
#else
cmd_s rectype_cmds[]= {{"a",T_A},{"ptr",T_PTR},{"cname",T_CNAME},{"mx",T_MX},{NULL,0}};
#endif

void print_version(void)
{
	printf("pdnsd-ctl, version pdnsd-%s\n",VERSION);
}

void print_help(void)
{
	fprintf(stderr,"Usage: pdnsd-ctl [-c cachedir] <command> [options]\n\n");

	fprintf(stderr,"Command line options\n");

	fprintf(stderr,"-c\tcachedir\n\tset the cache directory to cachedir (must match pdnsd setting)\n");

	fprintf(stderr,"Commands and needed options are:\n");

	fprintf(stderr,"help\t[no options]\n\tprint this help\n");
	fprintf(stderr,"version\t[no options]\n\tprint version info\n");
	fprintf(stderr,"status\t[no options]\n\tprint pdnsd's status\n");

	fprintf(stderr,"server\tindex\t(up|down|retest)\n");
	fprintf(stderr,"\tSet the status of the server with the given index to up or down, or\n");
	fprintf(stderr,"\tforce a retest. The index is assigned in the order of definition in\n");
	fprintf(stderr,"\tpdnsd.cache starting with 0. Use the status command to see the indexes.\n");
	fprintf(stderr,"\tYou can specify the label of a server (matches the label option)\n");
	fprintf(stderr,"\tinstead of an index to make this easier.\n");
	
	fprintf(stderr,"\tYou can specify all instead of an index to perform the action for all\n");
	fprintf(stderr,"\tservers registered with pdnsd.\n");

	fprintf(stderr,"record\tname\t(delete|invalidate)\n");
	fprintf(stderr,"\tDelete or invalidate the record of the given domain if it is in the\n");
	fprintf(stderr,"\tcache.\n");

	fprintf(stderr,"source\tfn\towner\t[ttl]\t[(on|off)]\t[auth]\n");
	fprintf(stderr,"\tLoad a hosts-style file. Works like using the pdnsd source option.\n");
	fprintf(stderr,"\tOwner and ttl are used as in the source section. ttl has a default\n");
	fprintf(stderr,"\tof 900 (it does not need to be specified). The last option corresponds\n");
	fprintf(stderr,"\tto the serve_aliases option, and is off by default. fn is the filename\n");

	fprintf(stderr,"add\ta\taddr\tname\t[ttl]\t[noauth]\n");
	fprintf(stderr,"add\taaaa\taddr\tname\t[ttl]\t[noauth]\n");
	fprintf(stderr,"add\tptr\thost\tname\t[ttl]\t[noauth]\n");
	fprintf(stderr,"add\tcname\thost\tname\t[ttl]\t[noauth]\n");
	fprintf(stderr,"add\tmx\thost\tname\tpref\t[ttl]\t[noauth]\n");
	fprintf(stderr,"\tAdd a record of the given type to the pdnsd cache, replacing existing\n");
	fprintf(stderr,"\trecords for the same name and type. The 2nd argument corresponds\n");
 	fprintf(stderr,"\tto the argument of the option in the rr section that is named like\n");
 	fprintf(stderr,"\tthe first option. The ttl is optional, the default is 900 seconds.\n");
 	fprintf(stderr,"\tIf you want no other record than the newly added in the cache, do\n");
 	fprintf(stderr,"\tpdnsdctl record <name> delete\n");
 	fprintf(stderr,"\tbefore adding records.\n");

	fprintf(stderr,"neg\tname\t[type]\t[ttl]\n");
 	fprintf(stderr,"\tAdd a negative cached record to pdnsd's cache, replacing existing\n");
	fprintf(stderr,"\trecords for the same name and type. If no type is given, the whole\n");
	fprintf(stderr,"\tdomain is cached negative. For negative cached records, errors are\n");
	fprintf(stderr,"\timmediately returned on a query, without querying other servers first.\n");
	fprintf(stderr,"\tThe ttl is optional, the default is 900 seconds.\n");

	fprintf(stderr,"list-rrtypes\n");
	fprintf(stderr,"\tList available rr types for the neg command. Note that those are only\n");
	fprintf(stderr,"\tused for the neg command, not for add!\n");
}

int open_sock(char *cache_dir)
{
	struct sockaddr_un a;
	int s;

	if ((s=socket(PF_UNIX,SOCK_STREAM,0))==-1) {
		perror("Error: could not open socket");
		exit(2);
	}

	a.sun_family=AF_UNIX;
	if (snprintf(a.sun_path, sizeof(a.sun_path), "%s/pdnsd.status", cache_dir)>=sizeof(a.sun_path)) {
		fprintf(stderr, "Cache dir string too long\n");
		exit(2);
	}
	printf("Opening socket %s.\n",a.sun_path);

	if (connect(s,(struct sockaddr *)&a,sizeof(a))==-1) {
		perror("Error: could not open socket");
		close(s);
		exit(2);
	}
	return s;
}

void send_long(long cmd, int f)
{
	long nc=htonl(cmd);

	if (write(f,&nc,sizeof(nc))<sizeof(nc)) {
		perror("Error: could not write long");
		exit(2);
	}
}

void send_short(long cmd, int f)
{
	short nc=htons(cmd);

	if (write(f,&nc,sizeof(nc))<sizeof(nc)) {
		perror("Error: could not write short");
		exit(2);
	}
}

void send_string(int fd, char *s)
{
	/* include the terminating \0 */
	if (write(fd,s,strlen(s)+1)<strlen(s)+1) {
		perror("Error: could not write short");
		exit(2);
	}
}

int match_cmd(char *cmd, cmd_s cmds[])
{
	int i=0;
	while (cmds[i].cmd) {
		if (strcmp(cmd,cmds[i].cmd)==0)
			return cmds[i].val;
		i++;
	}
	fprintf(stderr,"Command/option not recognized: %s\n",cmd);
	fprintf(stderr,"Try 'pdnsd-ctl help' for available commands.\n");
	exit(2);
}

int main(int argc, char *argv[])
{
	int pf,cmd,acnt;
	int i,rv=0;
	short cmd2,tp,flags;
	char errmsg[256]="";
	long ttl;
	struct in_addr ina4;
#ifdef ENABLE_IPV6
	struct in6_addr ina6;
#endif
	while ((i=getopt(argc, argv, "c:")) != -1) {
		switch(i) {
		case 'c':
			if (strlen(optarg)>=sizeof(cache_dir)) {
				fprintf(stderr,"-c: directory name too long\n");
				exit(2);
			}
			strncpy(cache_dir, optarg, sizeof(cache_dir));
			cache_dir[sizeof(cache_dir)-1]='\0';
			break;
		case '?':
			fprintf(stderr,"Try 'pdnsd-ctl help' for available commands and options.\n");
			exit(2);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc<1) {
		print_help();
		exit(2);
	}
	if (strcmp(argv[0],"help")==0) {
		print_version();
		print_help();
		exit(0);
	} else if (strcmp(argv[0],"version")==0) {
		print_version();
		exit(0);
	} else if (strcmp(argv[0],"list-rrtypes")==0) {
		printf("Available RR types for the neg command:\n");
		for (i=0;i<T_MAX;i++)
			printf("%s\n",rr_info[i].name);
		exit(0);
	} else {
		cmd=match_cmd(argv[0],top_cmds);
		pf=open_sock(cache_dir);
		send_short(cmd,pf);
		switch (cmd) {
		case CTL_STATS:
			if (argc!=1) {
				print_help();
				exit(2);
			}
			memset(buf,0,sizeof(buf));
			while (read(pf,buf,sizeof(buf) - 1)>0) {
				fwrite(buf,strlen(buf),sizeof(char),stdout);
				memset(buf,0,sizeof(buf));
			}
			break;
		case CTL_SERVER:
			if (argc!=3) {
				print_help();
				exit(2);
			}
			send_string(pf,argv[1]);
			send_short(match_cmd(argv[2],server_cmds),pf);
			read(pf,&cmd2,sizeof(cmd2));
			rv=ntohs(cmd2);
			if (rv)
				read(pf,errmsg,255);
			break;
		case CTL_RECORD:	
			if (argc!=3) {
				print_help();
				exit(2);
			}
			send_short(match_cmd(argv[2],record_cmds),pf);
			send_string(pf,argv[1]);
			read(pf,&cmd2,sizeof(cmd2));
			rv=ntohs(cmd2);
			if (rv)
				read(pf,errmsg,255);
			break;
		case CTL_SOURCE:
			if (argc<3 || argc>6) {
				print_help();
				exit(2);
			}
			send_string(pf,argv[1]);
			send_string(pf,argv[2]);
			ttl=900;
			acnt=3;
			flags=DF_LOCAL;
			if (argc==6 || (argc>=4 && isdigit(argv[3][0]))) {
				if (sscanf(argv[3],"%li",&ttl)!=1) {
					fprintf(stderr,"Bad argument for source\n");
					exit(2);
				}
				acnt++;
			}
			send_long(ttl,pf);
			cmd2=0;
			if (acnt<argc && (strcmp(argv[acnt], "noauth") || argc==6)) {
				cmd2=match_cmd(argv[acnt],onoff_cmds);
				acnt++;
			}
			if (acnt<argc) {
				if (!strcmp(argv[acnt], "noauth"))
					flags=0;
				else {
					fprintf(stderr,"Bad argument for source\n");
					exit(2);
				}
			}
			send_short(cmd2,pf);
			send_short(flags,pf);
			read(pf,&cmd2,sizeof(cmd2));
			rv=ntohs(cmd2);
			if (rv)
				read(pf,errmsg,255);
			break;
		case CTL_ADD:
			if (argc<4 || argc>7) {
				print_help();
				exit(2);
			}
			cmd=match_cmd(argv[1],rectype_cmds);
			send_short(cmd,pf);
			send_string(pf,argv[3]);
			ttl=900;
			flags=DF_LOCAL;
			tp = cmd==T_MX?5:4;
			if (tp<argc && strcmp(argv[tp],"noauth")) {
				if (sscanf(argv[tp],"%li",&ttl)!=1) {
					fprintf(stderr,"Bad argument for add\n");
					exit(2);
				}
				tp++;
			}
			if (tp<argc && !strcmp(argv[tp],"noauth")) {
				flags=0;
				tp++;
			}
			if (tp<argc) {
				fprintf(stderr,"Bad argument for add\n");
				exit(2);
			}
			send_long(ttl,pf);
			send_short(flags,pf);

			switch (cmd) {
			case T_A:
				if (!inet_aton(argv[2],&ina4)) {
					fprintf(stderr,"Bad IP for add a option\n");
					exit(2);
				}
				write(pf,&ina4,sizeof(ina4));
				break;
#ifdef ENABLE_IPV6
			case T_AAAA:
				if (!inet_pton(AF_INET6,(char *)argv[2],&ina6)) {
					fprintf(stderr,"Bad IP (v6) for add aaaa option\n");
					exit(2);
				}
				write(pf,&ina6,sizeof(ina6));
				break;
#endif
			case T_PTR:
			case T_CNAME:
				send_string(pf,argv[2]);
				break;
			case T_MX:
				if (sscanf(argv[4], "%hd", &tp)!=1) {
					fprintf(stderr,"Bad number.\n");
					exit(2);
				}
				send_short(tp,pf);
				send_string(pf,argv[2]);
				break;
			}

			read(pf,&cmd2,sizeof(cmd2));
			rv=ntohs(cmd2);
			if (rv)
				read(pf,errmsg,255);
			break;
		case CTL_NEG:
			if (argc<2 || argc>4) {
				print_help();
				exit(2);
			}
			send_string(pf,argv[1]);
			tp=255;
			ttl=900;
			if (argc==3) {
				if (isdigit(argv[2][0])) {
					if (sscanf(argv[2],"%li",&ttl)!=1) {
						fprintf(stderr,"Bad argument (ttl) for neg\n");
						exit(2);
					}
				} else {
					if ((tp=rr_tp_byname(argv[2]))==-1) {
						fprintf(stderr,"Bad argument (type) for neg\n");
						exit(2);
					}
				}
			} else if (argc==4) {
				if ((tp=rr_tp_byname(argv[2]))==-1) {
					fprintf(stderr,"Bad argument (type) for neg\n");
					exit(2);
				}
				if (sscanf(argv[3],"%li",&ttl)!=1) {
					fprintf(stderr,"Bad argument (ttl) for neg\n");
					exit(2);
				}
			}
			send_short(tp,pf);
			send_long(ttl,pf);
		}
		close(pf);
	}
	if (rv) {
		errmsg[255]='\0';
		fprintf(stderr,"Failed: %s\n",errmsg);
	}
	else
		printf("Succeeded\n");
	return rv;
}



