/* pdnsd-ctl.c - Control pdnsd through a pipe
   Copyright (C) 2000 Thomas Moestl

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
#include "../dns.h"
#include "../rr_types.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: pdnsd-ctl.c,v 1.4 2000/11/18 14:56:33 thomas Exp $";
#endif

char sock_path[MAXPATH];
char buf[1024];

typedef struct {
	char *cmd;
	int  val;
} cmd_s;

#define CTL_AUX_LISTRRT 16

cmd_s top_cmds[7]={{"status",CTL_STATS},{"server",CTL_SERVER},{"record",CTL_RECORD},
		   {"source",CTL_SOURCE},{"add",CTL_ADD},{"neg",CTL_NEG}, {NULL,0}};
cmd_s server_cmds[4]= {{"up",CTL_S_UP},{"down",CTL_S_DOWN},{"retest",CTL_S_RETEST},{NULL,0}};
cmd_s record_cmds[4]= {{"delete",CTL_R_DELETE},{"invalidate",CTL_R_INVAL},{NULL,0}};
cmd_s onoff_cmds[3]= {{"off",0},{"on",1},{NULL,0}};
#ifdef ENABLE_IPV6
cmd_s rectype_cmds[5]= {{"a",T_A},{"aaaa",T_AAAA},{"ptr",T_PTR},{"cname",T_CNAME},{NULL,0}};
#else
cmd_s rectype_cmds[4]= {{"a",T_A},{"ptr",T_PTR},{"cname",T_CNAME},{NULL,0}};
#endif

void print_version(void)
{
	printf("pdnsd-ctl, version pdnsd-%s\n",VERSION);
}

void print_help(void)
{
	printf("Usage: pdnsd-ctl <command> [options]\n\n");

	printf("Commands and needed options are:\n");

	printf("help\t[no options]\n\tprint this help\n");
	printf("version\t[no options]\n\tprint version info\n");
	printf("status\t[no options]\n\tprint pdnsd's status\n");

	printf("server\tindex\t(up|down|retest)\n");
	printf("\tSet the status of the server with the given index to up or down, or\n");
	printf("\tforce a retest. The index is assigned in the order of definition in\n");
	printf("\tpdnsd.cache starting with 0. Use the status command to view the indexes.\n");
	printf("\tYou can specify all instead of an index to perform th action for all\n");
	printf("\tservers registered with pdnsd.\n");

	printf("record\tname\t(delete|invalidate)\n");
	printf("\tDelete or invalidate the record of the given domain if it is in the\n");
	printf("\tcache.\n");

	printf("source\tfn\towner\t[ttl]\t[(on|off)]\n");
	printf("\tLoad a hosts-style file. Works like using the pdnsd source option.\n");
	printf("\tOwner and ttl are used as in the source section. ttl has a default\n");
	printf("\tof 900 (it does not need to be specified). The last option corresponds\n");
	printf("\tto the serve_aliases option, and is off by default. fn is the filename\n");

	printf("add\ta\taddr\tname\t[ttl]\n");
	printf("add\taaaa\taddr\tname\t[ttl]\n");
	printf("add\tptr\thost\tname\t[ttl]\n");
	printf("add\tcname\thost\tname\t[ttl]\n");
	printf("\tAdd a record of the given type to the pdnsd cache, replacing existing\n");
	printf("\trecords for the same name and type. The 2nd argument corresponds\n");
 	printf("\tto the argument of the option in the rr section that is named like\n");
 	printf("\tthe first option. The ttl is optional, the default is 900 seconds.\n");
 	printf("\tIf you want no other record than the newly added in the cache, do\n");
 	printf("\tpdnsdctl record <name> delete\n");
 	printf("\tbefore adding records.\n");

	printf("neg\tname\t[type]\t[ttl]\n");
 	printf("\tAdd a negative cached record to pdnsd's cache, replacing existing\n");
	printf("\trecords for the same name and type. If no type is given, the whole\n");
	printf("\tdomain is cached negative. For negative cached records, errors are\n");
	printf("\timmediately returned on a query, without querying other servers first.\n");
	printf("\tThe ttl is optional, the default is 900 seconds.\n");

	printf("list-rrtypes\n");
	printf("\tList available rr types for the neg command. Note that those are only\n");
	printf("\tused for the neg command, not for add!\n");
}

int open_sock(char *pipe)
{
	struct sockaddr_un a;
	int s;

	printf("Opening socket %s.\n",pipe);
	if ((s=socket(PF_UNIX,SOCK_STREAM,0))==-1) {
		printf("Error: could not open socket: %s\n",strerror(errno));
		exit(2);
	}

	a.sun_family=AF_UNIX;
	strncpy(a.sun_path,pipe,100);

	if (connect(s,(struct sockaddr *)&a,sizeof(a))==-1) {
		printf("Error: could not open socket: %s\n",strerror(errno));
		close(s);
		exit(2);
	}
	return s;
}

void send_long(long cmd, int f)
{
	long nc=htonl(cmd);

	if (write(f,&nc,sizeof(nc))<0) {
		printf("Error: could not write long: %s\n",strerror(errno));
		exit(2);
	}
}

void send_short(long cmd, int f)
{
	short nc=htons(cmd);

	if (write(f,&nc,sizeof(nc))<0) {
		printf("Error: could not write short: %s\n",strerror(errno));
		exit(2);
	}
}

void send_string(int fd, char *s)
{
	write(fd,s,strlen(s)+1); /* include the terminating \0 */
}

int match_cmd(char *cmd, cmd_s cmds[])
{
	int i=0;
	while (cmds[i].cmd) {
		if (strcmp(cmd,cmds[i].cmd)==0)
			return cmds[i].val;
		i++;
	}
	printf("Command/option not recognized: %s\n",cmd);
	printf("Try 'pdnsd-ctl help' for available commands.\n");
	exit(2);
}

int main(int argc, char *argv[])
{
	int pf,cmd,acnt;
	int i,rv=0;
	short cmd2,tp;
	char errmsg[256]="";
	long ttl;
	struct in_addr ina4;
#ifdef ENABLE_IPV6
	struct in6_addr ina6;
#endif

	strncpy(sock_path, TEMPDIR, MAXPATH);
	sock_path[MAXPATH-1]='\0';
	strncat(sock_path, "/.pdnsd.status", MAXPATH-1-strlen(sock_path));
	sock_path[MAXPATH-1]='\0';

	if (argc<2) {
		print_help();
		exit(2);
	}
	if (strcmp(argv[1],"help")==0) {
		print_version();
		print_help();
		exit(0);
	} else if (strcmp(argv[1],"version")==0) {
		print_version();
		exit(0);
	} else if (strcmp(argv[1],"list-rrtypes")==0) {
		printf("Available RR types for the neg command:\n");
		for (i=0;i<T_MAX;i++) {
			printf("%s\n",rr_info[i]);
		}
		exit(0);
	} else {
		cmd=match_cmd(argv[1],top_cmds);
		pf=open_sock(sock_path);
		send_short(cmd,pf);
		switch (cmd) {
		case CTL_STATS:
			if (argc!=2) {
				print_help();
				exit(2);
			}
			memset(buf,0,sizeof(buf));
			while (read(pf,buf,1024)>0) {
				fwrite(buf,strlen(buf),sizeof(char),stdout);
				memset(buf,0,sizeof(buf));
			}
			break;
		case CTL_SERVER:
			if (argc!=4) {
				print_help();
				exit(2);
			}
			if (strcmp(argv[2],"all")==0)
				cmd2=-1;
			else {
				if (sscanf(argv[2],"%hi",&cmd2)!=1) {
					printf("Bad argument for server\n");
					exit(2);
				}
			}
			send_short(cmd2,pf);
			send_short(match_cmd(argv[3],server_cmds),pf);
			read(pf,&cmd2,sizeof(cmd2));
			rv=ntohs(cmd2);
			if (rv)
				read(pf,errmsg,255);
			break;
		case CTL_RECORD:	
			if (argc!=4) {
				print_help();
				exit(2);
			}
			send_short(match_cmd(argv[3],record_cmds),pf);
			send_string(pf,argv[2]);
			read(pf,&cmd2,sizeof(cmd2));
			rv=ntohs(cmd2);
			if (rv)
				read(pf,errmsg,255);
			break;
		case CTL_SOURCE:
			if (argc<4 || argc>6) {
				print_help();
				exit(2);
			}
			send_string(pf,argv[2]);
			send_string(pf,argv[3]);
			ttl=900;
			acnt=4;
			if (argc==6 || (argc==5 && isdigit(argv[4][0]))) {
				if (sscanf(argv[4],"%li",&ttl)!=1) {
					printf("Bad argument for source\n");
					exit(2);
				}
				acnt++;
			}
			send_long(ttl,pf);
			cmd2=0;
			if (argc==6 || (argc==5 && !isdigit(argv[4][0]))) {
				cmd2=match_cmd(argv[acnt],onoff_cmds);
			}
			send_short(cmd2,pf);
			read(pf,&cmd2,sizeof(cmd2));
			rv=ntohs(cmd2);
			if (rv)
				read(pf,errmsg,255);
			break;
		case CTL_ADD:
			if (argc<5 || argc>6) {
				print_help();
				exit(2);
			}
			cmd=match_cmd(argv[2],rectype_cmds);
			send_short(cmd,pf);
			send_string(pf,argv[4]);
			ttl=900;
			if (argc==6) {
				if (sscanf(argv[5],"%li",&ttl)!=1) {
					printf("Bad argument for add\n");
					exit(2);
				}
			}
			send_long(ttl,pf);

			switch (cmd) {
			case T_A:
				if (!inet_aton(argv[3],&ina4)) {
					printf("Bad IP for add a option\n");
					exit(2);
				}
				write(pf,&ina4,sizeof(ina4));
				break;
#ifdef ENABLE_IPV6
			case T_AAAA:
				if (!inet_pton(AF_INET6,(char *)argv[3],&ina6)) {
					printf("Bad IP (v6) for add aaaa option\n");
					exit(2);
				}
				write(pf,&ina6,sizeof(ina6));
				break;
#endif
			case T_PTR:
			case T_CNAME:
				send_string(pf,argv[3]);
				break;
			}

			read(pf,&cmd2,sizeof(cmd2));
			rv=ntohs(cmd2);
			if (rv)
				read(pf,errmsg,255);
			break;
		case CTL_NEG:
			if (argc<3 || argc>5) {
				print_help();
				exit(2);
			}
			send_string(pf,argv[2]);
			tp=255;
			ttl=900;
			if (argc==4) {
				if (isdigit(argv[3][0])) {
					if (sscanf(argv[3],"%li",&ttl)!=1) {
						printf("Bad argument (ttl) for neg\n");
						exit(2);
					}
				} else {
					if ((tp=rr_tp_byname(argv[3]))==-1) {
						printf("Bad argument (type) for neg\n");
						exit(2);
					}
				}
			} else if (argc==5) {
				if ((tp=rr_tp_byname(argv[3]))==-1) {
					printf("Bad argument (type) for neg\n");
					exit(2);
				}
				if (sscanf(argv[4],"%li",&ttl)!=1) {
					printf("Bad argument (ttl) for neg\n");
					exit(2);
				}
			}
			send_short(tp,pf);
			send_long(ttl,pf);
		}
		close(pf);
	}
	if (rv)
		printf("Failed: %s\n",errmsg);
	else
		printf("Succeeded\n");
	return rv;
}



