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
#include <stddef.h>	/* for offsetof */
#include "../helpers.h"
#include "../status.h"
#include "../conff.h"
#include "../list.h"
#include "../dns.h"
#include "../rr_types.h"
#include "../cache.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: pdnsd-ctl.c,v 1.19 2001/12/30 15:29:43 tmm Exp $";
#endif

char *cache_dir=NULL;
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

static const char version_message[] =
	"pdnsd-ctl, version pdnsd-" VERSION "\n";

static const char help_message[] =

	"Usage: pdnsd-ctl [-c cachedir] <command> [options]\n\n"

	"Command line options\n"

	"-c\tcachedir\n\tset the cache directory to cachedir (must match pdnsd setting)\n"

	"Commands and needed options are:\n"

	"help\t[no options]\n\tprint this help\n"
	"version\t[no options]\n\tprint version info\n"
	"status\t[no options]\n\tprint pdnsd's status\n"

	"server\tindex\t(up|down|retest)\n"
	"\tSet the status of the server with the given index to up or down, or\n"
	"\tforce a retest. The index is assigned in the order of definition in\n"
	"\tpdnsd.cache starting with 0. Use the status command to see the indexes.\n"
	"\tYou can specify the label of a server (matches the label option)\n"
	"\tinstead of an index to make this easier.\n"
	
	"\tYou can specify all instead of an index to perform the action for all\n"
	"\tservers registered with pdnsd.\n"

	"record\tname\t(delete|invalidate)\n"
	"\tDelete or invalidate the record of the given domain if it is in the\n"
	"\tcache.\n"

	"source\tfn\towner\t[ttl]\t[(on|off)]\t[auth]\n"
	"\tLoad a hosts-style file. Works like using the pdnsd source option.\n"
	"\tOwner and ttl are used as in the source section. ttl has a default\n"
	"\tof 900 (it does not need to be specified). The last option corresponds\n"
	"\tto the serve_aliases option, and is off by default. fn is the filename\n"

	"add\ta\taddr\tname\t[ttl]\t[noauth]\n"
	"add\taaaa\taddr\tname\t[ttl]\t[noauth]\n"
	"add\tptr\thost\tname\t[ttl]\t[noauth]\n"
	"add\tcname\thost\tname\t[ttl]\t[noauth]\n"
	"add\tmx\thost\tname\tpref\t[ttl]\t[noauth]\n"
	"\tAdd a record of the given type to the pdnsd cache, replacing existing\n"
	"\trecords for the same name and type. The 2nd argument corresponds\n"
 	"\tto the argument of the option in the rr section that is named like\n"
 	"\tthe first option. The ttl is optional, the default is 900 seconds.\n"
 	"\tIf you want no other record than the newly added in the cache, do\n"
 	"\tpdnsdctl record <name> delete\n"
 	"\tbefore adding records.\n"

	"neg\tname\t[type]\t[ttl]\n"
 	"\tAdd a negative cached record to pdnsd's cache, replacing existing\n"
	"\trecords for the same name and type. If no type is given, the whole\n"
	"\tdomain is cached negative. For negative cached records, errors are\n"
	"\timmediately returned on a query, without querying other servers first.\n"
	"\tThe ttl is optional, the default is 900 seconds.\n"

	"list-rrtypes\n"
	"\tList available rr types for the neg command. Note that those are only\n"
	"\tused for the neg command, not for add!\n";


static int open_sock(char *cache_dir)
{
	struct sockaddr_un *sa;
	int sa_size;
	int sock;

	if ((sock=socket(PF_UNIX,SOCK_STREAM,0))==-1) {
		perror("Error: could not open socket");
		exit(2);
	}

	sa_size = (offsetof(struct sockaddr_un, sun_path) + sizeof("/pdnsd.status") + strlen(cache_dir));
	sa=(struct sockaddr_un *)alloca(sa_size);
	sa->sun_family=AF_UNIX;
	stpcpy(stpcpy(sa->sun_path,cache_dir),"/pdnsd.status");
	printf("Opening socket %s\n",sa->sun_path);

	if (connect(sock,(struct sockaddr *)sa,sa_size)==-1) {
		perror("Error: could not open socket");
		close(sock);
		exit(2);
	}
	return sock;
}

static void send_long(int fd,long cmd)
{
	long nc=htonl(cmd);

	if (write(fd,&nc,sizeof(nc))!=sizeof(nc)) {
		perror("Error: could not write long");
		exit(2);
	}
}

static void send_short(int fd,short cmd)
{
	short nc=htons(cmd);

	if (write(fd,&nc,sizeof(nc))!=sizeof(nc)) {
		perror("Error: could not write short");
		exit(2);
	}
}

static void send_string(int fd, char *s)
{
	unsigned short len=strlen(s);
	send_short(fd,len);
	if (write_all(fd,s,len)!=len) {
		perror("Error: could not write string");
		exit(2);
	}
}

static short read_short(int fd)
{
	short nc;

	if (read(fd,&nc,sizeof(nc))!=sizeof(nc)) {
		perror("Error: could not read short");
		exit(2);
	}
	return ntohs(nc);
}

static int match_cmd(char *cmd, cmd_s cmds[])
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
	int pf,acnt;
	int i;
	short cmd,cmd2,tp,flags,rv=0;
	char *errmsg=NULL;
	char msgbuf[256];
	long ttl;
	struct in_addr ina4;
#ifdef ENABLE_IPV6
	struct in6_addr ina6;
#endif
	while ((i=getopt(argc, argv, "c:")) != -1) {
		switch(i) {
		case 'c':
		  	if(cache_dir) free(cache_dir);
			cache_dir= strdup(optarg);
			if (!cache_dir) {
				fprintf(stderr,"Fatal error: out of memory.\n");
				exit(2);
			}
			break;
		case '?':
			fprintf(stderr,"Try 'pdnsd-ctl help' for available commands and options.\n");
			exit(2);
		}
	}

	if(!cache_dir) cache_dir= CACHEDIR;
	  
	argc -= optind;
	argv += optind;

	if (argc<1) {
		fputs(help_message,stderr);
		exit(2);
	}
	if (strcmp(argv[0],"help")==0) {
		fputs(version_message,stdout);
		fputs(help_message,stdout);
		exit(0);
	} else if (strcmp(argv[0],"version")==0) {
		fputs(version_message,stdout);
		exit(0);
	} else if (strcmp(argv[0],"list-rrtypes")==0) {
		printf("Available RR types for the neg command:\n");
		for (i=0;i<T_MAX;i++)
			printf("%s\n",rr_info[i].name);
		exit(0);
	} else {
		cmd=match_cmd(argv[0],top_cmds);
		pf=open_sock(cache_dir);
		send_short(pf,cmd);
		switch (cmd) {
		case CTL_STATS:
			if (argc!=1) {
				fputs(help_message,stderr);
				exit(2);
			}
			{
			  int n;
			  while ((n=read(pf,buf,sizeof(buf)))>0)
			    fwrite(buf,1,n,stdout);
			  if(n<0) {
			    perror("Error while reading from socket");
			    exit(2);
			  }
			}
			break;
		case CTL_SERVER:
			if (argc<3 || argc>4) {
				fputs(help_message,stderr);
				exit(2);
			}
			send_string(pf,argv[1]);
			send_short(pf,match_cmd(argv[2],server_cmds));
			if(argc<4)
			  send_short(pf,0);
			else
			  send_string(pf,argv[3]);
			goto read_retval;
		case CTL_RECORD:	
			if (argc!=3) {
				fputs(help_message,stderr);
				exit(2);
			}
			send_short(pf,match_cmd(argv[2],record_cmds));
			send_string(pf,argv[1]);
			goto read_retval;
		case CTL_SOURCE:
			if (argc<3 || argc>6) {
				fputs(help_message,stderr);
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
			send_long(pf,ttl);
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
			send_short(pf,cmd2);
			send_short(pf,flags);
			goto read_retval;
		case CTL_ADD:
			if (argc<4 || argc>7) {
				fputs(help_message,stderr);
				exit(2);
			}
			cmd=match_cmd(argv[1],rectype_cmds);
			send_short(pf,cmd);
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
			send_long(pf,ttl);
			send_short(pf,flags);

			switch (cmd) {
			case T_A:
				if (!inet_aton(argv[2],&ina4)) {
					fprintf(stderr,"Bad IP for add a option\n");
					exit(2);
				}
				if(write(pf,&ina4,sizeof(ina4))!=sizeof(ina4)) {
				  perror("Error: could not send IP");
				  exit(2);
				}
				break;
#ifdef ENABLE_IPV6
			case T_AAAA:
				if (!inet_pton(AF_INET6,(char *)argv[2],&ina6)) {
					fprintf(stderr,"Bad IP (v6) for add aaaa option\n");
					exit(2);
				}
				if(write(pf,&ina6,sizeof(ina6))!=sizeof(ina6)) {
				  perror("Error: could not send IP (v6)");
				  exit(2);
				}
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
				send_short(pf,tp);
				send_string(pf,argv[2]);
				break;
			}
			goto read_retval;

		case CTL_NEG:
			if (argc<2 || argc>4) {
				fputs(help_message,stderr);
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
			send_short(pf,tp);
			send_long(pf,ttl);
			break;

		read_retval:
			if((rv=read_short(pf))) {
			    int n=read(pf,msgbuf,255);
			    if(n>0) {
			      msgbuf[n]='\0';
			      errmsg=msgbuf;
			    }
			    else
			      errmsg="(could not read error message)";
			}
		}
		close(pf);
	}
	if (rv) {
		fprintf(stderr,"Failed: %s\n",errmsg);
	}
	else
		printf("Succeeded\n");
	return rv;
}

