/* icmp.c - Server response tests using ICMP echo requests
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

/*
 * This should now work on both Linux and FreeBSD. If anyone
 * with experience in other Unix flavors wants to contribute platform-specific
 * code, he is very welcome. 
 */

#include "config.h"
#include <sys/poll.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "ipvers.h"
#if TARGET==TARGET_BSD
# include <netinet/in_systm.h>
#endif
#include <netinet/ip.h>
#if TARGET==TARGET_LINUX
# include <linux/types.h>
# include <linux/icmp.h>
#else
# include <netinet/ip_icmp.h>
#endif
#ifdef ENABLE_IPV6
# include <netinet/ip6.h>
# include <netinet/icmp6.h>
#endif
#include <netinet/ip.h>
#include <netdb.h>
#include "icmp.h"
#include "error.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: icmp.c,v 1.7 2000/10/30 18:22:16 thomas Exp $";
#endif

#define ICMP_MAX_ERRS 5
int icmp_errs=0; /* This is only here to minimize log output. Since the 
		    consequences of a race is only one log message more/less
		    (out of ICMP_MAX_ERRS), no lock is required. */

int ping_isocket;
int ping_osocket;
#ifdef ENABLE_IPV6
int ping6_isocket=-1;
int ping6_osocket=-1;
#endif

/* different names, same thing... be careful, as these are macros... */
#if TARGET==TARGET_BSD
# define icmphdr   icmp
# define iphdr     ip
# define ip_ihl    ip_hl
# define ip_saddr  ip_src.s_addr
#else
# define ip_saddr  saddr
# define ip_ihl    ihl
#endif

#if TARGET==TARGET_LINUX
# define icmp_type  type
# define icmp_code  code
# define icmp_cksum checksum
# define icmp_id un.echo.id
# define icmp_seq un.echo.sequence
#endif

#if (TARGET==TARGET_LINUX) || (TARGET==TARGET_BSD)
/*
 * These are the ping implementations for Linux/FreeBSD in ther IPv4/ICMPv4 and IPv6/ICMPv6 versions.
 * I know they share some code, but I'd rather keep them separated in some parts, as some
 * things might go in different directions there.
 */

/* glibc2.0 versions don't have some Linux 2.2 Kernel #defines */
#ifndef MSG_ERRQUEUE
# define MSG_ERRQUEUE 0x2000
#endif

#ifndef IP_RECVERR
# define IP_RECVERR 11
#endif

/* Initialize the sockets for pinging */
void init_ping_socket()
{
#ifdef ENABLE_IPV4
	if (run_ipv4) {
		if ((ping_isocket=socket(PF_INET, SOCK_RAW, IPPROTO_ICMP))==-1) {
			log_warn("icmp ping: socket() failed: %s",strerror(errno));
			return;
		}
		if ((ping_osocket=socket(PF_INET,SOCK_RAW,IPPROTO_ICMP))==-1) {
			log_warn("icmp ping: socket() failed: %s",strerror(errno));
		}
	}
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6) {
		if ((ping_isocket=socket(PF_INET, SOCK_RAW, IPPROTO_ICMP))==-1) {
			log_warn("icmp ping: socket() failed: %s",strerror(errno));
			return;
		}
		if ((ping_osocket=socket(PF_INET,SOCK_RAW,IPPROTO_ICMP))==-1) {
			log_warn("icmp ping: socket() failed: %s",strerror(errno));
		}

		if ((ping6_isocket=socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6))==-1) {
			log_warn("icmpv6 ping: socket() failed: %s",strerror(errno));
			return;
		}
		if ((ping6_osocket=socket(PF_INET6,SOCK_RAW,IPPROTO_ICMPV6))==-1) {
			log_warn("icmpv6 ping: socket() failed: %s",strerror(errno));
		}
	}
#endif
}

/* IPv4/ICMPv4 ping. Called from ping (see below) */
static int ping4(struct in_addr addr, int timeout, int rep)
{
	char buf[1024];
	int i;
	long tm;
	int rve=1;
	int len;
	int isock,osock;
#if TARGET==TARGET_LINUX
	struct icmp_filter f;
#else
	struct protoent *pe;
	int SOL_IP;
#endif
	struct sockaddr_in from;
	struct icmphdr icmpd;
	struct icmphdr *icmpp;
	struct msghdr msg;
	unsigned long sum;
	unsigned short *ptr;
	unsigned short id=(unsigned short)(rand()&0xffff); /* randomize a ping id */
	socklen_t sl;
#ifdef NO_POLL
	fd_set fds;
	struct timeval tv;
#else
	struct pollfd pfd[2];
#endif

#if TARGET!=TARGET_LINUX	
	if (!(pe=getprotobyname("ip"))) {
		log_warn("icmp ping: getprotobyname() failed: %s",strerror(errno));
		return -1;
	}
	SOL_IP=pe->p_proto;
#endif

	isock=ping_isocket;
	osock=ping_osocket;


#if TARGET==TARGET_LINUX
	/* Fancy ICMP filering -- only on Linux (as far is I know) */
	
	/* In fact, there should be macros for treating icmp_filter, but I haven't found them in Linux 2.2.15.
	 * So, set it manually and unportable ;-) */
	f.data=0xfffffffe;
	if (setsockopt(isock,SOL_RAW,ICMP_FILTER,&f,sizeof(f))==-1) {
		if (icmp_errs<ICMP_MAX_ERRS) {
			icmp_errs++;
			log_warn("icmp ping: setsockopt() failed: %s", strerror(errno));
		}
		close(isock);
		return -1;
	}
#endif
	if (setsockopt(osock,SOL_IP,IP_RECVERR,&rve,sizeof(rve))==-1) {
		if (icmp_errs<ICMP_MAX_ERRS) {
			icmp_errs++;
			log_warn("icmp ping: setsockopt() failed: %s",strerror(errno));
		}
		close(osock);
		close(isock);
		return -1;
	}
	
	for (i=0;i<rep;i++) {
		icmpd.icmp_type=ICMP_ECHO;
		icmpd.icmp_code=0;
		icmpd.icmp_cksum=0;
		icmpd.icmp_id=htons((short)id);
		icmpd.icmp_seq=htons((short)i);

		/* Checksumming - Algorithm taken from nmap. Thanks... */

		ptr=(unsigned short *)&icmpd;
		sum=0;

		for (len=0;len<4;len++) {
			sum+=*ptr++;
		}
		sum = (sum >> 16) + (sum & 0xffff);
		sum += (sum >> 16);
		icmpd.icmp_cksum=~sum;

		memset(&from,0,sizeof(from));
		from.sin_family=AF_INET;
		from.sin_port=0;
		from.sin_addr=addr;
		SET_SOCKA_LEN4(from);
		if (sendto(osock,&icmpd,8,0,(struct sockaddr *)&from,sizeof(from))==-1) {
			if (icmp_errs<ICMP_MAX_ERRS) {
				icmp_errs++;
				log_warn("icmp ping: sendto() failed: %s.",strerror(errno));

			}
			return -1;
		}
		/* listen for reply. */
		tm=time(NULL);
		do {
#ifdef NO_POLL
			FD_ZERO(&fds);
			FD_SET(osock, &fds);
			FD_SET(isock, &fds);
			tv.tv_usec=0;
			tv.tv_sec=timeout>(time(NULL)-tm)?timeout-(time(NULL)-tm):0;
			if (select((isock>osock?isock:osock)+1,&fds,NULL,NULL,&tv)<0) {
				if (icmp_errs<ICMP_MAX_ERRS) {
					icmp_errs++;
					log_warn("poll/select failed: %s",strerror(errno));
				}
				return -1; 
			}
#else
			pfd[0].fd=osock;
			pfd[0].events=POLLIN;
			pfd[1].fd=isock;
			pfd[1].events=POLLIN;
			printf("to: %li\n",timeout>(time(NULL)-tm)?(timeout-(time(NULL)-tm))*1000:0);
			if (poll(pfd,2,timeout>(time(NULL)-tm)?(timeout-(time(NULL)-tm))*1000:0)<0) {
				if (icmp_errs<ICMP_MAX_ERRS) {
					icmp_errs++;
					log_warn("poll/select failed: %s",strerror(errno));
				}
				return -1; 
			}
#endif
#ifdef NO_POLL
			if (FD_ISSET(osock,&fds)) {
#else
			if (pfd[0].revents&POLLIN) {
#endif
				memset(&msg,0,sizeof(msg));
				msg.msg_control=buf;
				msg.msg_controllen=1024;
				if (recvmsg(osock,&msg,MSG_ERRQUEUE)!=-1) {
					if (*((unsigned int *)buf)!=0) {
						return -1;  /* error in sending (e.g. no route to host) */
					}
				}
				fcntl(osock,F_SETFL,O_NONBLOCK);
				/* Just to empty the queue should there be normal packets waiting */
				recvmsg(osock,&msg,0);
				fcntl(osock,F_SETFL,0);
			}

#ifdef NO_POLL
			if (FD_ISSET(isock,&fds)) {
#else
			if (pfd[1].revents&POLLIN) {
#endif
				sl=sizeof(from);
				if ((len=recvfrom(isock,&buf,sizeof(buf),0,(struct sockaddr *)&from,&sl))!=-1) {
					if (len>20 && len-((struct iphdr *)buf)->ip_ihl*4>=8) {
						icmpp=(struct icmphdr *)(((unsigned long int *)buf)+((struct iphdr *)buf)->ip_ihl);
						if (((struct iphdr *)buf)->ip_saddr==addr.s_addr &&
						    icmpp->icmp_type==ICMP_ECHOREPLY && ntohs(icmpp->icmp_id)==id && ntohs(icmpp->icmp_seq)<=i) {
							return (i-ntohs(icmpp->icmp_seq))*timeout+time(NULL)-tm; /* return the number of ticks */
						}
					}
				} else {
					return -1; /* error */
				}
			}
		} while (time(NULL)-tm<timeout);
	}
	return -1; /* no answer */
}


#ifdef ENABLE_IPV6

/* glibc2.0 versions don't have some Linux 2.2 Kernel #defines */
#ifndef IPV6_RECVERR
# define IPV6_RECVERR  25
#endif
#ifndef IPV6_CHECKSUM
# define IPV6_CHECKSUM  7
#endif

/* IPv6/ICMPv6 ping. Called from ping (see below) */
static int ping6(struct in6_addr a, int timeout, int rep)
{
	char buf[1024];
	int i;
	long tm;
	int rve=1;
/*	int ck_offs=2;*/
	int len;
	int isock,osock;
	struct icmp6_filter f;
	struct sockaddr_in6 from;
	struct icmp6_hdr icmpd;
	struct icmp6_hdr *icmpp;
	struct msghdr msg;
	unsigned short id=(unsigned short)(rand()&0xffff); /* randomize a ping id */
	socklen_t sl;
#ifdef NO_POLL
	fd_set fds;
	struct timeval tv;
#else
	struct pollfd pfd[2];
#endif
#if TARGET!=TARGET_LINUX
	int SOL_IPV6;
	struct protoent *pe;

	if (!(pe=getprotobyname("ipv6"))) {
		if (icmp_errs<ICMP_MAX_ERRS) {
			icmp_errs++;
			log_warn("icmp ping: getprotobyname() failed: %s",strerror(errno));
		}
		return -1;
	}
	SOL_IPV6=pe->p_proto;
#endif

	isock=ping6_isocket;
	osock=ping6_osocket;

	ICMP6_FILTER_SETBLOCKALL(&f);
	ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY,&f);

	if (setsockopt(isock,IPPROTO_ICMPV6,ICMP6_FILTER,&f,sizeof(f))==-1) {
		if (icmp_errs<ICMP_MAX_ERRS) {
			icmp_errs++;
			log_warn("icmpv6 ping: setsockopt() failed: %s", strerror(errno));
		}
		return -1;
	}
	
	/* enable error queueing and checksumming. --checksumming should be on by default.*/
	if (setsockopt(osock,SOL_IPV6,IPV6_RECVERR,&rve,sizeof(rve))==-1 /*|| 
	    setsockopt(osock,IPPROTO_ICMPV6,IPV6_CHECKSUM,&ck_offs,sizeof(ck_offs))==-1*/) {
		if (icmp_errs<ICMP_MAX_ERRS) {
			icmp_errs++;
				log_warn("icmpv6 ping: setsockopt() failed: %s",strerror(errno));
		}
		return -1;
	}
	
	for (i=0;i<rep;i++) {
		icmpd.icmp6_type=ICMP6_ECHO_REQUEST;
		icmpd.icmp6_code=0;
		icmpd.icmp6_cksum=0; /* The friendly kernel does fill that in for us. */
		icmpd.icmp6_id=htons((short)id);
		icmpd.icmp6_seq=htons((short)i);
		
		memset(&from,0,sizeof(from));
		from.sin6_family=AF_INET6;
		from.sin6_flowinfo=IPV6_FLOWINFO;
		from.sin6_port=0;
		from.sin6_addr=a;
		SET_SOCKA_LEN6(from);
/*		printf("to: %s.\n",inet_ntop(AF_INET6,&from.sin6_addr,buf,1024));*/
		if (sendto(osock,&icmpd,sizeof(icmpd),0,(struct sockaddr *)&from,sizeof(from))==-1) {
			if (icmp_errs<ICMP_MAX_ERRS) {
				icmp_errs++;
				log_warn("icmpv6 ping: sendto() failed: %s.",strerror(errno));

			}
			return -1;
		}
		/* listen for reply. */
		tm=time(NULL);
		do {
#ifdef NO_POLL
			FD_ZERO(&fds);
			FD_SET(osock, &fds);
			FD_SET(isock, &fds);
			tv.tv_usec=0;
			tv.tv_sec=timeout>(time(NULL)-tm)?timeout-(time(NULL)-tm):0;
			if (select((isock>osock?isock:osock)+1,&fds,NULL,NULL,&tv)<0) {
				if (icmp_errs<ICMP_MAX_ERRS) {
					icmp_errs++;
					log_warn("poll/select failed: %s",strerror(errno));
				}
				return -1; 
			}
#else
			pfd[0].fd=osock;
			pfd[0].events=POLLIN;
			pfd[1].fd=isock;
			pfd[1].events=POLLIN;
			if (poll(pfd,2,timeout>(time(NULL)-tm)?(timeout-(time(NULL)-tm))*1000:0)<0) {
				if (icmp_errs<ICMP_MAX_ERRS) {
					icmp_errs++;
					log_warn("poll/select failed: %s",strerror(errno));
				}
				return -1; 

			}
#endif

#ifdef NO_POLL
			if (FD_ISSET(osock,&fds)) {
#else
			if (pfd[0].revents&POLLIN) {
#endif
				memset(&msg,0,sizeof(msg));
				msg.msg_control=buf;
				msg.msg_controllen=1024;
				if (recvmsg(osock,&msg,MSG_ERRQUEUE)!=-1) {
					if (*((unsigned int *)buf)!=0) {
						return -1;  /* error in sending (e.g. no route to host) */
					}
				}
				fcntl(osock,F_SETFL,O_NONBLOCK);
				/* Just to empty the queue should there be normal packets waiting */
				recvmsg(osock,&msg,0);
				fcntl(osock,F_SETFL,0);
			}

#ifdef NO_POLL
			if (FD_ISSET(isock,&fds)) {
#else
			if (pfd[1].revents&POLLIN) {
#endif
				sl=sizeof(from);
/*	        		printf("before: %s.\n",inet_ntop(AF_INET6,&from.sin6_addr,buf,1024));*/
				if ((len=recvfrom(isock,&buf,sizeof(buf),0,(struct sockaddr *)&from,&sl))!=-1) {
					if (len>=sizeof(struct icmp6_hdr)) {
/*	   			        printf("reply: %s.\n",inet_ntop(AF_INET6,&from.sin6_addr,buf,1024));*/
						/* we get packets without IPv6 header, luckily */
						icmpp=(struct icmp6_hdr *)buf;
						/* The address comparation was diked out because some linux versions
						 * seem to have problems with it. */
						if (IN6_ARE_ADDR_EQUAL(&from.sin6_addr,&a) &&
						    ntohs(icmpp->icmp6_id)==id && ntohs(icmpp->icmp6_seq)<=i) {
							return (i-ntohs(icmpp->icmp6_seq))*timeout+time(NULL)-tm; /* return the number of ticks */
						}
					}
				} else {
					return -1; /* error */
				}
			}
		} while (time(NULL)-tm<timeout);
	}
	return -1; /* no answer */
}
#endif /* ENABLE_IPV6*/


/* Perform an icmp ping on a host, returning -1 on timeout or 
 * "host unreachable" or the ping time in 10ths of secs.
 * timeout in 10ths of seconds, rep is the repetition count
 */
int ping(pdnsd_a *addr, int timeout, int rep)
{
#ifdef ENABLE_IPV6
	struct in_addr v4;
#endif

	if (ping_isocket==-1 || ping_osocket==-1)
		return -1;

#ifdef ENABLE_IPV4
	if (run_ipv4)
		return ping4(addr->ipv4,timeout/10,rep);
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6) {
		/* If it is a IPv4 mapped IPv6 address, we prefer ICMPv4. */
		if (IN6_IS_ADDR_V4MAPPED(&addr->ipv6)) {
			v4.s_addr=((long *)&addr->ipv6)[3];
			return ping4(v4,timeout/10,rep);
		} else 
			return ping6(addr->ipv6,timeout/10,rep);
	}
#endif
	return -1;
}

#else
# error "No OS macro defined. Please look into config.h.templ."
#endif /*TARGET==TARGET_LINUX || TARGET==TARGET_BSD*/
