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
 * This is truly Linux-specific at this time, as I have to admit. If anyone
 * with experience in other Unix flavors wants to contribute platform-specific
 * code, he is very welcome. 
 */

#include "config.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "ipvers.h"
#if TARGET==TARGET_LINUX
# include <linux/types.h>
# include <linux/icmp.h>
#endif
#if TARGET==TARGET_BSD
# include <netinet/in_systm.h>
#endif
#ifdef ENABLE_IPV6
# include <netinet/ip6.h>
# include <netinet/icmp6.h>
#endif
#include <netinet/ip.h>
#include "icmp.h"
#include "error.h"

#define ICMP_MAX_ERRS 5
int icmp_errs=0; /* This is only here to minimize log output. Since the 
		    consequences of a race is only one log message more/less
		    (out of ICMP_MAX_ERRS), no lock is required. */

#if TARGET==TARGET_LINUX

/*
 * These are the ping implementations for Linux in ther IPv4/ICMPv4 and IPv6/ICMPv6 versions.
 * I know they share some code, but I'd rather keep them separated in some parts, as some
 * things might go in different directions there.
 * Btw., the Linux version of ping6 should be fairly portable, according to rfc2292.
 * The ping4 might be, but well, try it.
 */

/* glibc2.0 versions don't have some Linux 2.2 Kernel #defines */
#ifndef MSG_ERRQUEUE
# define MSG_ERRQUEUE 0x2000
#endif


/* glibc2.0 versions don't have some Linux 2.2 Kernel #defines */
#ifndef IP_RECVERR
# define IP_RECVERR 11
#endif

/* IPv4/ICMPv4 ping. Called from ping (see below) */
static int ping4(struct in_addr addr, int timeout, int rep)
{
	char buf[1024];
	int i,tm;
	int rve=1;
	int len;
	int isock,osock;
	struct icmp_filter f;
	struct sockaddr_in from;
	struct icmphdr icmpd;
	struct icmphdr *icmpp;
	struct msghdr msg;
	__u32 sum;
	__u16 *ptr;
	__u16 id=(__u16)(rand()&0xffff); /* randomize a ping id */
	socklen_t sl;
	/* In fact, there should be macros for treating icmp_filter, but I haven't found them in Linux 2.2.15.
	 * So, set it manually and unportable ;-) */
	f.data=0xfffffffe;
	for (i=0;i<rep;i++) {
		/* Open a raw socket for replies */
		isock=socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (isock==-1) {
			if (icmp_errs<ICMP_MAX_ERRS) {
				icmp_errs++;
				log_warn("icmp ping: socket() failed: %s",strerror(errno));
			}
			return -1;
		}
		if (setsockopt(isock,SOL_RAW,ICMP_FILTER,&f,sizeof(f))==-1) {
			if (icmp_errs<ICMP_MAX_ERRS) {
				icmp_errs++;
				log_warn("icmp ping: setsockopt() failed: %s", strerror(errno));
			}
			close(isock);
			return -1;
		}
		fcntl(isock,F_SETFL,O_NONBLOCK);
		/* send icmp_echo_request */
		osock=socket(PF_INET,SOCK_RAW,IPPROTO_ICMP);
		if (osock==-1) {
			if (icmp_errs<ICMP_MAX_ERRS) {
				icmp_errs++;
				log_warn("icmp ping: socket() failed.");
			}
			close(isock);
			return -1;
		}
		if (setsockopt(osock,SOL_IP,IP_RECVERR,&rve,sizeof(rve))==-1) {
			if (icmp_errs<ICMP_MAX_ERRS) {
				icmp_errs++;
				log_warn("icmp ping: setsockopt() failed: %s",strerror(errno));
			}
			close(osock);
			close(isock);
			return -1;
		}
		icmpd.type=ICMP_ECHO;
		icmpd.code=0;
		icmpd.checksum=0;
		icmpd.un.echo.id=htons((short)id);
		icmpd.un.echo.sequence=htons((short)i);

		/* Checksumming - Algorithm taken from nmap. Thanks... */

		ptr=(__u16 *)&icmpd;
		sum=0;

		for (len=0;len<4;len++) {
			sum+=*ptr++;
		}
		sum = (sum >> 16) + (sum & 0xffff);
		sum += (sum >> 16);
		icmpd.checksum=~sum;


		from.sin_family=AF_INET;
		from.sin_port=0;
		from.sin_addr=addr;
		SET_SOCKA_LEN4(from);
		if (sendto(osock,&icmpd,sizeof(icmpd),0,&from,sizeof(from))==-1) {
			if (icmp_errs<ICMP_MAX_ERRS) {
				icmp_errs++;
				log_warn("icmp ping: sendto() failed: %s.",strerror(errno));

			}
			close(osock);
			close(isock);
			return -1;
		}
		fcntl(osock,F_SETFL,O_NONBLOCK);
		/* listen for reply. */
		tm=0;
		do {
			memset(&msg,0,sizeof(msg));
			msg.msg_control=buf;
			msg.msg_controllen=1024;
			if (recvmsg(osock,&msg,MSG_ERRQUEUE)!=-1) {
				close(osock);
				close(isock);
				return -1;  /* error in sending (e.g. no route to host) */
			}
			sl=sizeof(from);
			if ((len=recvfrom(isock,&buf,sizeof(buf),0,&from,&sl))!=-1) {
				if (len>20 && len-((struct iphdr *)buf)->ihl*4>=8) {
					icmpp=(struct icmphdr *)(((unsigned long int *)buf)+((struct iphdr *)buf)->ihl);
					if (((struct iphdr *)buf)->saddr==addr.s_addr &&
					     ntohs(icmpp->un.echo.id)==id && ntohs(icmpp->un.echo.sequence)<=i) {
						close(osock);
						close(isock);
						return (i-ntohs(icmpp->un.echo.sequence))*timeout+tm; /* return the number of ticks */
					}
				}
			} else {
				if (errno!=EAGAIN)
				{
					close(osock);
					close(isock);
					return -1; /* error */
				}
			}
			usleep(100000);
			tm++;
		} while (tm<timeout);
		close(osock);
		close(isock);
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
	int i,tm;
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

	ICMP6_FILTER_SETBLOCKALL(&f);
	ICMP6_FILTER_SETPASS(ICMP6_ECHO_REQUEST,&f);

	for (i=0;i<rep;i++) {
		/* Open a raw socket for replies */
		isock=socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
		if (isock==-1) {
			if (icmp_errs<ICMP_MAX_ERRS) {
				icmp_errs++;
				log_warn("icmpv6 ping: socket() failed: %s",strerror(errno));
			}
			return -1;
		}
		if (setsockopt(isock,IPPROTO_ICMPV6,ICMP6_FILTER,&f,sizeof(f))==-1) {
			if (icmp_errs<ICMP_MAX_ERRS) {
				icmp_errs++;
				log_warn("icmpv6 ping: setsockopt() for is failed: %s", strerror(errno));
			}
			close(isock);
			return -1;
		}
		fcntl(isock,F_SETFL,O_NONBLOCK);
		/* send icmp_echo_request */
		osock=socket(PF_INET6,SOCK_RAW,IPPROTO_ICMPV6);
		if (osock==-1) {
			if (icmp_errs<ICMP_MAX_ERRS) {
				icmp_errs++;
				log_warn("icmpv6 ping: socket() failed.");
			}
			close(isock);
			return -1;
		}

		/* enable error queueing and checksumming. --checksumming should be on by default.*/
		if (setsockopt(osock,SOL_IPV6,IPV6_RECVERR,&rve,sizeof(rve))==-1 /*|| 
 		    setsockopt(osock,IPPROTO_ICMPV6,IPV6_CHECKSUM,&ck_offs,sizeof(ck_offs))==-1*/) {
			if (icmp_errs<ICMP_MAX_ERRS) {
				icmp_errs++;
				log_warn("icmpv6 ping: setsockopt() for os failed: %s",strerror(errno));
			}
			close(osock);
			close(isock);
			return -1;
		}

		icmpd.icmp6_type=ICMP6_ECHO_REQUEST;
		icmpd.icmp6_code=0;
		icmpd.icmp6_cksum=0; /* The friently kernel does fill that in for us. */
		icmpd.icmp6_id=htons((short)id);
		icmpd.icmp6_seq=htons((short)i);
		
		from.sin6_family=AF_INET6;
		from.sin6_flowinfo=IPV6_FLOWINFO;
		from.sin6_port=0;
		from.sin6_addr=a;
		SET_SOCKA_LEN6(from);
/*		printf("to: %s.\n",inet_ntop(AF_INET6,&from.sin6_addr,buf,1024));*/
		if (sendto(osock,&icmpd,sizeof(icmpd),0,&from,sizeof(from))==-1) {
			if (icmp_errs<ICMP_MAX_ERRS) {
				icmp_errs++;
				log_warn("icmpv6 ping: sendto() failed: %s.",strerror(errno));

			}
			close(osock);
			close(isock);
			return -1;
		}
		fcntl(osock,F_SETFL,O_NONBLOCK);
		/* listen for reply. */
		tm=0;
		do {
			memset(&msg,0,sizeof(msg));
			msg.msg_control=buf;
			msg.msg_controllen=1024;
			if (recvmsg(osock,&msg,MSG_ERRQUEUE)!=-1) {
				close(osock);
				close(isock);
				return -1;  /* error in sending (e.g. no route to host) */
			}
			sl=sizeof(from);
/*			printf("before: %s.\n",inet_ntop(AF_INET6,&from.sin6_addr,buf,1024));*/
			if ((len=recvfrom(isock,&buf,sizeof(buf),0,&from,&sl))!=-1) {
				if (len>=sizeof(struct icmp6_hdr)) {
/*	   			        printf("reply: %s.\n",inet_ntop(AF_INET6,&from.sin6_addr,buf,1024));*/
				        /* we get packets without IPv6 header, luckily */
					icmpp=(struct icmp6_hdr *)buf;
				        /* The address comparation was diked out because some linux versions
				         * seem to have problems with it. */
					if (/*IN6_ARE_ADDR_EQUAL(&from.sin6_addr,&a) &&*/
						ntohs(icmpp->icmp6_id)==id && ntohs(icmpp->icmp6_seq)<=i) {
						close(osock);
						close(isock);
						return (i-ntohs(icmpp->icmp6_seq))*timeout+tm; /* return the number of ticks */
					}
				}
			} else {
				if (errno!=EAGAIN)
				{
					close(osock);
					close(isock);
					return -1; /* error */
				}
			}
			usleep(100000);
			tm++;
		} while (tm<timeout);
		close(osock);
		close(isock);
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

#ifdef ENABLE_IPV4
	if (run_ipv4)
		return ping4(addr->ipv4,timeout,rep);
#endif
#ifdef ENABLE_IPV6
	if (run_ipv6) {
		/* If it is a IPv4 mapped IPv6 address, we prefer ICMPv4. */
		if (IN6_IS_ADDR_V4MAPPED(&addr->ipv6)) {
			v4.s_addr=((long *)&addr->ipv6)[3];
			return ping4(v4,timeout,rep);
		} else 
			return ping6(addr->ipv6,timeout,rep);
	}
#endif
	return -1;
}

#elif TARGET==TARGET_BSD

#else
# error "No OS macro defined. Currently, only Linux is supported. Do -DTARGET=LINUX on your compiler command line."
#endif /*TARGET==TARGET_LINUX*/
