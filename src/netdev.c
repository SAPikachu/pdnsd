/* netdev.c - Test network devices for existence and status
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
#include "config.h"
#include "ipvers.h"
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include "netdev.h"
#include "error.h"

#if !defined(lint) && !defined(NO_RCSIDS)
static char rcsid[]="$Id: netdev.c,v 1.3 2000/08/26 11:33:34 thomas Exp $";
#endif

/*
 * These portion is Linux/FreeBSD specific. Please write interface-detection routines for other
 * flavours of Unix if you can and want.
 */

#if (TARGET==TARGET_LINUX) || (TARGET==TARGET_BSD)
# if TARGET==TARGET_LINUX

int isdn_errs=0;

#  ifdef ISDN_SUPPORT

/*
 * Test the status of an ippp interface. Taken from the isdn4k-utils (thanks!) and adapted
 * by me (I love free software!)
 * This will not work with older kernels.
 * If your kernel is too old or too new, just try to get the status as uptest=exec command
 * This will work, although slower.
 */
 
#   include <linux/isdn.h>

int statusif(char *name)
{
	isdn_net_ioctl_phone phone;
	int isdninfo,rc=0;

	if ((isdninfo = open("/dev/isdninfo", O_RDONLY))<0) {
		if (isdn_errs<2) {
			log_warn("Could not open /dev/isdninfo for uptest: %s",strerror(errno));
			isdn_errs++;
		}
		return 0;
	}
		
	memset(&phone, 0, sizeof(phone));
	strncpy(phone.name, name, sizeof(phone.name)-1);
	if (ioctl(isdninfo, IIOCNETGPN, &phone)==0) {
		rc=1;
	}
	close(isdninfo);
	return rc;
}
#  endif

/*
 * Test whether the network interface specified in ifname and its
 * associated device specified in devname have locks owned by the
 * same process.
 */
int dev_up(char *ifname, char *devname)
{
	char buffer[256];
 	FILE *fd;
 	int pidi, pidd, rv;
	
 	snprintf(buffer, 256, "/var/run/%s.pid", ifname) ;
 	if ( (fd=fopen(buffer, "r")) == NULL ) {
 		return 0 ;
 	}

 	if ( fscanf(fd, "%d", &pidi) != 1 ) {
		fclose(fd) ;
 		return 0 ;
 	}
 	fclose(fd) ;
 
 	snprintf(buffer, 256, "/var/lock/LCK..%s", devname) ;
 	if ( (fd=fopen(buffer, "r")) == NULL ) {
		return 0 ;
 	}
	
 	if ( fscanf(fd, "%d", &pidd) != 1 ) {
		fclose(fd) ;
		return 0 ;
 	}
 	fclose(fd) ;
	
 	if (pidi != pidd)
		return 0;
	/* Test whether pppd is still alive */
	rv=kill(pidi,0);
	return (rv==0 || (rv==-1 && errno==ESRCH));
}
 

# endif

/*
 * Test whether the network device specified in devname is up and
 * running (returns -1) or non-existent, down or not-running (returns 0)
 *
 * Note on IPv6-Comptability: rfc2133 requires all IPv6 implementation
 * to be backwards-compatible to IPv4 in means of permitting socket(PF_INET,...)
 * and similar. So, I don't put code here for both IPv4 and IPv6, since
 * I use that socket only for ioctls. If somebody notices incompatabilities,
 * please notify me.
 */
int if_up(char *devname)
{
        struct protoent *pe;
	int sock;
	struct ifreq ifr;
# if TARGET==TARGET_LINUX
	if (strlen(devname)>4 && strlen(devname)<=6 && strncmp(devname,"ippp",4)==0) {
		/* This function didn't manage the interface uptest correctly. Thanks to
		 * Joachim Dorner for pointing out. 
		 * The new code (statusif()) was shamelessly stolen from isdnctrl.c of the 
		 * isdn4k-utils. */
#  ifdef ISDN_SUPPORT
		return statusif(devname);
#  else
		if (isdn_errs==0) {
			log_warn("An ippp? device was specified for uptest, but pdnsd was compiled without ISDN support.");
			log_warn("The uptest result will be wrong.");
			isdn_errs++;
		}
#  endif
		/* If it doesn't match our rules for isdn devices, treat as normal if */
	}
# endif
	if (!(pe=getprotobyname("udp")))
		return 0;
	if ((sock=socket(PF_INET,SOCK_DGRAM, pe->p_proto))==-1)
		return 0;
	strncpy(ifr.ifr_name,devname,IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ-1]='\0';
	if (ioctl(sock,SIOCGIFFLAGS,&ifr)==-1) {
		close(sock);
		return 0;
	}
	close(sock);
	if (!(ifr.ifr_flags&IFF_UP) || !(ifr.ifr_flags&IFF_RUNNING))
		return 0;
	return 1;
}

# if TARGET==TARGET_LINUX

int is_local_addr(pdnsd_a *a)
{
	int i,res;
#  ifdef ENABLE_IPV4
	struct protoent *pe;
	int sock;
	struct ifreq ifr;
#  endif
#  ifdef ENABLE_IPV6
	char   buf[50];
	FILE   *f;
	struct in6_addr b;
#  endif
#  ifdef ENABLE_IPV4
	if (run_ipv4) {
		res=0;
		if (!(pe=getprotobyname("udp")))
			return 0;
		if ((sock=socket(PF_INET,SOCK_DGRAM, pe->p_proto))==-1)
			return 0;
		for (i=1;i<255;i++) {
			ifr.ifr_ifindex=i;
			if (ioctl(sock,SIOCGIFNAME,&ifr)==-1) {
				/* There may be gaps in the interface enumeration, so just continue */
				continue;
			}
			if (ioctl(sock,SIOCGIFADDR, &ifr)==-1) {
				continue;
			}
			if (((struct sockaddr_in *)(&ifr.ifr_addr))->sin_addr.s_addr==a->ipv4.s_addr) {
				res=1;
				break;
			}
		}
		close(sock);
		return res;
	}

#  endif
#  ifdef ENABLE_IPV6
	if (run_ipv6) {
		/* the interface configuration and information retrieval is obiously currently done via 
		 * rt-netlink sockets. I think it is relatively likely to change in an incompatible way the 
		 * Linux kernel (there seem to be some major changes for 2.4).
		 * Right now, I just analyze the /proc/net/if_inet6 entry. This may not be the fastest, but 
		 * should work and is easily to adapt should the format change. */
		if (!(f=fopen("/proc/net/if_inet6","r")))
			return 0;
		/* The address is at the start of the line. We just read 4 characters and insert a ':' 8 
		 * times. Such, we can use inet_pton conveniently. More portable, that. */
		while (!feof(f)) {
			memset(buf,'\0',50);
			for (i=0;i<8;i++) {
				for (res=0;res<4;res++) {
					if ((buf[i*5+res]=fgetc(f))==EOF) {
						fclose(f);
						return 0; /* we are at the end of the file and haven't found anything.*/
					}
				}
				if (i<7)
					buf[i*5+4]=':';
			}
			inet_pton(AF_INET6,buf,&b);
			if (IN6_ARE_ADDR_EQUAL((&a->ipv6),(&b))) {
				fclose(f);
				return 1;
			}
			while ((res=fgetc(f))!='\n' && res!=EOF) ;
		}
		fclose(f);
	}
#  endif
	return 0;
}

# else

int is_local_addr(pdnsd_a *a)
{
	struct protoent *pe;
	int sock;
        struct ifconf ifc;
	char buf[2048];
	int cnt=0;
	struct ifreq *ir;
	char *ad;
	  

	ifc.ifc_len=2048;
	ifc.ifc_buf=buf;
	if (!(pe=getprotobyname("udp")))
		return 0;
	if ((sock=socket(PF_INET,SOCK_DGRAM, pe->p_proto))==-1)
		return 0;
	if (ioctl(sock,SIOCGIFCONF,&ifc)==-1) {
	        return 0;
	}
	ad=buf;
	while(cnt<ifc.ifc_len) {
		ir=(struct ifreq *)ad;
#  ifdef ENABLE_IPV4
		if (run_ipv4) {
			if (ir->ifr_addr.sa_family==AF_INET &&
			    ((struct sockaddr_in *)&ir->ifr_addr)->sin_addr.s_addr==a->ipv4.s_addr) {
				return 1;
			}
		}
#  endif
#  ifdef ENABLE_IPV6
		if (run_ipv6) {
			if (ir->ifr_addr.sa_family==AF_INET6 &&
			    IN6_ARE_ADDR_EQUAL(&((struct sockaddr_in6 *)&ir->ifr_addr)->sin6_addr,&a->ipv6)) {
				return 1;
			}
		}
#  endif
		cnt+=_SIZEOF_ADDR_IFREQ(*ir);
		ad+=_SIZEOF_ADDR_IFREQ(*ir);
	        
	}
	close(sock);
	
	return 0;
}

# endif

#else
# error "No OS macro defined. Please look into config.h.templ."
#endif
