/* ipvers.h - definitions for IPv4 and IPv6

   Copyright (C) 2000, 2001 Thomas Moestl
   Copyright (C) 2003 Paul A. Rombouts

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

/* $Id: ipvers.h,v 1.6 2001/04/06 18:11:35 tmm Exp $ */

#ifndef IPVERS_H
#define IPVERS_H

#include <config.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined(ENABLE_IPV4) && !defined(ENABLE_IPV6)
# ifdef DEFAULT_IPV4
#  undef DEFAULT_IPV4 
# endif
# define DEFAULT_IPV4 1
#endif

#if !defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
# ifdef DEFAULT_IPV4
#  undef DEFAULT_IPV4 
# endif
# define DEFAULT_IPV4 0
#endif

#if defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
# define ELSE_IPV6 else
#else
# define ELSE_IPV6
#endif

/* From main.c */
#ifdef ENABLE_IPV4
# ifdef ENABLE_IPV6
extern short int run_ipv4;
extern short int cmdlineipv;
# else
#  define run_ipv4 1
# endif
#else
#  define run_ipv4 0
#endif
#ifdef ENABLE_IPV6
#define DEFAULT_IPV4_6_PREFIX "::ffff:0.0.0.0"
extern short int cmdlineprefix;
#endif

#if TARGET==TARGET_LINUX && defined(NO_IN_PKTINFO)
struct in_pktinfo
{
	int		ipi_ifindex;
	struct in_addr	ipi_spec_dst;
	struct in_addr	ipi_addr;
};
#endif

#if TARGET==TARGET_LINUX
/* some older glibc versions seem to lack this. */
# ifndef IP_PKTINFO
#  define IP_PKTINFO 8
# endif
# ifndef CMSG_LEN
/* ---- from glibc 2.1.2 */

/* Ancillary data object manipulation macros.  */
#  if !defined __STRICT_ANSI__ && defined __GNUC__ && __GNUC__ >= 2
#   define CMSG_DATA(cmsg) ((cmsg)->__cmsg_data)
#  else
#   define CMSG_DATA(cmsg) ((unsigned char *) ((struct cmsghdr *) (cmsg) + 1))
#  endif
#  define CMSG_NXTHDR(mhdr, cmsg) __cmsg_nxthdr (mhdr, cmsg)
#  define CMSG_FIRSTHDR(mhdr) \
  ((size_t) (mhdr)->msg_controllen >= sizeof (struct cmsghdr)		      \
   ? (struct cmsghdr *) (mhdr)->msg_control : (struct cmsghdr *) NULL)
#  define CMSG_ALIGN(len) (((len) + sizeof (size_t) - 1) \
			 & ~(sizeof (size_t) - 1))
#  define CMSG_SPACE(len) (CMSG_ALIGN (len) \
			 + CMSG_ALIGN (sizeof (struct cmsghdr)))
#  define CMSG_LEN(len)   (CMSG_ALIGN (sizeof (struct cmsghdr)) + (len))
extern struct cmsghdr *__cmsg_nxthdr __P ((struct msghdr *__mhdr,
					   struct cmsghdr *__cmsg));
#  ifdef __USE_EXTERN_INLINES
#   ifndef _EXTERN_INLINE
#    define _EXTERN_INLINE extern __inline
#   endif
_EXTERN_INLINE struct cmsghdr *
__cmsg_nxthdr (struct msghdr *__mhdr, struct cmsghdr *__cmsg) __THROW
{
  if ((size_t) __cmsg->cmsg_len < sizeof (struct cmsghdr))
    /* The kernel header does this so there may be a reason.  */
    return 0;

  __cmsg = (struct cmsghdr *) ((unsigned char *) __cmsg
			       + CMSG_ALIGN (__cmsg->cmsg_len));
  if ((unsigned char *) (__cmsg + 1) >= ((unsigned char *) __mhdr->msg_control
					 + __mhdr->msg_controllen)
      || ((unsigned char *) __cmsg + CMSG_ALIGN (__cmsg->cmsg_len)
	  >= ((unsigned char *) __mhdr->msg_control + __mhdr->msg_controllen)))
    /* No more entries.  */
    return 0;
  return __cmsg;
}
#  endif	/* Use `extern inline'.  */
/* ---- */
# endif
#endif

#if defined(ENABLE_IPV4) && !defined(SIN_LEN) && (TARGET==TARGET_BSD)
# define SIN_LEN
#endif 

#if defined(ENABLE_IPV6) && TARGET==TARGET_LINUX

/* Some glibc versions (I know of 2.1.2) get this wrong, so we define out own. To be exact, this is fixed
 * glibc code. */
#ifdef IN6_ARE_ADDR_EQUAL
# undef IN6_ARE_ADDR_EQUAL
#endif
#define IN6_ARE_ADDR_EQUAL(a,b) \
	((((uint32_t *) (a))[0] == ((uint32_t *) (b))[0]) && \
	 (((uint32_t *) (a))[1] == ((uint32_t *) (b))[1]) && \
	 (((uint32_t *) (a))[2] == ((uint32_t *) (b))[2]) && \
	 (((uint32_t *) (a))[3] == ((uint32_t *) (b))[3]))

#endif

/* This is the IPv6 flowid that we pass on to the IPv6 protocol stack. This value was not currently defined
 * at the time of writing. Should this change, define a appropriate flowinfo here. */
#define IPV6_FLOWINFO 0

/* There does not seem to be a function/macro to generate IPv6-mapped IPv4-Adresses. So here comes mine. 
 * Pass an in_addr* and an in6_addr* */
#define IPV6_MAPIPV4(a,b) ((uint32_t *)(b))[3]=(a)->s_addr;((uint32_t *)(b))[2]=htonl(0xffff);((uint32_t *)(b))[1]=((uint32_t *)(b))[0]=0

/* A macro to extract the pointer to the address of a struct sockaddr (_in or _in6) */

#define SOCKA_A4(a) ((pdnsd_a *)&((struct sockaddr_in *)(a))->sin_addr)
#define SOCKA_A6(a) ((pdnsd_a *)&((struct sockaddr_in6 *)(a))->sin6_addr)

#ifdef ENABLE_IPV4
# ifdef ENABLE_IPV6
#  define SOCKA_A(a) (run_ipv4?SOCKA_A4(a):SOCKA_A6(a))
#  define PDNSD_PF_INET (run_ipv4?PF_INET:PF_INET6)
#  define PDNSD_AF_INET (run_ipv4?AF_INET:AF_INET6)
# else
#  define SOCKA_A(a) SOCKA_A4(a)
#  define PDNSD_PF_INET PF_INET
#  define PDNSD_AF_INET AF_INET
# endif
#else
# define SOCKA_A(a) SOCKA_A6(a)
# define PDNSD_PF_INET PF_INET6
# define PDNSD_AF_INET AF_INET6
#endif

/* This is to compare two addresses. This is a macro because it may change due to the more complex IPv6 adressing architecture
 * (there are, for example, two equivalent addresses of the loopback device) 
 * Pass this two addresses as in_addr or in6_addr. pdnsd_a is ok (it is a union) */

#define ADDR_EQUIV4(a,b) (((struct in_addr *)(a))->s_addr==((struct in_addr *)(b))->s_addr)
#define ADDR_EQUIV6(a,b) IN6_ARE_ADDR_EQUAL(((struct in6_addr *)(a)),((struct in6_addr *)(b)))

#ifdef ENABLE_IPV4
# ifdef ENABLE_IPV6
#  define ADDR_EQUIV(a,b) ((run_ipv4 && ADDR_EQUIV4(a,b)) || (!run_ipv4 && ADDR_EQUIV6(a,b)))
# else
#  define ADDR_EQUIV(a,b) ADDR_EQUIV4(a,b)
# endif
#else
# define ADDR_EQUIV(a,b) ADDR_EQUIV6(a,b)
#endif

/* See if we need 4.4BSD style sockaddr_* structures and define some macros that set the length field. 
 * The non-4.4BSD behaviour is the only one that is POSIX-conformant.*/
#if defined(SIN6_LEN) || defined(SIN_LEN)
# define BSD44_SOCKA
# define SET_SOCKA_LEN4(socka) (socka.sin_len=sizeof(struct sockaddr_in))
# define SET_SOCKA_LEN6(socka) (socka.sin6_len=sizeof(struct sockaddr_in6))
#else
# define SET_SOCKA_LEN4(socka)
# define SET_SOCKA_LEN6(socka)
#endif

#ifdef ENABLE_IPV6
# define ADDRSTR_MAXLEN INET6_ADDRSTRLEN
#else
# ifdef INET_ADDRSTRLEN
#  define ADDRSTR_MAXLEN INET_ADDRSTRLEN
# else
#  define ADDRSTR_MAXLEN 16
# endif
#endif

#if TARGET==TARGET_BSD
# define SOL_IPV6 IPPROTO_IPV6
#endif

typedef union {
#ifdef ENABLE_IPV4
	struct in_addr   ipv4;
#endif
#ifdef ENABLE_IPV6
	struct in6_addr  ipv6;
#endif
} pdnsd_a;

/* used to enter local records */
typedef	union {
	struct in_addr ipv4;
#ifdef ENABLE_IPV6
	struct in6_addr ipv6;
#endif
} pdnsd_ca;


#endif
