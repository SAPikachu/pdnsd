/* dns.h - Declarations for dns handling and generic dns functions
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

/* $Id: dns.h,v 1.5 2000/10/20 08:58:57 thomas Exp $ */

#ifndef _DNS_H_
#define _DNS_H_

#include <config.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>

/* Deal with byte orders */
#ifndef __BYTE_ORDER
# ifdef __LITTLE_ENDIAN
#  define __BYTE_ORDER __LITTLE_ENDIAN
# endif
# ifdef __BIG_ENDIAN
#   define __BYTE_ORDER __BIG_ENDIAN
# endif
#endif

/* type codes */
#define T_MIN       1
#define T_A         1
#define T_NS        2    /* additional A*/
#define T_MD        3    /* additional A*/
#define T_MF        4    /* additional A*/
#define T_CNAME     5
#define T_SOA       6
#define T_MB        7    /* additional A*/
#define T_MG        8  
#define T_MR        9    
#define T_NULL     10
#define T_WKS      11
#define T_PTR      12
#define T_HINFO    13
#define T_MINFO    14
#define T_MX       15    /* additional A*/
#define T_TXT      16
#ifdef DNS_NEW_RRS
# define T_MAX     36
# define T_NUM     36
#else
# define T_MAX     16
# define T_NUM     16
#endif

#define T_RP	   17
#define T_AFSDB    18
#define T_X25      19
#define T_ISDN     20
#define T_RT       21
#define T_NSAP     22
#define T_NSAP_PTR 23    /* deprecated (ill-designed) and not supported */
#define T_SIG      24
#define T_KEY      25
#define T_PX       26
#define T_GPOS     27
#define T_AAAA     28
#define T_LOC      29
#define T_NXT      30
#define T_EID      31
#define T_NIMLOC   32
#define T_SRV      33
#define T_ATMA     34
#define T_NAPTR    35
#define T_KX       36

/* special type codes for queries */
#define QT_MIN    251
#define QT_IXFR   251
#define QT_AXFR   252
#define QT_MAILB  253
#define QT_MAILA  254
#define QT_ALL    255
#define QT_MAX    255
#define QT_NUM      5

/* classes */
#define C_MIN       1
#define C_IN        1
#define C_CS        2
#define C_CH        3
#define C_HS        4
#define C_MAX       4
#define C_NUM       4

/* special classes for queries */
#define QC_ALL    255

/* status codes */
#define RC_OK       0
#define RC_FORMAT   1
#define RC_SERVFAIL 2
#define RC_NAMEERR  3
#define RC_NOTSUPP  4
#define RC_REFUSED  5

/*
 * special internal retvals
 */
#define RC_TCPREFUSED 254
#define RC_TRUNC      255

/* query/response */
#define QR_QUERY    0
#define QR_RESP     1

/*opcodes */
#define OP_QUERY    0
#define OP_IQUERY   1
#define OP_STATUS   2


/* rfc2181 details that the ttl is a 32-bit integer, where the most significant bit is always 0.
 * for convenience and Unix compatablility we use a long, which satisfies these conditions if 
 * positive (which is ensured in the code */
typedef struct {
	/* the name is the first field. It has variable length, so it can't be put in the struct */
	unsigned short type      __attribute__((packed));
	unsigned short class     __attribute__((packed)); 
	long           ttl       __attribute__((packed));
	unsigned short rdlength  __attribute__((packed));
	/* rdata follows */
} rr_hdr_t;

typedef struct {
	/* The server name and maintainer mailbox are the first two fields. It has variable length, */
	/* so they can't be put in the struct */
	unsigned long  serial    __attribute__((packed));
	unsigned long  refresh   __attribute__((packed));
	unsigned long  retry     __attribute__((packed));
	unsigned long  expire    __attribute__((packed));
	unsigned long  minimum   __attribute__((packed));
} soa_r_t;


typedef struct {
/*	char           qname[];*/
	unsigned short qtype     __attribute__((packed));
	unsigned short qclass    __attribute__((packed));
} std_query_t;

typedef struct {
	unsigned short id        __attribute__((packed));
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int   rd:1;
	unsigned int   tc:1;
	unsigned int   aa:1;
	unsigned int   opcode:4;
	unsigned int   qr:1;
	unsigned int   rcode:4;
	unsigned int   z1:1;
	unsigned int   au:1;
	unsigned int   z2:1;
	unsigned int   ra:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int   qr:1;
	unsigned int   opcode:4;
	unsigned int   aa:1;
	unsigned int   tc:1;
	unsigned int   rd:1;
	unsigned int   ra:1;
	unsigned int   z2:1;
	unsigned int   au:1;
	unsigned int   z1:1;
	unsigned int   rcode:4;
#else
# error	"Please define __BYTE_ORDER to be __LITTLE_ENDIAN or __BIG_ENDIAN"
#endif
	unsigned short qdcount   __attribute__((packed));
	unsigned short ancount   __attribute__((packed));
	unsigned short nscount   __attribute__((packed));
	unsigned short arcount   __attribute__((packed));
} dns_hdr_t;

/* Recursion depth. */
#define MAX_HOPS 20

/*
 * Types for compression buffers.
 */
typedef struct {
	int           index;
	unsigned char s[255];
} compel_t;

typedef struct {
	int      num;
	compel_t first_el;
} compbuf_t;


int decompress_name(unsigned char *msg, unsigned char *tgt, unsigned char **src, long *sz, long msgsz, int *len);
int domain_match(int *o, unsigned char *ms, unsigned char *md, unsigned char *rest);
int compress_name(unsigned char *in, unsigned char *out, int offs, compbuf_t **cb);

int read_hosts(char *fn, unsigned char *rns, time_t ttl, int aliases, char *errbuf, int errsize);

#if DEBUG>0 
char *get_cname(int id);
char *get_tname(int id);
char *get_ename(int id);
#endif

#endif
