# $Id: Makefile.am,v 1.3 2000/11/11 16:21:39 thomas Exp $
.PHONY: all clean distclean

noinst_PROGRAMS = if_up is_local_addr tping random

## Dirty trick:  I demand that these objects be built; then, with the knowledge
## that the object files will end up here, I redefine the link chain. 

TESTADDSRC= netdev.c error.c thread.c helpers.c icmp.c
#TESTDEPS = ../netdev.o ../error.o ../thread.o ../helpers.o ../icmp.o

#TESTOBJS = netdev.o error.o thread.o helpers.o icmp.o

if_up_SOURCES = if_up.c $(TESTADDSRC)
#if_up_LDADD =  $(TESTOBJS)
#if_up_DEPENDENCIES = $(TESTDEPS)

is_local_addr_SOURCES = is_local_addr.c $(TESTADDSRC)
#is_local_addr_LDADD = $(TESTOBJS)
#is_local_addr_DEPENDENCIES = $(TESTDEPS)

tping_SOURCES = tping.c $(TESTADDSRC)
#tping_LDADD = $(TESTOBJS)
#tping_DEPENDENCIES = $(TESTDEPS)

random_SOURCES = random.c $(TESTADDSRC)
#random_LDADD = $(TESTOBJS)
#random_DEPENDENCIES = $(TESTDEPS)
