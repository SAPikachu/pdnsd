#!/bin/sh

# $Id: a-conf.sh,v 1.3 2000/06/24 21:44:21 thomas Exp $
# This is a rather quick-and-dirty script to determine parameters that cannot 
# be gotten using pure #ifdefs.
# It generates a-conf.h 
# If you want to tell me that I should use autoconf, you are right; this is 
# indeed planned, and I hope this code is compatible enough so that the 
# transition will be easy. This script is just a drop-in thingie.

CC=$1

rm -f a-conf.h
touch a-conf.h

if [ `uname` = "Linux" ] ; then
    echo -n "Looking for struct in_pktinfo in your glibc... "
    cat > .a-conf.test.c <<EOF
#include "config.h"
#include "ipvers.h"

struct in_pktinfo pi;

int main()
{
    return 0;
}
EOF

    $CC .a-conf.test.c -o .a-conf.out >/dev/null 2>/dev/null
    if [ $? -eq 0 ] ; then
	echo "present (OK)"
    else
	echo "missing (OK, using my own)"
	echo "#define NO_IN_PKTINFO" >> a-conf.h
    fi
    rm -f .a-conf.out .a-conf.test.c
fi
