#!/bin/sh
#
# Client regression testing for pdnsd.
#
# $Id: clnt-test.sh,v 1.4 2001/05/19 15:14:25 tmm Exp $

SERVER=192.168.0.50

# The following programs are needed:
# dig   - queries
# nmap  - test the effect of immediately closed connections
# dd/nc - pipe some random data as query to pdnsd (robustness test)
DIG=/usr/bin/dig
NMAP=/usr/local/bin/nmap
DD=/bin/dd
NC=/usr/local/bin/nc

err() {
    echo 'Failed.'
    exit 1;
};

$DIG @$SERVER www.gmx.de || $ERR
$DIG @$SERVER gmx.net NS || $ERR
$DIG @$SERVER www.dents.org || $ERR
$DIG @$SERVER slashdot.org MX || $ERR
$DIG @$SERVER www.v6.itojun.org AAAA || $ERR

# Some things that should not work.
$DIG @$SERVER version.bind chaos txt
$DIG @$SERVER local AXFR
$DIG @$SERVER local IXFR

$NMAP -sT $SERVER

$DD if=/dev/random | $NC $SERVER 53

# Test that the server is still alive.
$DIG @$SERVER www.gmx.de A || $ERR

echo "Succeeded."
