#!/bin/sh
#
# Client regression testing for pdnsd.
#
# $Id: clnt-test.sh,v 1.3 2001/04/12 18:48:56 tmm Exp $

DIG=/usr/bin/dig
ERR="{ echo "Failed."; exit 1; }"

$DIG www.gmx.de || $ERR
$DIG gmx.net NS || $ERR
$DIG www.dents.org || $ERR
$DIG slashdot.org MX || $ERR
$DIG www.v6.itojun.org AAAA || $ERR

# Some things that should not work.
$DIG version.bind chaos txt
$DIG local AXFR
$DIG local IXFR

nmap -sT 192.168.0.50

dd if=/dev/random | nc 192.168.0.50 53

# Test that the server is still alive.
$DIG www.gmx.de A || $ERR

echo "Succeeded."
