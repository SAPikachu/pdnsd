#!/bin/sh
#
# Client regression testing for pdnsd.
#
# $Id: clnt-test.sh,v 1.1 2001/04/12 01:29:36 tmm Exp $

DIG=/usr/bin/dig
ERR="{ echo "Failed."; exit 1; }"

$DIG www.gmx.de || $ERR
$DIG gmx.net NS || $ERR
$DIG www.dents.org || $ERR
$DIG slashdot.org MX || $ERR

# Some things that should not work.
$DIG version.bind chaos txt
$DIG local AXFR
$DIG local IXFR

nmap -sT 192.168.0.50

dd if=/dev/random | nc -p 53 192.168.0.50

# Test that the server is still alive.
$DIG www.gmx.de A || $ERR

echo "Succeeded."
