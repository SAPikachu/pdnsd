#!/bin/sh
#
# Client regression testing for pdnsd.
#
# $Id: clnt-test.sh,v 1.2 2001/04/12 02:45:40 tmm Exp $

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

dd if=/dev/random | nc 192.168.0.50 53

# Test that the server is still alive.
$DIG www.gmx.de A || $ERR

echo "Succeeded."
