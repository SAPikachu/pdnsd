#!/bin/sh
#
# Regression testing for pdnsd.
#
# $Id: test.sh,v 1.1 2001/04/12 01:29:36 tmm Exp $

ERR="{ echo 'Failed.'; exit 1; }"

DIR=`dirname $0`
if [ -z "DIR" ] ; then
    DIR=.
fi

$DIR/srv-test.sh || $ERR
$DIR/clnt-test.sh || $ERR

echo "Succeeded."
