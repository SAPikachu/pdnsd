#!/bin/sh
#
# Regression testing for pdnsd.
#
# $Id: test.sh,v 1.2 2001/05/19 15:14:25 tmm Exp $

err() {
    echo 'Failed.'
    exit 1;
};

DIR=`dirname $0`
if [ -z "DIR" ] ; then
    DIR=.
fi

$DIR/srv-test.sh || $ERR
$DIR/clnt-test.sh || $ERR

echo "Succeeded."
