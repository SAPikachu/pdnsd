#!/bin/sh
#
# Regression testing for pdnsd.
#
# $Id: test.sh,v 1.3 2001/05/19 15:17:31 tmm Exp $

err() {
    echo 'Failed.'
    exit 1;
};

DIR=`dirname $0`
if [ -z "DIR" ] ; then
    DIR=.
fi

$DIR/srv-test.sh || err
$DIR/clnt-test.sh || err

echo "Succeeded."
