#!/bin/sh
#
# Server regression testing for pdnsd.
#
# $Id: srv-test.sh,v 1.1 2001/04/12 01:29:36 tmm Exp $

DIR=`dirname $0`
if [ -z "DIR" ] ; then
    DIR=.
fi

TMPFILE=`mktemp /tmp/pdnsd.conf.XXXXXX`
if [ $? -ne 0 ]; then
    echo "$0: Can't create temp file, exiting..."
    echo "Failed."
    exit 1
fi

cat > $TMPFILE <<EOF
global {
	perm_cache=512;
	cache_dir="/var/cache/pdnsd";
	max_ttl=604800;
	run_as="nobody";
	paranoid=on;
	server_port=53;
	server_ip="127.0.0.1";
	scheme_file="/tmp/foo";
	linkdown_kluge=on;
	min_ttl=900;
	strict_setuid=on;
	daemon=on;
	tcp_server=on;
	pid_file="/var/run/pdnsd.pid";
	debug=on;
	ctl_perms=600;
	proc_limit=10;
	procq_limit=20;
	tcp_qtimeout=10;
	par_queries=10;
	randomize_recs=on;
	neg_ttl=900;
	neg_rrs_pol=auth;
	neg_domain_pol=auth;
}

server {
	ip="192.168.0.1";
	timeout=30;
	interval=30;
	uptest=ping;
	ping_timeout=50;
	purge_cache=off;
	lean_query=on;
	include=".bar.foo.com.";
	exclude=".foo.com.";
	policy=included;
}

source {
	ttl=86400;
	owner="localhost.";
	serve_aliases=on;
	file="/etc/hosts";
}


neg {
	ttl=86400;
	name="foo.bar.";
	types=domain;
}

neg {
	ttl=86400;
	name="foo.baz.";
	types=A,AAAA, MX;
}

rr {
	ttl=86400;
	owner="localhost.";
	name="localhost.";
	a="127.0.0.1";
	soa="localhost.","root.localhost.",42,86400,900,86400,86400;
}

rr {
	ttl=86400;
	owner="localhost.";
	name="1.0.0.127.in-addr.arpa.";
	ptr="localhost.";
	soa="localhost.","root.localhost.",42,86400,900,86400,86400;
}
EOF

$DIR/../pdnsd -d -c $TMPFILE -s

sleep 5

$DIR/../pdnsd-ctl/pdnsd-ctl status || echo 'Failed.'; exit 1;

if ps aux | grep pdnsd | grep -v grep > /dev/null ; then
    killall pdnsd
else
    echo 'Failed.'; exit 1; 
fi

rm $TMPFILE

echo "Succeeded."
