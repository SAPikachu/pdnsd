#!/bin/su root

PATH=/sbin:/usr/sbin:/usr/local/sbin:/bin:/usr/bin:/usr/local/bin

install -p -s pdnsd /usr/local/sbin/
install -p -s pdnsd-ctl/pdnsd-ctl /usr/local/sbin/
