#!/usr/bin/perl
#
##########################################################################
#
# Filename:     pdnsd_update.pl
# Description:  Dynamic DNS-DHCP update scrypt for pdnsd
# Author: 	Mike Stella
# Modified by:  Marko Stolle
# Created:      November 19, 2001
# Last Updated: February 20, 2001
# Email:        fwd2m@gmx.de
#
###########################################################################
#
#  This code is Copyright (c) 1998-2001 by Mike Stella and Marko Stolle
#
#  NO WARRANTY is given for this program.  If it doesn't
#  work on your system, sorry.  If it eats your hard drive, 
#  again, sorry.  It works fine on mine.  Good luck!
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
###########################################################################
#
# This script reads a dhcpd.leases file and dynamically updates pdnsd with
# hostname and ip information.  
#
# It assumes that your DHCP server recieves hostnames from the
# clients, and that your clients offer their hostnames to the server.
# Some versions of Linux DHCP clients don't do that.  I use ISC's
# DHCPD, found at http://www.isc.org - though others may work just
# fine.
#
# This version of the script updates the pdnsd database. The status
# control socket of psdnd has to be enabled (psnsd -d -s). 
#
###########################################################################
#
# 02/20/2001 - first working version
#
###########################################################################

use Fcntl;
use POSIX qw(tmpnam);
use strict;
$|=1;

###########################################################################
### Globals - you can change these as needed

# Domain name
my $domain_name        = "mww";

# DHCPD lease file
my $lease_file         = "/var/lib/dhcp/dhcpd.leases";

# path to pdnsd-ctl
my $pdnsd_ctl          = "/usr/local/sbin/pdnsd-ctl";

# owning name server for the newly added records
my $nameserver         = "localhost.";

# TTL (Time To Live) for the new records
my $ttl                = "86400";

# number of seconds to check the lease file for updates
my $update_freq        = 60;

my $debug = 0;

###########################################################################
### Don't mess with anything below unless you REALLY need to modify the
### code.  And if you do, please let me know, I'm always interested in
### in improving this program.

# Make a pid file
`echo $$ > /var/run/pdnsd_update.pid`;

my $logstr;

# last modified time
my $modtime = 0;

use vars qw (%db);

my $version = "1.0";

###########################################################################
# Main Loop
while (1) {

  # check the file's last updated time, if it's been changed, update
  # the DNS and save the modified time.  This will ALWAYS run once - on
  # startup, since $modtime starts at zero.

  my @stats = stat ($lease_file);
  if ($stats[9] > $modtime) {

	# clear the old hash
	undef %db;

	printf STDERR "dhcpd.leases changed - updating DNS\n";
	$modtime = $stats[9];
	&read_lease_file;
	&update_dns;
  } 

  # wait till next check time
  sleep $update_freq;

} # end main
###########################################################################


### write out the import file
sub update_dns {
	my ($ip, $hostname, $fname);

	do { $fname = tmpnam() }
        until sysopen(DNSFILE, $fname, O_WRONLY|O_CREAT|O_EXCL);

	while (($hostname,$ip) = each (%db)) {
		print DNSFILE "$ip $hostname.$domain_name\n";
	}
	close DNSFILE;

	system ("$pdnsd_ctl source $fname $nameserver $ttl");
	unlink($fname);
}


### reads the lease file & makes a hash of what's in there.
sub read_lease_file {

  unless (open(LEASEFILE,$lease_file)) {
	#`logger -t dns_update.pl error opening dhcpd lease file`;
	print STDERR "Can't open lease file\n";
	return;
  }

  my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
  my $curdate = sprintf "%02d%02d%02d%02d%02d%20d%20d",
  		($year+1900),($mon+1),$mday,$hour,$min,$sec;

  ## Loop here, reading from LEASEFILE
  while (<LEASEFILE>) {
	my ($ip, $hostname, $mac, $enddate,$endtime);

	if (/^\s*lease/i) {
		
	  # find ip address
	  $_ =~ /^\s*lease\s+(\S+)/;
	  $ip = $1;
	  
	  # do the rest of the block - we're interested in hostname,
	  # mac address, and the lease time
	  while ($_ !~ /^}/) {
	    $_ = <LEASEFILE>;
		# find hostname
		if ($_ =~ /^\s*client/i) {
		  #chomp $_;
		  #chop $_;
		  $_ =~ /\"(.*)\"/;
		  $hostname = $1;
		  
		  # change spaces to dash, remove dots - microsoft
		  # really needs to not do this crap
		  $hostname =~ s/\s+/-/g;
		  $hostname =~ s/\.//g;
		}
		# get the lease end date
		elsif ($_ =~ /^\s*ends/i) {
			$_ =~ m/^\s*ends\s+\d\s+([^;]+);/;
			$enddate = $1;
			$enddate =~ s|[/: ]||g;
		}
	  }
	  # lowercase it - stupid dhcp clients
	  $hostname =~ tr/[A-Z]/[a-z]/;

	  ($debug < 1 ) || print STDERR "$hostname $ip $enddate $curdate\n";
	  
	  # Store hostname/ip in hash - this way we can do easy dupe checking
	  if (($hostname ne "") and ($enddate > $curdate)) {
		$db{$hostname} = $ip;
	  }
	}
  }
  close LEASEFILE;
}

### left around for testing
sub print_db {
  my ($key,$value);

  while (($key,$value) = each (%db)) {
	print "$key - $value\n";
  }
}

