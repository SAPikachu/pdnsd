#!/usr/bin/perl
# $Id§
##########################################################################
#
# Filename:     save_ram.pl
# Description:  check sysopen mode values for pdnsd_dhcp.pl
# Author: 	Marko Stolle
# Created:      November 28, 2001
# Last Updated: February 28, 2001
# Email:        fwd2m@gmx.de
#
###########################################################################

use Fcntl;
use strict;

 printf STDOUT O_WRONLY."|".O_CREAT."|".O_EXCL."\n";
