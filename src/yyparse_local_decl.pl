#!/usr/bin/perl -w
#
# A Perl script to insert the macro name YYPARSE_LOCAL_DECL
# at the beginning of the body of the function yyparse().
#
# Written by Paul A. Rombouts
#
# This file Copyright 2002 Paul A. Rombouts
# It may be distributed under the GNU Public License, version 2, or
# any higher version.  See section COPYING of the GNU Public license
# for conditions under which this file may be redistributed.
#

use strict;
use English;


my $found_decl=0;
my $found_yyparse=0;
my $exitval=0;

while(<>) {
    print;
    if(/^\#\s*define\s+YYPARSE_LOCAL_DECL\b/) {
       $found_decl=1;
       last;
   }
}

if(!$found_decl) {
    warn "No definition for YYPARSE_LOCAL_DECL found, no modifications made.\n";
    exit 1;
}

my @patterns= (qr/int\b/, qr/yyparse\s*\([^()]*\)/, qr/(\s*[^\s(){};][^(){};]*\;?)*/, qr/\{/);

LOOP: while(defined(my $rest = <>)) {
    my $match='';
    foreach my $patt (@patterns) {
	if($rest =~ /^\s*$patt/) {
	    $match .= $MATCH;
	    $rest= $POSTMATCH;
	    while($rest =~ /^\s*\\?$/) {
		$match.=$rest;
		unless(defined($rest = <>)) {print($match); last LOOP};
	    }
	}
	else {
	    print($match,$rest);
	    next LOOP;
	}
    }
    if($found_yyparse && !$exitval) {
	warn "Warning: multiple instances of yyparse() found!.\n";
	$exitval=3;
    }
    $found_yyparse=1;
    print($match,"  YYPARSE_LOCAL_DECL\n",$rest);
}

if(!$found_yyparse) {
    warn "Warning: definition of yyparse() not found,  no modifications made.\n";
    $exitval=2;
}

exit $exitval;
