#!/usr/bin/perl -w

use strict;

unless(@ARGV) {die "Error: no label specified.\n"}
my $label=shift;
unless(@ARGV) {die "Error: no DNS addresses specified.\n"}
my $dns_str=shift;

unless($label =~ /^\".*\"$/) {$label="\"$label\""}
unless($dns_str =~ /^\".*\"$/) {$dns_str="\"$dns_str\""}
unless($dns_str =~ /\"\s*\,\s*\"/) {$dns_str =~ s/\,/","/g}

my $found_label=0;
my $found_ip=0;
my $changed_ip=0;

LOOP:while(<>) {
    print;
    if(/^\s*server\s*\{/) {
	while(<>) {
	    print;
	    if(/^\s*\}/) {next LOOP}
	    if(/^\s*label\s*=\s*\Q$label\E\s*\;/) {
		if(!($found_label++)) {
		    while(<>) {
			if(/^\s*\}/) {
			    if(!$found_ip) {
				print "  ip=$dns_str;\n";
				$changed_ip=1;
			    }
			    print;
			    next LOOP;
			}
			if(/^(\s*ip\s*=\s*)(\"[^"]*\"(?:\s*\,\s*\"[^"]*\")*)\s*\;/) {
			    if(!($found_ip++)) {
				if($2 eq $dns_str) {
				    print;
				}
				else {
				    print "$1$dns_str;$'";
				    $changed_ip=1;
				}
			    }
			    else {
				$changed_ip=1;
			    }
			}
		        else {print}
		    }
		    last LOOP;
	        }
	    }
	}
	last LOOP;
    }
}

if(!$found_label) {
    warn "No server sections labeled $label found.\n";
    exit 2;
}
elsif($found_label>1) {
    warn "Warning: multiple server sections labeled $label found.\n";
    exit 2;
}
elsif(!$found_ip && !$changed_ip) {
    warn "Could not add ip address to section labeled $label.\n";
    exit 2;
}

exit $changed_ip;
