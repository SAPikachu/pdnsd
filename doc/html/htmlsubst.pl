#!/usr/bin/perl -w

# Primitive ad-hoc script for updating pdnsd html doc files.
# Written by Paul Rombouts.

use strict;
use integer;
use POSIX qw(strftime);

my $version='';
my $baseurl='';

sub sizeof {
    my($filename)=@_;
    (-f $filename) or return '???';
    (((-s $filename)+1023)/1024).'kB';
}


while(@ARGV && $ARGV[0]=~/^[a-z]\w*=/i) {
    eval "\$$&\"$'\"";
    shift @ARGV;
}

while(<>) {
    s/\$(?:version\b|\{version\})/$version/g;
    s/\$(?:baseurl\b|\{baseurl\})/$baseurl/g;
    s/\$sizeof\(([^()]*)\)/sizeof(eval($1))/eg;
    s/\$(?:date\b|\{date\})/strftime("%d %b %Y",localtime)/eg;
    print;
}
