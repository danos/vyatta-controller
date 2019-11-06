#! /usr/bin/perl

use warnings;
use strict;

use Carp;

use MIME::Base64;
use Google::ProtocolBuffers;

my $target_dir = $ARGV[1];
my $proto_dir = $ARGV[2];
`mkdir -p $target_dir`;

if (substr($ARGV[0], -6) eq ".proto") {
    
    my %options;
    $options{include_dir} = $proto_dir;
    
    my $pb_pm = substr($ARGV[0], 0, length($ARGV[0]) - 6) . ".pm";

    $options{generate_code} = $target_dir . "/$pb_pm";
    $options{create_accessors} = 1;
    Google::ProtocolBuffers->parsefile($proto_dir . "/$ARGV[0]", \%options);
}

exit 0;
