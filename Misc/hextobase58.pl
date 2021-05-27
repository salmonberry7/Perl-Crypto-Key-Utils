#!/usr/bin/perl
# hextobase58.pl
# ==============
# Converts hex string representing a binary string to Base58 (Bitcoin) encoding of the binary string.
# Follows Bitcoin Base58 alphabet and method of handling leading zero bytes (according to 
# https://en.bitcoin.it/wiki/Base58Check_encoding)
#
# Testing
# =======
# Tested on Perl v5.12.3 on Windows 7
# Beware using on any older Perl version in case a feature is being used not available in that earlier version.
# Newer versions should be OK, so long as they maintain backward compatibility with Perl v5.12.3
#

use strict;
use warnings;

use Crypt::Misc qw(encode_b58b);


# sub check_hex_string
# ====================
# usage: check_hex_string($hex)
# Checks if $hex consists of an even number of hex characters (with no preceding '0x'), exiting the program with 
# error code 1 and an error message if not, otherwise returning to calling procedure taking no action.
sub check_hex_string {
	my $hex = $_[0];

	if ( $hex =~ /[^A-Fa-f0-9]/ ) {
		printf(STDERR "check_hex_string: String contains an invalid hex character\n");
		exit 1;
	}

	my $len = length($hex);
	if ( $len % 2 != 0 ) {
		printf(STDERR "check_hex_string: Invalid length of hex string: %u\nLength must be even, use a preceding zero if needed\n", $len);
		exit 1;
	}
}

# sub hex_to_bin
# ==============
# usage: hex_to_bin($hex)
# Takes a string as input parameter and interprets it as 1 or more pairs of valid hex digits [0-9A-Fa-f]
# (no preceding '0x'). Returns the corresponding binary string of half the length.
# This function is not actually called in this version of the program but is handy for testing.
sub hex_to_bin {
	my $hex = $_[0];

	# note this method works on any valid hex string consisting of 1 or more pairs of valid hex digits [0-9A-Fa-f]
	# because '.' in regex will match EVERY individual character in such a string
	(my $bin = $hex) =~ s/(..)/chr(hex($1))/ge;
	return $bin;
}


if (@ARGV != 1) {
	print(STDERR "Invalid parameters\nUsage: perl hextobase58.pl <hex string>\n");
	exit 1;
}

my $hex = $ARGV[0];
&check_hex_string($hex);

my $bin = &hex_to_bin($hex);

printf("%s\n", encode_b58b($bin));

