#!/usr/bin/perl
use strict;
use warnings;

use Crypt::Digest::SHA256 qw(sha256);


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
sub hex_to_bin {
	my $hex = $_[0];

	# note this method works on any valid hex string consisting of 1 or more pairs of valid hex digits [0-9A-Fa-f]
	# because '.' in regex will match EVERY individual character in such a string
	(my $bin = $hex) =~ s/(..)/chr(hex($1))/ge;
	return $bin;
}

# sub bin_to_hex
# ==============
# usage: bin_to_hex($bin)
# Takes a binary string as input parameter and returns equivalent hex string (using upper case A-F)
# of twice the length, with no preceding '0x'. Every byte is converted to a 2 hex digit representation,
# eg byte value 8 -> 08, byte value 254 -> FE
sub bin_to_hex {
	my $bin = $_[0];
	my $hex = "";

	for my $i ( 0..length($bin) - 1 ) {
		my $char = substr($bin, $i, 1);
		$hex .= sprintf("%02X", ord($char));
	}
	return $hex;
}


######################################################################################################################
# Main code
######################################################################################################################

use constant BLANKLINE => "\n";

if (@ARGV == 0 || $ARGV[0] eq "-h") {
	print(	"------------------\n" .
			"hexdoublesha256.pl\n" .
			"------------------\n" .
			BLANKLINE .
			"To calculate double SHA256 hash of a binary string whose hex representation is <data>.\n" .
			"Output hash is in upper case hex, or if option -l is specified, lower case hex.\n" .
			BLANKLINE .
			"Usage:\n" .
			"perl hexdoublesha256.pl [-l] <data>\n" 
	);
	exit 0;
}

my $lower_case;
my $hex = shift @ARGV;

if ( $hex eq "-l" ) {
	$lower_case = 1;
	$hex = shift @ARGV;
} else {
	$lower_case = 0;
}

&check_hex_string($hex);

my $bin = &hex_to_bin($hex);

my $hash = sha256(sha256($bin));
$hash = bin_to_hex($hash);

printf("%s\n", $lower_case ? lc($hash) : $hash );

