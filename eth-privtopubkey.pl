#!/usr/bin/perl
# ethprivtopubkey.pl
# ==================
# Usage :
# see `perl ethprivtopubkey.pl -h'
#
# Testing
# =======
# Tested on Perl v5.12.3 on Windows 7
# Beware using on any older Perl version in case a feature is being used not available in that earlier version.
# Newer versions should be OK, so long as they maintain backward compatibility with Perl v5.12.3
#

use strict;
use warnings;

use Crypt::PK::ECC;

# sub check_hex_priv_key
# ======================
# usage: check_hex_priv_key($hex)
# Checks if $hex consists of 64 hex characters (with no preceding '0x'), exiting the program with 
# error code 1 and an error message if not, otherwise returning the passed in value.
sub check_hex_priv_key {
	my $hex = $_[0];

	if ( $hex =~ /[^A-Fa-f0-9]/ ) {
		printf(STDERR "check_hex_priv_key: String contains an invalid hex character:\n$hex\n");
		exit 1;
	}

	my $len = length($hex);
	if ( $len != 64 ) {
		printf(STDERR "check_hex_priv_key: Hex private key length must be 64:\n$hex\n", $len);
		exit 1;
	}

	return $hex;
}


# sub get_eth_pubkey
# ==================
# usage: get_eth_pubkey($priv_key_bin)
# Accepts an Ethereum private key as 32 byte BINARY string as input and returns the 
# Ethereum public key as a 64 byte long binary string
sub get_eth_pubkey {
	my $priv_key_bin = $_[0];
	my $pub_key;

	# obtain 65 byte long binary string containing uncompressed public key
	my $ecc = Crypt::PK::ECC->new();
	my $curve = "secp256k1";
	$ecc->import_key_raw($priv_key_bin, $curve);

	# note there is a call $ecc->export_key_raw('public_compressed') also available for the compressed public key
	# Here we require the uncompressed form
	$pub_key = $ecc->export_key_raw('public');

	return substr($pub_key, 1, 64);
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


######################################################################################################################
# Main code
######################################################################################################################

use constant BLANKLINE => "\n";

my $priv_key;
my $priv_key_bin;
my $public_key;
my $public_key_hex;

# two separate blocks use this (statefully)
my $param1;

if (@ARGV == 0 || $ARGV[0] eq "-h") {
	print(	"---------------------------------------------------------------\n" .
			"ethprivtopubkey.pl Ethereum private key to public key converter\n" .
			"---------------------------------------------------------------\n" .
			BLANKLINE .
			"Usage:\n" .
			BLANKLINE .
			"To convert Ethereum private key (64 hex digits) to all lower case 128 hex char public key :-\n" . 
			"perl ethprivtopubkey.pl <privkey>\n" .
			BLANKLINE .
			"To take input from a file(s) :-\n" .
			"perl ethprivtopubkey.pl -f <filename1> <filename2> ... \n" .
			"where each <filename> contains a private key 1 per line. Any amount\n" .
			"of white space can appear at the start of a line.\n" .
			BLANKLINE .
			"A <filename> of '-' means the standard input, and an empty list of filenames means\n" .
			"ALL the input is from standard input. Blank lines and lines beginning with '#' in a\n" .
			"file are ignored. 1 line of output is produced for every line of input.\n" .
			BLANKLINE .
			"When input is from the command line the 64 byte public key is also written to a\n" .
			"binary output file pubkey.bin of length 64 bytes.\n"
	);
} elsif ( ($param1 = shift @ARGV) eq "-f" ) {
	# read in all the lines from the input files
	while (<>) {
		chomp;
		/\s*(\S*)/;

		# skip any blank lines in input
		next if ($1 eq "");

		# skip any line beginning with '#'
		next if ( substr($1, 0, 1) eq '#' );

		$priv_key = &check_hex_priv_key($1);
		$priv_key_bin = &hex_to_bin($priv_key);

		$public_key = &get_eth_pubkey($priv_key_bin);
		$public_key_hex = &bin_to_hex($public_key);

		printf("%s\n", lc $public_key_hex );
	}
} else {
	if ( @ARGV != 0 ) {
		print(STDERR "Invalid parameters : run 'perl ethprivtopubkey.pl -h' for usage information.\n");
		exit 1;
	}
	$priv_key = &check_hex_priv_key($param1);
	$priv_key_bin = &hex_to_bin($priv_key);

	$public_key = &get_eth_pubkey($priv_key_bin);
	$public_key_hex = &bin_to_hex($public_key);

	printf("%s\n", lc $public_key_hex );

	if ( !open(FH_OUT, '>', "pubkey.bin") ) {
		die "Cannot open output file: $!";
	}
	binmode FH_OUT;
	print FH_OUT $public_key;
}
