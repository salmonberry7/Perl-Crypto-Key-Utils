#!/usr/bin/perl
# secp256k1.pl
# ============
# Convert 32-byte secp256k1 private key into corresponding compressed/uncompressed form of public key (33/65 bytes)
# Usage :
# see `perl secp256k1.pl -h'
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


# get_compression_switch
# ======================
# usage: get_compression_switch($switch)
# Returns true or false according as $switch on command line or in input file denotes compressed
# or uncompressed public key.
# Although in help message switches are specified as being preceded by '--' or '-' on command line, 
# and not preceded by these in input file, both forms are accepted in both cases.
# ie valid switches for WIF-compressed private key are :-
# --compressed, -c, compressed, c
# and valid switches for WIF-uncompressed private key are :-
# --uncompressed, -u, uncompressed, u
# Exits program with error code 1 and an error message if $switch is invalid.
sub get_compression_switch {
	my $switch = $_[0];

	if ($switch eq "--compressed" || $switch eq "-c" || $switch eq "compressed" || $switch eq "c") {
		return 1;
	} elsif ($switch eq "--uncompressed" || $switch eq "-u" || $switch eq "uncompressed" || $switch eq "u") {
		return 0;
	} else {
		printf(STDERR "get_compression_switch: Invalid compressed/uncompressed switch : %s\nrun 'perl secp256k1.pl -h' for usage information.\n", $switch);
		exit 1;
	}
}

# sub check_hex_string
# ====================
# usage: check_hex_string($hex)
# Checks if $hex is a 64 character hex string (with no preceding '0x'), exiting the program with error code 1 and an 
# error message if not, otherwise returning to calling procedure taking no action.
sub check_hex_string {
	my $hex = $_[0];

	if ( $hex !~ /^[A-Fa-f0-9]+$/ ) {
		printf(STDERR "check_hex_string: String contains an invalid hex character\n");
		exit 1;
	}

	my $len = length($hex);
	if ( $len != 64 ) {
		printf(STDERR "check_hex_string: Invalid length of hex string: %u\nLength must be 64\n", $len);
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

# sub get_public_key
# ==================
# usage: get_public_key($priv_key_bin, $is_compressed_priv_key)
# Accepts a private key as 32 byte BINARY string as input and returns the corresponding compressed/uncompressed form 
# of public key as a 33/65 byte binary string.
# Assumes a 32 byte binary string is passed as input, and this is a valid secp256k1 private key,
# ie integer in the range [1, n - 1], where n = order of generator point G of secp256k1 elliptic curve
# (= order N of elliptic curve group E itself as cofactor h = 1). G, n, h are parameters specified in secp256k1.
# n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141.
sub get_public_key {
	my $priv_key_bin = $_[0];
	my $is_compressed_priv_key = $_[1];
	my $pub_key;

	# obtain 33 (or 65) byte long binary string containing compressed (or uncompressed) public key
	my $ecc = Crypt::PK::ECC->new();
	my $curve = "secp256k1";
	$ecc->import_key_raw($priv_key_bin, $curve);
	if ($is_compressed_priv_key) {
		$pub_key = $ecc->export_key_raw('public_compressed');
	} else {
		$pub_key = $ecc->export_key_raw('public');
	}

	return $pub_key;
}


######################################################################################################################
# Main code
######################################################################################################################

use constant BLANKLINE => "\n";

# could have made $compression_flag a state variable within the 'while' loop, but just made it global as an 'else'
# block uses it also (independently)
my $compression_flag;

# two separate blocks use this (independently)
my $hex;

# two separate blocks use this (statefully)
my $param1;

if (@ARGV == 0 || $ARGV[0] eq "-h") {
	print(	"------------------------------------------------\n" .
			"secp256k1.pl private key to public key converter\n" .
			"------------------------------------------------\n" .
			BLANKLINE .
			"Usage:\n" .
			BLANKLINE .
			"To convert 64 character hex private key <hex> to 33-byte compressed public key :-\n" . 
			"perl secp256k1.pl --compressed|-c <hex>\n" .
			BLANKLINE .
			"To convert 64 character hex private key <hex> to 65-byte uncompressed public key :-\n" . 
			"perl secp256k1.pl --uncompressed|-u <hex>\n" .
			BLANKLINE .
			"The hex string should not have any '0x' prefix. The max hex key value is n - 1 =\n" .
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140, where n is the\n" .
			"parameter specified in secp256k1. The minimum key value is 1.\n" .
			BLANKLINE .
			"To take input from a file(s) :-\n" .
			"perl secp256k1.pl -f <filename1> <filename2> ... \n" .
			"where each <filename> consists potentially of both of the following line forms :-\n" .
			"<hex> compressed|c\n" .
			"and\n" .
			"<hex> uncompressed|u.\n" .
			"A <filename> of '-' means the standard input, and an empty list of filenames means\n" .
			"ALL the input is from standard input. Blank lines and lines beginning with '#' in\n" .
			"a file are ignored. Any amount of white space can be at the start of a line or \n" .
			"between the two items on a line. 1 line of output is produced for every line of input.\n" .
			BLANKLINE .
			"To process piped output from another program :-\n" .
			"<other program> | perl secp256k1.pl -f\n" .
			BLANKLINE .
			"If the compressed/uncompressed switch is omitted on a line in an input file then the\n" .
			"nearest previous switch is used (the first line of the first file must thus always\n" .
			"contain a switch). For the first line form, a compressed public key is created.\n" .
			"For the second line form, an uncompressed public key is created.\n"
	);
} elsif ( ($param1 = shift @ARGV) eq "-f" ) {
	# read in all the lines from the input files
	while (<>) {
		# note this loop uses the global var $compression_flag to retain value between invocations
		# ('else' block below uses it also separately)
		chomp;
		/\s*(\S*)\s*(\S*)/;

		# skip any blank lines in input
		next if ($1 eq "");

		# skip any line beginning with '#'
		next if ( substr($1, 0, 1) eq '#' );

		$hex = $1;
		&check_hex_string($hex);
		if ($2 ne "") {
			# a compressed/uncompressed switch was specified on the current line
			# so update $compression_flag
			$compression_flag = &get_compression_switch($2);
		}

		# must always have a defined $compression_flag, so 1st line of 1st input file must have a
		# compressed/uncompressed switch. All other lines may or may not have this switch.
		if ( !defined($compression_flag) ) {
			printf(STDERR "First input file does not specify a compressed/uncompressed switch on first line\n");
			exit 1;
		}

		printf("%s\n", &bin_to_hex(&get_public_key(&hex_to_bin($hex), $compression_flag)) );
	}
} else {
	if ( @ARGV != 1 ) {
		print(STDERR "Invalid parameters : run 'perl secp256k1.pl -h' for usage information.\n");
		exit 1;
	}
	$compression_flag = &get_compression_switch($param1);
	$hex = shift @ARGV;
	&check_hex_string($hex);

	printf("%s\n", &bin_to_hex(&get_public_key(&hex_to_bin($hex), $compression_flag)) );
}

