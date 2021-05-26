#!/usr/bin/perl

###############################################################################################################
# NOTE: this script was created for Litecoin by adapting the corresponding Bitcoin script privkeytohex.pl 
# See Litecoin Note.txt file for description of the changes.
###############################################################################################################

# litecoinprivkeytohex.pl
# =======================
# Convert Litecoin WIF-compressed or Litecoin WIF-uncompressed private key into 64 character hex string
# representing the binary key.
# Usage :
# see `perl litecoinprivkeytohex.pl -h'
#
# Testing
# =======
# Tested on Perl v5.12.3 on Windows 7
# Beware using on any older Perl version in case a feature is being used not available in that earlier version.
# Newer versions should be OK, so long as they maintain backward compatibility with Perl v5.12.3
#

use strict;
use warnings;

use Crypt::Digest::SHA256 qw(sha256);
use Crypt::Misc qw(decode_b58b);


# sub get_priv_key_bin
# ====================
# Usage : get_priv_key_bin($priv_key)
# Accepts as input a private key in WIF-compressed format (starting with a 'T') or 
# WIF-uncompressed format (starting with a '6'), and returns the corresponding 32 byte long 
# BINARY private key as a binary string.
sub get_priv_key_bin {
	my $priv_key = $_[0];

	my $first_char = substr($priv_key, 0, 1);
	if ( $first_char ne 'T' && $first_char ne '6' ) {
		printf(STDERR "get_priv_key_bin: Private key first character should be 'T' (compressed key),\nor '6' (uncompressed key), found '%s'\n", $first_char);
		exit 1;
	}

	# function decode_bitcoin_base58 returns binary string
	my $priv_key_decode = decode_bitcoin_base58($priv_key);
	if ( $priv_key_decode eq "" ) {
		printf(STDERR "get_priv_key_bin: Unable to Base58 decode private key %s\n", $priv_key);
		exit 1;
	}

	&check_priv_key_decode($priv_key_decode, ($first_char ne '6') );
	return substr($priv_key_decode, 1, 32);
}

# sub check_priv_key_decode
# =========================
# usage: check_priv_key_decode($priv_key_decode, $is_compressed_priv_key)
# Checks whether $priv_key_decode (binary string obtained by Base58 decoding a WIF-compressed or WIF-uncompressed
# format private key) has the correct format below :-
# <0xB0> <32 byte private key> 0x01 <4 checksum bytes>		(compressed)
# <0xB0> <32 byte private key> <4 checksum bytes>			(uncompressed)
# The boolean $is_compressed_priv_key determines whether to check for compressed or uncompressed key.
# Exits the program with error code 1 if an error is detected, otherwise returns to calling procedure taking no action.
sub check_priv_key_decode() {
	my $priv_key_decode = $_[0];
	my $is_compressed_priv_key = $_[1];
	my $error_message;

	my $compression_type = $is_compressed_priv_key ? "compressed" : "uncompressed";

	my $required_length = $is_compressed_priv_key ? 38 : 37;
	my $len = length($priv_key_decode);
	if ( $len ne $required_length ) {
		printf(STDERR "check_priv_key_decode: Invalid length of Base58 decoded WIF-%s private key: %u\nLength must be %u\n", $compression_type, $len, $required_length);
		exit 1;
	}

	my $version_prefix = substr($priv_key_decode, 0, 1);
	if ( $version_prefix ne "\xB0" ) {
		printf(STDERR "check_priv_key_decode: Invalid version prefix in Base58 decoded WIF-%s private key: 0x%s\nVersion prefix 0xB0 required\n", $compression_type, &bin_to_hex($version_prefix) );
		exit 1;
	}

	if ($is_compressed_priv_key) {
		my $compression_suffix = substr($priv_key_decode, 33, 1);
		if ( $compression_suffix ne "\x01" ) {
			printf(STDERR "check_priv_key_decode: Invalid compression suffix in Base58 decoded WIF-compressed private key: 0x%s\nSuffix must be 0x01\n", &bin_to_hex($compression_suffix));
			exit 1;
		}
	}

	# note Crypt::Digest::SHA256 function sha256 always returns a 32 byte long binary string
	# even if there are leading zero bytes
	my $checksum = substr($priv_key_decode, -4);
	my $checksum_calc = substr( sha256(sha256(substr($priv_key_decode, 0, -4))), 0, 4 );

	if ( $checksum_calc ne $checksum ) {
		printf(STDERR "check_priv_key_decode: Invalid checksum in Base58 decoded WIF-%s private key\n", $compression_type);
		exit 1;
	}
}


#####################################################################################################
# NOTE: function decode_bitcoin_base58 identical to Bitcoin version in privkeytohex.pl
#####################################################################################################

# decode_bitcoin_base58
# =====================
# usage: decode_bitcoin_base58($base58_string)
# Takes a string as input parameter and returns :-
# (1) if string is a valid non-null Bitcoin Base58 string, the Bitcoin Base58 decoding of it as a binary string,
# otherwise,
# (2) the empty string
# NOTE: decode_b58b has a bug causing it to accept invalid Bitcoin Base58 characters of 0, O, I, l, assigning 
# them same values as valid Bitcoin Base58 characters 1, R, K, p respectively. Otherwise this function appears 
# to work. (See bug report).
sub decode_bitcoin_base58 {
	my $base58_string = $_[0];

	my $bitcoin_base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	if ($base58_string !~ /^[$bitcoin_base58_alphabet]+$/) {
		return "";
	}

	# function decode_b58b returns binary string
	my $decode = decode_b58b($base58_string);
	if ( !defined($decode) ) {
		return "";
	} else {
		return $decode;
	}
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

my $priv_key;
my $priv_key_bin;
my $priv_key_hex;

# two separate blocks use this (statefully)
my $param1;

if (@ARGV == 0 || $ARGV[0] eq "-h") {
	print(	"--------------------------------------------------------------\n" .
			"litecoinprivkeytohex.pl Litecoin WIF/Hex private key converter\n" .
			"--------------------------------------------------------------\n" .
			BLANKLINE .
			"Usage:\n" .
			BLANKLINE .
			"To convert Litecoin WIF-compressed or WIF-uncompressed private key to 64\n" .
			"character hex string representing the binary key :-\n" .
			"perl litecoinprivkeytohex.pl <key>\n" .
			BLANKLINE .
			"To take input from a file(s) :-\n" .
			"perl litecoinprivkeytohex.pl -f <filename1> <filename2> ... \n" .
			"where each <filename> contains WIF format private keys (compressed or\n" .
			"uncompressed), 1 per line. Any amount of white space can appear at the\n" .
			"start of a line.\n" .
			BLANKLINE .
			"A <filename> of '-' means the standard input, and an empty list of filenames\n" .
			"means ALL the input is from standard input. Blank lines and lines beginning\n" .
			"with '#' in a file are ignored. 1 line of output is produced for every line\n" .
			"of input.\n" .
			BLANKLINE .
			"To process piped output from another program :-\n" .
			"<other program> | perl litecoinprivkeytohex.pl -f\n"
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

		$priv_key = $1;
		$priv_key_bin = &get_priv_key_bin($priv_key);
		$priv_key_hex = &bin_to_hex($priv_key_bin);

		printf("%s\n", $priv_key_hex);
	}
} else {
	if ( @ARGV != 0 ) {
		print(STDERR "Invalid parameters : run 'perl litecoinprivkeytohex.pl -h' for usage information.\n");
		exit 1;
	}
	$priv_key = $param1;
	$priv_key_bin = &get_priv_key_bin($priv_key);
	$priv_key_hex = &bin_to_hex($priv_key_bin);

	printf("%s\n", $priv_key_hex);
}

