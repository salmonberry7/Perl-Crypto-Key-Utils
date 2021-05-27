#!/usr/bin/perl
# base58tohex.pl
# ==============
# Decodes Base58 (Bitcoin) string to binary string and outputs hex representation of the binary string.
# Follows Bitcoin Base58 alphabet and method of handling leading zero bytes (according to 
# https://en.bitcoin.it/wiki/Base58Check_encoding)
#
# Issues
# ======
# decode_b58b accepts invalid Base58 (Bitcoin) characters of 0, O, I, l, assigning them same values as valid 
# Base58 (Bitcoin) characters 1, R, K, p respectively. Otherwise this function appears to work.
#
# Testing
# =======
# Tested on Perl v5.12.3 on Windows 7
# Beware using on any older Perl version in case a feature is being used not available in that earlier version.
# Newer versions should be OK, so long as they maintain backward compatibility with Perl v5.12.3
#

use strict;
use warnings;

use Crypt::Misc qw(decode_b58b);

if (@ARGV != 1) {
	print(STDERR "Invalid parameters\nUsage: perl base58tohex.pl <Base58 string>\n");
	exit 1;
}

my $base58 = $ARGV[0];

my $bin = decode_bitcoin_base58($base58);
if ( $bin eq "" ) {
	printf(STDERR "Invalid Base58 string %s\n", $base58);
	exit 1;
}

printf("%s\n", &bin_to_hex($bin));


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

