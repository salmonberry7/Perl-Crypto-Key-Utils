#!/usr/bin/perl
# ethcheckEIP55addr.pl
# ====================
# Usage :
# see `perl ethcheckEIP55addr.pl -h'
#
# Testing
# =======
# Tested on Perl v5.12.3 on Windows 7
# Beware using on any older Perl version in case a feature is being used not available in that earlier version.
# Newer versions should be OK, so long as they maintain backward compatibility with Perl v5.12.3
#

use strict;
use warnings;

use Crypt::Digest::Keccak256 qw( keccak256 );


# sub apply_EIP55
# ===============
# usage: apply_EIP55($eth_addr)
# Applies EIP-55 'checksum' to supplied Ethereum address, which can have any mixture of letter cases.
# Returns the checksummed value.
# Exits program with error code 1 if supplied Ethereum address is not a 40 char hex string.
sub apply_EIP55 {
	my $eth_addr = $_[0];

	if ( $eth_addr =~ /[^A-Fa-f0-9]/ ) {
		printf(STDERR "apply_EIP55: input Ethereum address contains an invalid hex character:\n$eth_addr\n");
		exit 1;
	}

	my $len = length($eth_addr);
	if ( $len != 40 ) {
		printf(STDERR "apply_EIP55: input Ethereum address length must be 40 hex characters:\n$eth_addr\n");
		exit 1;
	}

	my $hex_hash = &bin_to_hex( keccak256(lc $eth_addr) );
	for my $i ( 0..39 ) {
		if ( substr($hex_hash, $i, 1) =~ /[0-7]/ ) {
			substr($eth_addr, $i, 1) = lc substr($eth_addr, $i, 1);
		} else {
			substr($eth_addr, $i, 1) = uc substr($eth_addr, $i, 1);
		}
	}

	return $eth_addr;
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

my $eth_addr;

if (@ARGV == 0 || $ARGV[0] eq "-h") {
	print(	"-----------------------------------------------------\n" .
			"ethcheckEIP55addr.pl Ethereum EIP55 address checker  \n" .
			"-----------------------------------------------------\n" .
			BLANKLINE .
			"Check an Ethereum address (assumed in format of 40 hex characters prefixed by '0x')\n" .
			BLANKLINE .
			"Usage:\n" .
			"perl ethcheckEIP55addr.pl <addr>\n"
	);
} else {
	if ( @ARGV != 1 ) {
		print(STDERR "Invalid parameters : run 'perl ethcheckEIP55addr.pl -h' for usage information.\n");
		exit 1;
	}
	$eth_addr = shift @ARGV;
	$eth_addr = substr($eth_addr, 2, 40);

	if ( $eth_addr eq &apply_EIP55($eth_addr) ) {
		print("Ethereum EIP-55 address is valid\n");
	} else {
		print("Ethereum EIP-55 address is not valid\n");
	}
}
