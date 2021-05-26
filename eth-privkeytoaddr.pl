#!/usr/bin/perl
# ethprivkeytoaddr.pl
# ===================
# Usage :
# see `perl ethprivkeytoaddr.pl -h'
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
use Crypt::Digest::Keccak256 qw( keccak256 );


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


# sub apply_EIP55
# ===============
# usage: apply_EIP55($eth_addr)
# Applies EIP-55 'checksum' to supplied Ethereum address, which can have any mixture of letter cases.
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


######################################################################################################################
# Main code
######################################################################################################################

use constant BLANKLINE => "\n";

my $priv_key;
my $priv_key_bin;
my $public_key;
my $eth_addr;

# two separate blocks use this (statefully)
my $param1;

if (@ARGV == 0 || $ARGV[0] eq "-h") {
	print(	"-------------------------------------------------------------\n" .
			"ethprivkeytoaddr.pl Ethereum private key to address converter\n" .
			"-------------------------------------------------------------\n" .
			BLANKLINE .
			"To convert Ethereum private key (64 char hex string) to EIP-55 checksummed Ethereum\n" . 
			"address consisting of 40 hex characters prefixed by '0x'.\n" .
			BLANKLINE .
			"Usage:\n" .
			"perl ethprivkeytoaddr.pl <privkey>\n" .
			BLANKLINE .
			"To take input from a file(s) :-\n" .
			"perl ethprivkeytoaddr.pl -f <filename1> <filename2> ... \n" .
			"where each <filename> contains a private key 1 per line. Any amount\n" .
			"of white space can appear at the start of a line.\n" .
			BLANKLINE .
			"A <filename> of '-' means the standard input, and an empty list of filenames means\n" .
			"ALL the input is from standard input. Blank lines and lines beginning with '#' in a\n" .
			"file are ignored. 1 line of output is produced for every line of input.\n"
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
		$eth_addr = &bin_to_hex( substr( keccak256($public_key), 12, 20 ) );

		printf("%s\n", '0x' . &apply_EIP55($eth_addr) );
	}
} else {
	if ( @ARGV != 0 ) {
		print(STDERR "Invalid parameters : run 'perl ethprivkeytoaddr.pl -h' for usage information.\n");
		exit 1;
	}
	$priv_key = &check_hex_priv_key($param1);
	$priv_key_bin = &hex_to_bin($priv_key);

	$public_key = &get_eth_pubkey($priv_key_bin);
	$eth_addr = &bin_to_hex( substr( keccak256($public_key), 12, 20 ) );

	printf("%s\n", '0x' . &apply_EIP55($eth_addr) );
}
