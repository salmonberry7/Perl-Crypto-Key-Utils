#!/usr/bin/perl
# sha256.pl
# =========
# Usage :
# see `perl sha256.pl -h'
#
# Testing
# =======
# Tested on Perl v5.12.3 on Windows 7
# Beware using on any older Perl version in case a feature is being used not available in that earlier version.
# Newer versions should be OK, so long as they maintain backward compatibility with Perl v5.12.3
#
# Performance
# ===========
# Compared sha256 of 1GB file with this tool on Windows 7 and sha256sum on Ubuntu Linux :-
# This tool => approx 8 secs, sha256sum => approx 7 secs
#
# Notes
# =====
# Globbing works on Linux
#


use strict;
use warnings;

use Crypt::Digest::SHA256 qw(sha256 sha256_file);


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
	print(	"----------------------------------------\n" .
			"sha256.pl compute SHA256 hash of file(s)\n" .
			"----------------------------------------\n" .
			BLANKLINE .
			"Usage:\n" .
			"perl sha256.pl [-f] <filename1> <filename2> ...\n" .
			BLANKLINE .
			"Switch -f prints file names to the right of the hash values.\n"
	);
} else {
	my $param1;
	my $print_filenames;

	if ( ($param1 = shift @ARGV) eq "-f" ) {
		$print_filenames = 1;
	} else {
		$print_filenames = 0;
	}

	if ( !$print_filenames ) {
		unshift(@ARGV, $param1);
	}

	while (@ARGV > 0) {
		my $filename = shift @ARGV;

		# alt method
#		if ( !open(FH, '<', $filename) ) {
#			die "Cannot open file $filename: $!";
#		}
#		binmode FH;
#		local $/;
#		my $bin = <FH>;
#		close FH;
#		my $sha256 = sha256($bin);
#		printf("%s%s\n", lc &bin_to_hex($sha256), $print_filenames ? "\t$filename" : "" );

		# main method
		printf("%s%s\n", lc &bin_to_hex( sha256_file($filename) ), $print_filenames ? "\t$filename" : "" );
	}
}
