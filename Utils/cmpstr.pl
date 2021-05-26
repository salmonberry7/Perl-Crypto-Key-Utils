#!/usr/bin/perl
# cmpstr.pl
# =========
# 
# Compare two strings passed in as command line parameters and report "IDENTICAL" if they are identical
# or "DIFFERENT" if they are not identical. Optionally also print the 2 strings one above the other (switch -p).
# Usage:
# perl cmpstr.pl <string1> <string2>
# perl cmpstr.pl -p <string1> <string2>
#
# Testing
# =======
# Tested on Perl v5.12.3 on Windows 7
# Beware using on any older Perl version in case a feature is being used not available in that earlier version.
# Newer versions should be OK, so long as they maintain backward compatibility with Perl v5.12.3
#

use strict;
use warnings;

use constant BLANKLINE => "\n";

my ($string1, $string2, $param1);

if (@ARGV == 0 || $ARGV[0] eq "-h") {
	print(	"---------------------------\n" .
			"cmpstr.pl string comparison\n" .
			"---------------------------\n" .
			BLANKLINE .
			"Usage:\n" .
			BLANKLINE .
			"To compare <string1> and <string2> :-\n" . 
			"perl cmpstr.pl <string1> <string2>\n" .
			BLANKLINE .
			"To compare <string1> and <string2> and print them one above the other :-\n" . 
			"perl cmpstr.pl -p <string1> <string2>\n"
	);
	exit 0;
} elsif ( ($param1 = shift @ARGV) eq "-p" ) {
	if ( @ARGV != 2 ) {
		print(STDERR "Invalid parameters : run 'perl cmpstr.pl -h' for usage information.\n");
		exit 1;
	}
	$string1 = shift @ARGV;
	$string2 = shift @ARGV;
	printf("Compare .....\n%s\n%s\n", $string1, $string2);
} else {
	if ( @ARGV != 1 ) {
		print(STDERR "Invalid parameters : run 'perl cmpstr.pl -h' for usage information.\n");
		exit 1;
	}
	$string1 = $param1;
	$string2 = shift @ARGV;
}

if ($string1 eq $string2) {
	print("=> IDENTICAL\n");
} else {
	print("=> DIFFERENT\n");
}
