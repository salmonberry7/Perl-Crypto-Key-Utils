#!/usr/bin/perl
use strict;
use warnings;

use Crypt::Digest::SHA256 qw(sha256);
use POSIX;


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


# sub seconds_to_dhms
# ===================
# usage: check_hex_string($seconds)
# Converts a number of seconds to the equivalent number of days, hours, minutes, and seconds.
sub seconds_to_dhms {
	use constant SECONDS_IN_DAY => 86400;
	use constant SECONDS_IN_HOUR => 3600;
	use constant SECONDS_IN_MINUTE => 60;

	my $seconds = $_[0];

	my $days = floor($seconds / SECONDS_IN_DAY);
	$seconds = $seconds % SECONDS_IN_DAY;
	my $hours = floor($seconds / SECONDS_IN_HOUR);
	$seconds = $seconds % SECONDS_IN_HOUR;
	my $minutes = floor($seconds / SECONDS_IN_MINUTE);
	$seconds = $seconds % SECONDS_IN_MINUTE;
	return ($days, $hours, $minutes, $seconds);
}


use constant BLANKLINE => "\n";
use constant MAX_PREFIX => 1000000;

if (@ARGV == 0 || $ARGV[0] eq "-h") {
	print(	"-------------\n" .
			"gensha256z.pl\n" .
			"-------------\n" .
			BLANKLINE .
			"Generates a SHA256 hash beginning with <n> zero bytes.\n" .
			BLANKLINE .
			"Usage:\n" .
			"perl gensha256z.pl <n>\n" 
	);
	exit 0;
}

my $num_of_zeros = shift @ARGV;

my $prefix = sprintf("PREFIX__%06u__", floor(rand(MAX_PREFIX)) );
my ($data, $hash);

my $counter = 1;
my $found = 0;
my $start_time = time;
while (!$found) {
	$data = sprintf("$prefix%08u", $counter);
	print("DATA : $data\n");
	
	$hash = sha256($data);

	if ( substr($hash, 0, $num_of_zeros) eq "\x00" x $num_of_zeros ) {
		printf("SHA256 = %s\n", lc &bin_to_hex($hash));
		last;
	}

	$counter++;
}
my $end_time = time;

my $time_duration = $end_time - $start_time;
my ($days, $hours, $minutes, $seconds) = &seconds_to_dhms($time_duration);
printf("time = %s seconds (%s days, %s hours, %s minutes, %s seconds)\n", $time_duration, $days, $hours, $minutes, $seconds);
