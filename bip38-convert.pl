#!/usr/bin/perl
# bip38convert.pl
# ===============
# Provides functions encrypt_priv_key and decrypt_priv_key for converting from private key to BIP38 encrypted
# private key and vice-versa. Both WIF-compressed private keys (starting with a 'K' or 'L') and WIF-uncompressed 
# private keys (starting with a '5') are supported.
# Both the private key and the BIP38 encrypted private key are in Base58Check encoded forms.
# The output is one line for every line of input.
# Usage:
# perl bip38convert.pl <priv_key> <password>
# perl bip38convert.pl <enc_priv_key> <password>
# perl bip38convert.pl -f <filename1> <filename2> ...
# perl bip38convert.pl -h
# <piped output from other program> | perl bip38convert.pl -f
# perl bip38convert.pl -f < <filename of redirected input>
# (see print statement below)
#
#
# Error checking
# ==============
# It is assumed command line parameters passed in are non-empty strings.
# Base58 strings passed in are checked for correct prefix and validity (ie consist purely of Bitcoin Base58 alphabet characters)
# and using the return value of decode_b58b (= undef if a problem). Once Base58 decoded the binary string is checked
# to have the correct length and format, and the Base58Check checksum is checked. Note decode_b58b has a bug (see below).
# In the case of an encrypted private key a check is made that addresshash and salt match when decrypting. The error
# 'decrypt_priv_key: Encrypted private key salt does not match its bitcoin address addresshash' will (to very high
# probability - ie probability of 1st 4 bytes of a double SHA256 hash being correct for an incorrect bitcoin address) always
# catch an incorrect password for a given encrypted key (because the AES decryption is performed with the wrong password)
# (see proc decrypt_priv_key) (note AES encryption is a 1-1 (ie bijective) mapping from 128 bit numbers to 128 bit 
# numbers - if it was not injective it could not be reversible - it then must also be 'onto' by pigeon-hole principle).
# These checks ensure get_bitcoin_address and get_private_key are always passed a 32 byte binary string as parameter.
# Thus invalidity of the parameters passed in will generally always be detected, but if some highly unusual error was not
# detected there would be some malfunction producing a Perl interpreter error, or no reported error but an invalid output produced.
# When an error is detected, a message is printed (which includes the name of the function where it was found) and the 
# program exits with error code of 1. The Perl 'exit' function is used rather than the 'die' function as the latter
# produces its own exit code.
#
#
# Testing
# =======
# Tested on Perl v5.12.3 on Windows 7
# Beware using on any older Perl version in case a feature is being used not available in that earlier version.
# Newer versions should be OK, so long as they maintain backward compatibility with Perl v5.12.3
#
#
# List of Functions
# =================
# encrypt_priv_key
# decrypt_priv_key
# get_priv_key_bin
# check_priv_key_decode
# check_enc_priv_key_decode
# get_bitcoin_address
# get_private_key
# decode_bitcoin_base58
# hex_to_bin
# bin_to_hex
#

use strict;
use warnings;

use Crypt::Digest::SHA256 qw(sha256);
use Crypt::Digest::RIPEMD160 qw(ripemd160);
use Crypt::ScryptKDF qw(scrypt_raw);
use Crypt::Cipher::AES;
use Crypt::PK::ECC;
use Crypt::Misc qw(decode_b58b encode_b58b);

# sub encrypt_priv_key
# ====================
# Usage : encrypt_priv_key($priv_key, $password)
# Accepts a WIF-compressed format private key (starting with a 'K' or 'L') or a WIF-uncompressed 
# private key (starting with a '5'), and password as input and returns the corresponding BIP38 encrypted 
# private key.
# The returned encrypted private key is Base58Check encoded with Version Prefix 0x0142,
# as specified in BIP38, and always starts with '6PY' for a compressed private key, and '6PR'
# for an uncompressed private key
sub encrypt_priv_key {
	my $priv_key = $_[0];
	my $password = $_[1];
	my $is_compressed;

	my $priv_key_bin = &get_priv_key_bin($priv_key);

	$is_compressed = substr($priv_key, 0, 1) ne '5';

	# to have reached here must have $priv_key_bin as a 32 byte binary string
	my $bitcoin_address = &get_bitcoin_address($priv_key_bin, $is_compressed);

	# note Crypt::Digest::SHA256 function sha256 always returns a 32 byte long binary string
	# even if there are leading zero bytes
	my $salt = substr( sha256(sha256($bitcoin_address)), 0, 4 );

	# parameters passed to scrypt function are as defined in BIP38
	my $key = scrypt_raw($password, $salt, 16384, 8, 8, 64);

	my $derivedhalf1 = substr($key, 0, 32);
	my $derivedhalf2 = substr($key, 32, 32);

	my $AES_cipher = Crypt::Cipher::AES->new($derivedhalf2);
	my $encryptedhalf1 = $AES_cipher->encrypt( substr($priv_key_bin, 0, 16) ^ substr($derivedhalf1, 0, 16) );
	my $encryptedhalf2 = $AES_cipher->encrypt( substr($priv_key_bin, 16, 16) ^ substr($derivedhalf1, 16, 16) );

	my $flagbyte = $is_compressed ? "\xE0" : "\xC0";

	my $payload = $flagbyte . $salt . $encryptedhalf1 . $encryptedhalf2;

	# add version prefix to payload
	my $payload_encode = "\x01\x42$payload";

	# append checksum to payload
	# note Crypt::Digest::SHA256 function sha256 always returns a 32 byte long binary string
	# even if there are leading zero bytes
	my $checksum = sha256( sha256($payload_encode) );
	$payload_encode .= substr($checksum, 0, 4);

	return encode_b58b($payload_encode);
}

# sub decrypt_priv_key
# ====================
# Usage : decrypt_priv_key($enc_priv_key, $password)
# Accepts a BIP38 encrypted compressed private key (starting with '6PY') or a BIP38 encrypted 
# uncompressed private key (starting with '6PR'), and password as input and returns the
# corresponding WIF-compressed format private key (starting with a 'K' or 'L') or WIF-uncompressed 
# format private key (starting with a '5'), respectively.
sub decrypt_priv_key {
	my $enc_priv_key = $_[0];
	my $password = $_[1];
	my $is_compressed;

	my $prefix = substr($enc_priv_key, 0, 3);
	if ( $prefix ne '6PY' && $prefix ne '6PR' ) {
		printf(STDERR "decrypt_priv_key: Encrypted private key prefix should be '6PY' or '6PR', found '%s'\n", $prefix);
		exit 1;
	}

	$is_compressed = ($prefix eq '6PY');

	# function decode_bitcoin_base58 returns a binary string
	my $enc_priv_key_decode = decode_bitcoin_base58($enc_priv_key);
	if ( $enc_priv_key_decode eq "" ) {
		printf(STDERR "decrypt_priv_key: Unable to Base58 decode encrypted private key %s\n", $enc_priv_key);
		exit 1;
	}

	&check_enc_priv_key_decode($enc_priv_key_decode, $is_compressed);

	my $salt = substr($enc_priv_key_decode, 3, 4);
	my $encryptedhalf1 = substr($enc_priv_key_decode, 7, 16); 
	my $encryptedhalf2 = substr($enc_priv_key_decode, 23, 16); 

	# parameters passed to scrypt function are as defined in BIP38
	my $key = scrypt_raw($password, $salt, 16384, 8, 8, 64);

	my $derivedhalf1 = substr($key, 0, 32);
	my $derivedhalf2 = substr($key, 32, 32);

	my $AES_cipher = Crypt::Cipher::AES->new($derivedhalf2);
	my $decryptedhalf1 = $AES_cipher->decrypt($encryptedhalf1);
	my $decryptedhalf2 = $AES_cipher->decrypt($encryptedhalf2);

	my $priv_key_half1 = $decryptedhalf1 ^ substr($derivedhalf1, 0, 16);
	my $priv_key_half2 = $decryptedhalf2 ^ substr($derivedhalf1, 16, 16);

	my $priv_key_bin = $priv_key_half1 . $priv_key_half2;

	# to have reached here $priv_key_bin must be a 32 byte binary string
	my $bitcoin_address = &get_bitcoin_address($priv_key_bin, $is_compressed);

	# note Crypt::Digest::SHA256 function sha256 always returns a 32 byte long binary string
	# even if there are leading zero bytes
	my $addresshash = substr( sha256(sha256($bitcoin_address)), 0, 4 );

	if ($addresshash ne $salt) {
		printf(	STDERR
				"decrypt_priv_key: Encrypted private key salt does not match its bitcoin address addresshash\n" . 
				"Possible causes: incorrect password or incorrect BIP38 encryption\n"
		);
		exit 1;
	}

	return &get_private_key($priv_key_bin, $is_compressed);
}

# sub get_priv_key_bin
# ====================
# Usage : get_priv_key_bin($priv_key)
# Accepts as input a private key in WIF-compressed format (starting with a 'K' or 'L') or 
# WIF-uncompressed format (starting with a '5'), and returns the corresponding 32 byte long 
# BINARY private key as a binary string.
sub get_priv_key_bin {
	my $priv_key = $_[0];

	my $first_char = substr($priv_key, 0, 1);
	if ( $first_char ne 'K' && $first_char ne 'L' && $first_char ne '5') {
		printf(STDERR "get_priv_key_bin: Private key first character should be 'K' or 'L' (compressed key),\nor '5' (uncompressed key), found '%s'\n", $first_char);
		exit 1;
	}

	# function decode_bitcoin_base58 returns binary string
	my $priv_key_decode = decode_bitcoin_base58($priv_key);
	if ( $priv_key_decode eq "" ) {
		printf(STDERR "get_priv_key_bin: Unable to Base58 decode private key %s\n", $priv_key);
		exit 1;
	}

	&check_priv_key_decode($priv_key_decode, ($first_char ne '5') );
	return substr($priv_key_decode, 1, 32);
}

# sub check_priv_key_decode
# =========================
# usage: check_priv_key_decode($priv_key_decode, $is_compressed_priv_key)
# Checks whether $priv_key_decode (binary string obtained by Base58 decoding a WIF-compressed or WIF-uncompressed
# format private key) has the correct format below :-
# <0x80> <32 byte private key> 0x01 <4 checksum bytes>		(compressed)
# <0x80> <32 byte private key> <4 checksum bytes>			(uncompressed)
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
	if ( $version_prefix ne "\x80" ) {
		printf(STDERR "check_priv_key_decode: Invalid version prefix in Base58 decoded WIF-%s private key: 0x%s\nVersion prefix 0x80 required\n", $compression_type, &bin_to_hex($version_prefix) );
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

# sub check_enc_priv_key_decode
# =============================
# usage: check_enc_priv_key_decode($enc_priv_key_decode, $is_compressed_priv_key)
# Checks whether $enc_priv_key_decode (binary string obtained by Base58 decoding a BIP38 encrypted compressed
# or uncompressed private key) has the correct format below :-
# 0x01 0x42 <flagbyte=0xE0> <4 byte salt> <16 byte encryptedhalf1> <16 byte encryptedhalf2> <4 checksum bytes>		(compressed)
# 0x01 0x42 <flagbyte=0xC0> <4 byte salt> <16 byte encryptedhalf1> <16 byte encryptedhalf2> <4 checksum bytes>		(uncompressed)
# The boolean $is_compressed_priv_key determines whether to check for compressed or uncompressed.
# Exits the program with error code 1 if an error is detected, otherwise returns to calling procedure taking no action.
sub check_enc_priv_key_decode() {
	my $enc_priv_key_decode = $_[0];
	my $is_compressed_priv_key = $_[1];

	my $compression_type = $is_compressed_priv_key ? "compressed" : "uncompressed";

	my $len = length($enc_priv_key_decode);
	if ( $len != 43 ) {
		printf(STDERR "check_enc_priv_key_decode: Invalid length of Base58 decoded BIP38 encrypted %s private key: %u\nLength must be 43\n", $compression_type, $len);
		exit 1;
	}

	my $version_prefix = substr($enc_priv_key_decode, 0, 2);
	if ( $version_prefix ne "\x01\x42" ) {
		printf(STDERR "check_enc_priv_key_decode: Invalid version prefix in Base58 decoded BIP38 encrypted %s private key: 0x%s\nVersion prefix 0x0142 required\n", $compression_type, &bin_to_hex($version_prefix));
		exit 1;
	}

	my $flagbyte = substr($enc_priv_key_decode, 2, 1);

	if ($is_compressed_priv_key) {
		if ( $flagbyte ne "\xE0" ) {
			printf(STDERR "check_enc_priv_key_decode: Invalid flag byte in Base58 decoded BIP38 encrypted compressed private key: 0x%s\nFlag byte 0xE0 required\n", &bin_to_hex($flagbyte));
			exit 1;
		}
	} else {
		if ( $flagbyte ne "\xC0" ) {
			printf(STDERR "check_enc_priv_key_decode: Invalid flag byte in Base58 decoded BIP38 encrypted uncompressed private key: 0x%s\nFlag byte 0xC0 required\n", &bin_to_hex($flagbyte));
			exit 1;
		}
	}

	# note Crypt::Digest::SHA256 function sha256 always returns a 32 byte long binary string
	# even if there are leading zero bytes
	my $checksum = substr($enc_priv_key_decode, -4);
	my $checksum_calc = substr( sha256(sha256(substr($enc_priv_key_decode, 0, -4))), 0, 4 );

	if ( $checksum_calc ne $checksum ) {
		printf(STDERR "check_enc_priv_key_decode: Invalid checksum in Base58 decoded BIP38 encrypted %s private key\n", $compression_type);
		exit 1;
	}
}

# sub get_bitcoin_address
# =======================
# usage: get_bitcoin_address($priv_key_bin, $is_compressed_priv_key)
# Accepts a private key as 32 byte BINARY string as input and returns the Base58Check encoded compressed or 
# uncompressed Bitcoin address for it (according as $is_compressed_priv_key is true or false). The returned 
# Bitcoin address always starts with a '1'. Approx 1 out of 256 times the Bitcoin address starts 
# with '11', approx 1 out of 256^2 times it starts with '111', & etc. Assumes a 32 byte binary string is 
# passed as input.
sub get_bitcoin_address {
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

	# Base58Check encode compressed/uncompressed public key into Bitcoin address.
	# Note Crypt::Digest::SHA256 function sha256 always returns a 32 byte long binary string
	# even if there are leading zero bytes and
	# Crypt::Digest::RIPEMD160 function ripemd160 always returns a 20 byte long binary string
	# even if there are leading zero bytes
	my $raw_bitcoin_address = ripemd160(sha256($pub_key));
	my $raw_bitcoin_address_encode = "\x00$raw_bitcoin_address";
	my $checksum = sha256( sha256($raw_bitcoin_address_encode) );
	$raw_bitcoin_address_encode .= substr($checksum, 0, 4);
	return encode_b58b($raw_bitcoin_address_encode);
}

# sub get_private_key
# ===================
# usage: get_private_key($priv_key_bin, $is_compressed_priv_key)
# Accepts a private key as 32 byte BINARY string as input and returns the Base58Check encoded WIF-compressed 
# or WIF-uncompressed private key, according as $is_compressed_priv_key is true or false.
# The returned private key always starts with a 'K' or 'L' (compressed key) or a '5' (uncompressed key).
# Assumes a 32 byte binary string is passed as input.
sub get_private_key {
	my $priv_key_bin = $_[0];
	my $is_compressed_priv_key = $_[1];

	my $private_key_encode = "\x80$priv_key_bin";
	if ($is_compressed_priv_key) {
		$private_key_encode .= "\x01";
	}
	my $checksum = sha256( sha256($private_key_encode) );
	$private_key_encode .= substr($checksum, 0, 4);
	return encode_b58b($private_key_encode);
}

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


######################################################################################################################
# Main code
######################################################################################################################

use constant BLANKLINE => "\n";

# could have made $password a state variable within the 'while' loop, but just made it global as an 'else'
# block uses it also (independently)
my $password;

# two separate blocks use this (independently)
my $firstchar;

# two separate blocks use this (statefully)
my $param1;

if (@ARGV == 0 || $ARGV[0] eq "-h") {
	print(	"------------------------------------------\n" .
			"bip38convert.pl BIP38 encrypt/decrypt tool\n" .
			"------------------------------------------\n" .
			BLANKLINE .
			"Usage:\n" .
			BLANKLINE .
			"To BIP38 encrypt <priv_key> with <password> :-\n" . 
			"perl bip38convert.pl <priv_key> <password>\n" .
			"where <priv_key> = private key in Base58Check encoded format (starts\n" .
			"with 'K' or 'L' for compressed key, or with '5' for uncompressed key).\n" .
			BLANKLINE .
			"To BIP38 decrypt <enc_priv_key> with <password> :-\n" .
			"perl bip38convert.pl <enc_priv_key> <password>\n" .
			"where <enc_priv_key> = BIP38 encrypted private key in Base58Check encoded format\n" .
			"(starts with '6PY' for compressed key, or with '6PR' for uncompressed key)\n" .
			BLANKLINE .
			"To take input from a file(s) :-\n" .
			"perl bip38convert.pl -f <filename1> <filename2> ... \n" .
			"where each <filename> consists potentially of both of the following\n" .
			"line forms :-\n" .
			"<priv_key> <password>\n" .
			"and\n" .
			"<enc_priv_key> <password>.\n" .
			"A <filename> of '-' means the standard input, and an empty list of\n" .
			"filenames means ALL the input is from standard input. Blank lines and\n" .
			"lines beginning with '#' in a file are ignored. Any amount of white\n" .
			"space can be at the start of a line or between the two items on a line.\n" .
			"1 line of output is produced for every line of input.\n" .
			BLANKLINE .
			"To process piped output from another program :-\n" .
			"<other program> | perl bip38convert.pl -f\n" .
			BLANKLINE .
			"If a <password> is omitted on a line in an input file then the nearest\n" .
			"previous password is used (the first line of the first file must thus\n" .
			"always contain a password). This allows blocks of keys with a common\n" .
			"password to be easily specified.\n" .
			"For the first line form, BIP38 encryption of the private key <priv_key>\n" .
			"is performed. For the second line form, decryption of the BIP38 encrypted\n" .
			"private key <enc_priv_key> is performed.\n" .
			BLANKLINE .
			"Supports passwords containing non-whitespace characters only (ie Perl\n" .
			"regex \\S characters).\n" .
			BLANKLINE .
			"Beware certain password characters will not function as expected due\n" . 
			"to interpolation within the Perl program (eg \$, \@, \\) or within the\n" .
			"command line (eg \", <, >, |). To avoid confusion with different\n" . 
			"character encodings use printable ASCII characters only or just\n" .
			"alphanumeric characters.\n"
	);
} elsif ( ($param1 = shift @ARGV) eq "-f" ) {
	# read in all the lines from the input files
	while (<>) {
		# note this loop uses the global var $password to retain value between invocations
		# ('else' block below uses it also separately)
		chomp;
		/\s*(\S*)\s*(\S*)/;

		# skip any blank lines in input
		next if ($1 eq "");

		# skip any line beginning with '#'
		next if ( substr($1, 0, 1) eq '#' );

		if ($2 ne "") {
			# a password was specified on the current line so update $password
			$password = $2;
		}

		# must always have a defined $password, so 1st line of 1st input file must have a password
		# All other lines may or may not have a password
		if ( !defined($password) ) {
			printf(STDERR "First input file does not specify a password on first line\n");
			exit 1;
		}

		$firstchar = substr($1, 0, 1);
		if ( $firstchar eq 'K' || $firstchar eq 'L' || $firstchar eq '5' ) {
			printf("%s\n", &encrypt_priv_key($1, $password) );
		} else {
			printf("%s\n", &decrypt_priv_key($1, $password) );
		}
	}
} else {
	if ( @ARGV != 1 ) {
		print(STDERR "Invalid parameters : run 'perl bip38convert.pl -h' for usage information.\n");
		exit 1;
	}
	my $key = $param1;
	$password = shift @ARGV;
	$firstchar = substr($key, 0, 1);
	my $prefix = substr($key, 0, 3);

	if ( $firstchar eq 'K' || $firstchar eq 'L' || $firstchar eq '5' ) {
		printf("%s\n", &encrypt_priv_key($key, $password) );
	} elsif ( $prefix eq '6PY' || $prefix eq '6PR' ) {
		printf("%s\n", &decrypt_priv_key($key, $password) );
	} else {
		printf(STDERR "Specify a WIF private key (starting 'K' or 'L' or '5') or BIP38 encrypted private key (starting '6PY' or '6PR')\n");
		exit 1;
	}
}

