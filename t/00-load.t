#!perl -T

use Test::More tests => 5;

BEGIN {
	use_ok( 'CAS::Messaging' );
	use_ok( 'CAS::DB' );
	use_ok( 'CAS::Config' );
	use_ok( 'CAS' );
	use_ok( 'CAS::User' );
}

#diag( "Testing CAS $CAS::VERSION, Perl $], $^X" );
