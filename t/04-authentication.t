#!perl -T

use Test::More tests => 7;

use CAS;

# diag( "Testing user authentication $CAS::VERSION, Perl $], $^X" );
my $dir = $ENV{PWD};
my $config = "$dir/CAS.yaml";


# load test client
my $client = new CAS({CLIENT_ID => 0, CONFIG => $config, CLIENT_ID => 0});
ok($client && $client->response_is('CREATED'),
	'Loaded test client');

# fail authentication, wrong username
my $session = $client->authenticate({USERNAME => 'test2',
	PASSWORD => 'testing'});
#warn $client->messages;
ok(! defined $session && $client->response_is('NOT_FOUND'),
	'NOT_FOUND with wrong username provided');

# fail authentication, no username
$session = $client->authenticate({PASWORD => 'testing'});
ok(! defined $session && $client->response_is('BAD_REQUEST'),
	'No username provided');

# fail authentication, wrong password
$session = $client->authenticate({USERNAME => 'tester2',
	PASSWORD => 'foobar'});
#warn $client->messages;
ok(! defined $session && $client->response_is('AUTH_REQUIRED'),
	'AUTH_REQUIRED with wrong password provided');

# try to authenticate disabled user
$session = $client->authenticate({USERNAME => 'tester1',
	PASSWORD => 'testing1'});
#warn $client->messages;
ok(! defined $session && $client->response_is('FORBIDDEN'),
	'FORBIDDEN when User disabled');

# authenticate user
$session = $client->authenticate({USERNAME => 'tester2',
	PASSWORD => 'testing'});
ok(defined $session && $client->response_is('OK'),
	'Test user authenticated');

# confirm user
my $user = $client->user($session);
#warn $client->messages;
my $email = $user->Email;
#warn $user->messages;
ok($email eq 'tester2@foo.com',
	'Authenticated user has expected email address');

__END__

Need to add tests for including IP in authentication
