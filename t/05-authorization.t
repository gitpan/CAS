#!perl -T

use Test::More tests => 28;

use CAS;

# diag( "Testing user authorization $CAS::VERSION, Perl $], $^X" );
my $dir = $ENV{PWD};
my $config = "$dir/CAS.yaml";


# load test client
$client = new CAS({CLIENT_ID => 0, CONFIG => $config, CLIENT_ID => 0});
ok($client && $client->response_is('CREATED'),
	'Loaded test client');

# authenticate user 2
my $session2 = $client->authenticate({USERNAME => 'tester2',
	PASSWORD => 'testing'});
ok(defined $session2 && $client->response_is('OK'),
	'Test user 2 authenticated');

# authenticate user 3
my $session3 = $client->authenticate({USERNAME => 'tester3',
	PASSWORD => 'testing'});
ok(defined $session3 && $client->response_is('OK'),
	'Test user 3 authenticated');

my $t2_id = $client->user($session2)->ID;
ok($t2_id =~ /\d+/, 'Able to get tester2 ID');
my $t3_id = $client->user($session3)->ID;
ok($t3_id =~ /\d+/, 'Able to get tester3 ID');
my $group_id = $client->client->{Default_Group};
ok($group_id =~ /\d+/, 'Able to get group ID');


##
## until there is an admin module to hadle these functions, we'll
## add a bunch of permissions here
##
my $dbh = $client->dbh;

# grant read permissions on test resource0 for user 2 & 3
$dbh->do("INSERT INTO Permissions (User, Resource, Permissions)
	VALUES ($t2_id, 'resource0', 8), ($t3_id, 'resource0', 8)");

# grant create permissions on test resource1 for user 3
$dbh->do("INSERT INTO Permissions (User, Resource, Permissions)
	VALUES ($t3_id, 'resource1', 2)");

# grant modify permissions on test resource2 for user 3
$dbh->do("INSERT INTO Permissions (User, Resource, Permissions)
	VALUES ($t3_id, 'resource2', 4)");

# grant delete permissions on test resource3 for user 3
$dbh->do("INSERT INTO Permissions (User, Resource, Permissions)
	VALUES ($t3_id, 'resource3', 1)");

# grant read + modify permissions on test resource4 for user 3
$dbh->do("INSERT INTO Permissions (User, Resource, Permissions)
	VALUES ($t3_id, 'resource4', 12)");

# grant read permissions on test resource5 for group users
$dbh->do("INSERT INTO Permissions (GroupID, Resource, Permissions)
	VALUES ($group_id, 'resource5', 8)");

##
## back to testing
##


# fail authorization to modify on resource0 for user 2
my $rc = $client->authorize({SESSION => $session2,
	RESOURCE => 'resource1', MASK => 'modify'});
ok(! defined $rc && $client->response_is('FORBIDDEN'),
	'testing2 not authorized to modify on resource1');

# fail authorization to read on resource1 for user 2
$rc = $client->authorize({SESSION => $session2,
	RESOURCE => 'resource1', MASK => 'read'});
ok(! defined $rc && $client->response_is('FORBIDDEN'),
	'testing2 not authorized to read on resource1');

# fail authorization to create on resource1 for user 2
$rc = $client->authorize({SESSION => $session2,
	RESOURCE => 'resource1', MASK => 'create'});
ok(! defined $rc && $client->response_is('FORBIDDEN'),
	'testing2 not authorized to create on resource1');

# fail authorization to delete on resource1 for user 2
$rc = $client->authorize({USER => $session2,
	RESOURCE => 'resource1', MASK => 'delete'});
ok(! defined $rc && $client->response_is('FORBIDDEN'),
	'testing2 not authorized to delete on resource1');

# pass authorization to read on resource0 for user 2
$rc = $client->authorize({USER => $session2,
	RESOURCE => 'resource0', PERMISSION => 'read'});
#warn $client->messages;
ok($client->response_is('OK'),
	'testing2 authorized to read on resource0');


# fail authorization to modify on resource0 for user 3
$rc = $client->authorize({SESSION => $session3,
	RESOURCE => 'resource0', PERMISSION => 'modify'});
ok(! defined $rc && $client->response_is('FORBIDDEN'),
	'testing3 not authorized to modify on resource0');

# pass authorization to read on resource0 for user 3
$rc = $client->authorize({SESSION => $session3,
	RESOURCE => 'resource0', PERMISSION => 'read'});
ok($client->response_is('OK'),
	'testing3 authorized to read on resource0');

# fail authorization to read on resource1 for user 3
$rc = $client->authorize({SESSION => $session3,
	RESOURCE => 'resource1', PERMISSION => 'read'});
ok(! defined $rc && $client->response_is('FORBIDDEN'),
	'testing3 not authorized to read on resource1');

# pass authorization to create on resource1 for user 3
$rc = $client->authorize({SESSION => $session3,
	RESOURCE => 'resource1', PERMISSION => 'create'});
ok($client->response_is('OK'),
	'testing3 authorized to create on resource1');

# fail authorization to delete on resource2 for user 3
$rc = $client->authorize({SESSION => $session3,
	RESOURCE => 'resource2', PERMISSION => 'delete'});
ok(! defined $rc && $client->response_is('FORBIDDEN'),
	'testing3 not authorized to delete on resource2');

# pass authorization to modify on resource2 for user 3
$rc = $client->authorize({SESSION => $session3,
	RESOURCE => 'resource2', PERMISSION => 'modify'});
ok($client->response_is('OK'),
	'testing3 authorized to modify on resource2');

# fail authorization to read on resource3 for user 3
$rc = $client->authorize({SESSION => $session3,
	RESOURCE => 'resource3', PERMISSION => 'read'});
ok(! defined $rc && $client->response_is('FORBIDDEN'),
	'testing3 not authorized to read on resource3');

# pass authorization to delete on resource3 for user 3
$rc = $client->authorize({SESSION => $session3,
	RESOURCE => 'resource3', PERMISSION => 'delete'});
ok($client->response_is('OK'),
	'testing3 authorized to delete on resource3');

# fail authorization to delete on resource4 for user 3
$rc = $client->authorize({SESSION => $session3,
	RESOURCE => 'resource4', PERMISSION => 'delete'});
ok(! defined $rc && $client->response_is('FORBIDDEN'),
	'testing3 not authorized to delete on resource4');

# pass authorization to read on resource4 for user 3
$rc = $client->authorize({SESSION => $session3,
	RESOURCE => 'resource4', PERMISSION => 'read'});
ok($client->response_is('OK'),
	'testing3 authorized to read on resource4');

# pass authorization to modify on resource4 for user 3
$rc = $client->authorize({SESSION => $session3,
	RESOURCE => 'resource4', PERMISSION => 'modify'});
ok($client->response_is('OK'),
	'testing3 authorized to modify on resource4');

# pass authorization to read & modify on resource4 for user 3
$rc = $client->authorize({SESSION => $session3,
	RESOURCE => 'resource4', MASK => '12'});
ok($client->response_is('OK'),
	'testing3 authorized to read & modify on resource4');

# pass authorization to read on resource5 for user 3
$rc = $client->authorize({SESSION => $session3,
	RESOURCE => 'resource5', PERMISSION => 'read'});
ok($client->response_is('OK'),
	'default group authorized to read on resource5');


# test timeout
sleep($client->client->{Timeout}+2);
# as test 'testing3 authorized to modify on resource4' above
$rc = $client->authorize({SESSION => $session3,
	RESOURCE => 'resource4', PERMISSION => 'modify'});
ok(! defined $rc && $client->response_is('AUTH_REQUIRED'),
	'testing3 session timed out');

# should user get dumped from client?

# re-authenticate user 3
my $new_session3 = $client->authenticate({USERNAME => 'tester3',
	PASSWORD => 'testing'});
ok(defined $new_session3 && $client->response_is('OK'),
	'Test user 3 authenticated');

# verify session token is fresh
ok($new_session3 ne $session3, 'New session token different');

# pass authorization to modify on resource4 for user 3
$rc = $client->authorize({SESSION => $new_session3,
	RESOURCE => 'resource4', PERMISSION => 'modify'});
ok($client->response_is('OK'),
	'testing3 authorized works after re-login');

__END__

Need to add tests for including IP in authorization

Need to add more tests using int masks and multiple permissions

Need to differentiate permission & mask?
