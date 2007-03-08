#!perl -T

use Test::More skip_all => 'Admin methodology not settled yet';

use CAS;

# diag( "Testing CAS::Admin - not written yet $CAS::VERSION, Perl $], $^X" );
my $dir = $ENV{PWD};
my $config = "$dir/CAS.yaml";


#
# brainstorming
#

# make a CAS client object for the client to be admin'd
my $client = new CAS({CLIENT_ID => 0, CONFIG => $config, CLIENT_ID => 0});
ok(ref($client) eq 'CAS', 'Load test client with CLIENT_ID');

# authenticate user

# 

# grant 'global' test permissions (on client)
ok($admin->grant({RESOURCE => 'CAS/test/login', PERMISSIONS => 'read'}),
	'Grant "access" to test login page');

# create group
my $tgroup =
	$client3->add_group({NAME => 'test group 1', DESCRIPTION => 'Foo group'});
ok($tgroup, 'Add group to CAS owned by client admin');

# grant test permissions on group
ok($client3->grant({GROUP => $tgroup, RESOURCE => 'CAS/test/welcome',
	PERMISSIONS => 'read'}), 'Grant group permission to read welcome "page"');

# grant read permissions on test resource0 for user1

# grant create permissions on test resource1 for user1

# grant write permissions on test resource2 for user1

# grant delete permissions on test resource3 for user1

# grant read + write permissions on test resource4 for user1

