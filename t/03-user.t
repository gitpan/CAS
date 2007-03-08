#!perl -T

use Test::More tests => 20;

use CAS::User;

#diag( "Testing CAS::User $CAS::User::VERSION, Perl $], $^X" );
my $dir = $ENV{PWD};
my $config = "$dir/CAS.yaml";


# create a new user
my $user1 = CAS::User->new({Username =>  'tester1', Password => 'testing',
	Email => 'tester1@foo.com', CONFIG => $config, CLIENT_ID => 0});
ok($user1->response_is('CREATED'), 'Created initial test user');

# fail new user on various required inputs
my $user2 = undef;
eval { $user2 = CAS::User->new({Username =>  'tester2', Password => 'testing',
	CONFIG => $config, CLIENT_ID => 0}) };
ok($@ && $@ =~ /parameters missing or invalid/,	'No Email address provided');

eval { $user2 = CAS::User->new({Username =>  'tester2', Password => 'te',
	Email => 'tester2@foo.com', CONFIG => $config, CLIENT_ID => 0}) };
ok($@ && $@ =~ /parameters missing or invalid/, 'Password too short');

eval { $user2 = CAS::User->new({Username =>  'tester1', Password => 'testing',
	Email => 'tester2@foo.com', CONFIG => $config, CLIENT_ID => 0}) };
ok($@ && $@ =~ /Username .+ already used/,	'Username already used');


# create new new user that previously failed
$user2 = CAS::User->new({Username =>  'tester2', Password => 'testing',
	Email => 'tester2@foo.com', CONFIG => $config, CLIENT_ID => 0});
ok($user2->response_is('CREATED'), 'Created second test user');

# get tester1's ID
my $t1_id = $user1->ID;
ok($t1_id =~ /\d+/, 'Able to get tester1 ID');

# load test user by ID and Username
my $user1a = CAS::User->load({ID => $t1_id, CONFIG => $config, CLIENT_ID => 0});
ok($user1a->response_is('CREATED'), 'Succesfully loaded tester1');

# try set user attributes to illegal values
my $rc = $user1a->Email('foo.com');
ok(! defined $rc && $user1a->response_is('NOT_MODIFIED'),
	'Invalid Email address');

ok(! defined $user1a->Phone('555=1212') && $user1a->response_is('NOT_MODIFIED'),
	'Invalid Password');

ok(! defined $user1a->Zip(222) && $user1a->response_is('NOT_MODIFIED'),
	'Invalid zip code');

# set required user attributes to legal values
ok($user1a->Email('tester1@bar.com') && $user1a->response_is('OK'),
	'Good Email address');

ok($user1a->Password('testing1') && $user1a->response_is('OK'),
	'Good Password');


# get an attribute and confirm change
ok($user1a->Email eq 'tester1@bar.com', 'Stored Email correct');

# save user
ok($user1a->save && $user1a->response_is('OK'), 'Saved changes to user');

# load user and check to see if new attributes were saved
my $user1b = CAS::User->load({ID => $t1_id, CONFIG => $config, CLIENT_ID => 0});
ok($user1b->response_is('CREATED'), 'Succesfully loaded tester1 again');

ok($user1b->Email eq 'tester1@bar.com', 'Saved Email correct');


# disable users (these users will be used to test auth next)
ok($user1b->disable && $user1b->response_is('OK'), 'tester1 disabled');
ok($user2->disable && $user2->response_is('OK'), 'tester2 disabled');

# enable one user
ok($user2->enable && $user2->response_is('OK'), 'tester2 enabled');

# create one more user for later use in testing - there is little reason for
# this to ever fail
my $user3 = CAS::User->new({Username =>  'tester3', Password => 'testing',
	Email => 'tester3@foo.com', CONFIG => $config, CLIENT_ID => 0});
ok($user3->response_is('CREATED'), 'Created third test user');
