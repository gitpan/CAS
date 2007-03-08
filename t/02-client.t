#!perl -T

use Test::More tests => 7;

use CAS;

#diag( "Testing CAS,  Config reading & Client $CAS::VERSION, Perl $], $^X" );
my $dir = $ENV{PWD};
my $config = "$dir/CAS.yaml";


# fail client load for invalid client ID
my $client1 = '';
eval { $client1 = new CAS({CLIENT_ID => 1000, CONFIG => $config}) };
ok(ref($client1) ne 'CAS', 'Fail on invalid CLIENT_ID');

# fail client load for invalid client Name
eval { $client1 = new CAS({CLIENT_NAME => 'Some bogus name',
	CONFIG => $config}) };
ok(ref($client1) ne 'CAS', 'Fail on invalid CLIENT_NAME');

# fail client load for invalid client Domain
eval { $client1 = new CAS({CLIENT_DOMAIN => '321.321.321.321',
	CONFIG => $config}) };
ok(ref($client1) ne 'CAS', 'Fail on invalid CLIENT_DOMAIN');

# make a client object for the Admin user with ID
my $client2 = new CAS({CLIENT_ID => 0, CONFIG => $config});
ok(ref($client2) eq 'CAS', 'Load test client with CLIENT_ID');

# make a client object for the Admin user with Name
my $client3 = new CAS({CLIENT_NAME => 'Test client', CONFIG => $config});
ok(ref($client3) eq 'CAS', 'Load Admin client with CLIENT_NAME');

# make a client object for the Admin user with Domain
my $client4 = new CAS({CLIENT_DOMAIN => '127.0.0.1', CONFIG => $config});
ok(ref($client3) eq 'CAS', 'Load Admin client with CLIENT_DOMAIN');


# check to make sure Admin client info loaded properly
ok($client3->client->{Name} eq 'Test client',
	'Client object contains correct client name');

__END__

Need to test basic messaging as well, including writing a log file
