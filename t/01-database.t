#!perl -T

use Test::More tests => 3;

use CAS::Config;

#diag( "Testing CAS::DB $CAS::DB::VERSION, Perl $], $^X" );

# We don't actually connect to the datbase directly, we'll get the
# database handle from CAS::Config just as most code normally would.

my $dir = $ENV{PWD};
my $config = "$dir/CAS.yaml";

my $HR_config = CAS::Config->load({CLIENT_ID => 0, CONFIG => $config});
ok(ref($HR_config) eq 'HASH', 'CAS::Config->load');

# get the wrapped database handle

my $dbh = $HR_config->{dbh};
ok(ref($dbh) eq 'CAS::DB', 'CAS DBI wrapper found');

# make sure $dbh can talk to the database
ok($dbh->ping, 'CAS DBI wrapper found');

# now we do some direct housekeeping operations on the database, starting with
# scrubbing any existing test users, just in case
$dbh->do("DELETE FROM Users WHERE Username = 'tester1'");
$dbh->do("DELETE FROM UserInfo WHERE Email = 'tester1\@foo.com'");
$dbh->do("DELETE FROM UserInfo WHERE Email = 'tester1\@bar.com'");
$dbh->do("DELETE FROM Users WHERE Username = 'tester2'");
$dbh->do("DELETE FROM UserInfo WHERE Email = 'tester2\@foo.com'");
$dbh->do("DELETE FROM Users WHERE Username = 'tester3'");
$dbh->do("DELETE FROM UserInfo WHERE Email = 'tester3\@foo.com'");
$dbh->do("DELETE FROM Permissions WHERE GroupID = 99");

__END__
TODO: {
local $TODO = 'This section still to be worked out';

# now test any other additional methods in CAS::DB except allowed. That
# will be tested in more detail later
ok($dbh->enum_to_array('DESC Clients'),
	'Get the allowed values in an enum or set and return them in an array.');

ok($dbh->client_info({CLIENT_ID => 0}), 'Get information about a CAS client')
}
