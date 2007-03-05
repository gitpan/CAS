use strict;
use warnings;
use ExtUtils::MakeMaker;

unless (-r 'CAS.yaml') {
	my $conf = '';
	while (<DATA>) {
		my @F = split(/\t/);
		if (@F == 2 && $F[0] =~ /(\S+):\s(.+)/) {
			chomp $F[1];
			my $val = prompt($F[1], $2);
			$conf .= "$1: $val\n";
		} # line should be key:value\tquestion
		
		else { $conf .= $_ }
	} # while reading conf from DATA section
	
	open(CONF,'> CAS.yaml') or die "Couldn't save conf file: $!";
	print CONF $conf;
	close CONF or warn "Problem closing CAS.yaml: $!";
	
	print <<NOTE;

The CAS configuration file has been written. You should review the
configuration file and make any edits needed.

NOTE
} # unless the conf file already exists

else {
	warn "\n" . 'Using existing CAS configuration file. '
		. "Delete CAS.yaml to regenerate.\n\n";
} # else notify user skipping generation


# This will check to see if the config file got generated correctly and
# add it to the install target.
my $conf_dir = prompt('Where do you want the CAS config file installed?',
	'/etc/');
sub MY::postamble {
	return <<"END_MAKEFILE";
install ::
	./post_install.prl $conf_dir CAS.yaml
END_MAKEFILE
} # postamble

WriteMakefile(
    NAME                => 'CAS',
    AUTHOR              => 'Sean P. Quinlan <gilant@gmail.com>',
    VERSION_FROM        => 'lib/CAS.pm',
    ABSTRACT_FROM       => 'lib/CAS.pm',
    PL_FILES            => { },
    PREREQ_PM => {
        'Test::More' => 0,
        'Data::Dumper' => 0,
        'DBI' => 0,
        'Mail::Sendmail' => 0.7,
        'Digest::MD5' => 0,
        'YAML' => 0.35,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'CAS-*' },
);

print <<NOTES;

The makefile has been generated. Please note that the CAS database must be
installed and all privileges on that database granted to the user identified
in the configuration file before make test or make install can be run
sucessfully. If during the final installation steps the CAS core client (ID: 1)
is not found in the database, that client and the administrative user will
be added to the database.

NOTES

exit;

##
## The data section will be read and the key:value lines will be
## be presented as a question if there is a question following the value
## seperated by tab.
##
__DATA__
--- #YAML:1.0
# This section provides the information required for DBI to connect
# to the CAS database. Minimally the password should be changed!
DB_DATABASE: CAS	CAS database name
DB_HOST: localhost	Host machine for database server
DB_USER: CAS_query	User to log into database
DB_PASSWD: local_passwd	Password to access database
DEFAULT_GROUP: 100	default group for new users

# Set this to true argument to turn on debugging. Higher numbers further
# increase verbosity.
DEBUG: 0	Debug value for this installation

# Default timeout to assign new clients. Actual timeout for requests is
# determined by the timeout field in the database for the specific client
TIMEOUT: 900	Default session timeout in seconds

# Client 0 is the test client and client 1 is the CAS administration client.
# here we'll get some info on the initial admin user and client. Most of this
# is used only during server installation for bootstrapping the settings.
ADMIN_CLIENT_NAME: CAS Admin
ADMIN_CLIENT_DOMAIN: localhost
ADMIN_CLIENT_ID: 1
ADMIN_CLIENT_DESCRIPTION: CAS Administrative client
ADMIN_CLIENT_COOKIE: CAS_Admin
ADMIN_USERNAME: admin	Username for primary CAS administrator
ADMIN_FIRST_NAME: CAS
ADMIN_LAST_NAME: Admin
ADMIN_EMAIL: casadmin@mycompany.com	Administrators email address
ADMIN_PHONE: 555-1212	Administrators phone #
