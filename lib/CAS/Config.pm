package CAS::Config;

use strict;

=head1 NAME

CAS::Config - Load the core configuration data and conect to the database.

=head1 VERSION

Version 0.40

=cut

our $VERSION = '0.40';

=head1 SYNOPSIS


    use CAS::Config;
    my $HR_config = CAS::Config->load({CLIENT_ID => n});

This module isn't intended for direct use. It returns a hashref which is used
as the common core data structure for all other CAS modules.

=cut

use YAML;
use CAS::DB;
use Carp qw(cluck confess croak carp);


=head1 load

Load a CAS client. This function returns a hashref containing all the basic
data from the config file and the indicated client, except the admin password.
This function is not intended to be called directly, but rather is the core
data structure blessed as a CAS client object.

PARAMETERS:

One of the following three arguments must be provided. If more than one is
available, they are selected in the order listed here.

CLIENT_ID:	The database ID of the client which is seeking to connect to
CAS.

CLIENT_NAME:	The name of the client which is seeking to connect to
CAS.

CLIENT_DOMAIN:	The domain of the client which is seeking to connect to
CAS.
listed.


OPTIONS:

CONFIG:	Alternate configuration file. Defaults to '/etc/CAS.yaml'.

=cut
sub load {
	# though we don't use $class
	my $proto = shift;
	my $class = ref($proto) || $proto;
	
	
	my $HR_params = shift;
	croak("Parameters not passed as a hashref")
		unless ref($HR_params) eq 'HASH';
	
	croak("No client key provided")
		unless defined $HR_params->{CLIENT_ID} || $HR_params->{CLIENT_NAME}
		|| $HR_params->{CLIENT_DOMAIN};
	
	# see if conf specified in case we're in make test
	my $conf_file = $HR_params->{CONFIG} || '/etc/CAS.yaml';
	
	local $/ = undef; # slurpy
	open(YAML,$conf_file) or die "Couldn't open CAS config file $conf_file: $!";
	my $yaml_in = <YAML>;
	close YAML or warn("YAML didn't close preoperly: $!");
	
	my $HR_config = Load($yaml_in);
	$HR_config->{conf_file} = $conf_file;
	
	# allow caller to overide default
	$HR_config->{debug} = $HR_config->{DEBUG}; # user-fetchable from config
	$HR_config->{debug} = $HR_params->{debug} if defined $HR_params->{debug};
	$^W++ if $HR_config->{debug};
	require diagnostics && import diagnostics
		if $HR_config->{debug} && $HR_config->{debug} > 2;
	
	
	# connect to db
	eval { $HR_config->{dbh} = CAS::DB->connectDB({user => $HR_config->{DB_USER},
		password => $HR_config->{DB_PASSWD}, host => $HR_config->{DB_HOST},
		debug => $HR_config->{debug}, database => $HR_config->{DB_DATABASE}}) };
	die "Problem connecting to database: $@" if $@;
	my $dbh = $HR_config->{dbh};
	warn "dbh = $dbh" if $HR_config->{debug} >= 2;
	
	# We don't need anyone interogating the config for the password
	delete $HR_config->{DB_PASSWD};
	
	$HR_config->{client} = $dbh->client_info($HR_params);
	die 'Problem getting Client data: ' . $dbh->errstr
		unless ref $HR_config->{client} eq 'HASH';
	
	# get user info table fields - will it get used a lot? Should we get the
	# client tables as well then? Should the field type be a value?
	foreach my $field (grep($_ ne "ID",
			@{$dbh->selectcol_arrayref("DESC UserInfo")})) {
		$HR_config->{user_info_fields}{$field} = 1;
	} # foreach field in the UserInfo table
	
	# if this client has a suplimental user table load that too
	if (defined $HR_config->{client}{Supplemental_User_Table}) {
		foreach my $field (grep($_ ne 'User',
				@{$dbh->selectcol_arrayref("DESC
				$HR_config->{client}{Supplemental_User_Table}")})) {
			$HR_config->{supl_user_info_fields}{$field} = 1;
		} # foreach feild
	} # if Supplemental_User_Table
	
	# This assumes CAS will always be Client 1 - that should be in the docs
	$HR_config->{admin_email} = $dbh->selectrow_array("SELECT Email
		FROM Clients, UserInfo WHERE Clients.ID = 1 AND UserInfo.ID = Admin");
	die('Problem getting Admin email: ' . $dbh->errstr)
		if $dbh->err;
	
	return $HR_config;
} # load

=head1 AUTHOR

Sean P. Quinlan, C<< <gilant at gmail.com> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-cas-config at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=CAS>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc CAS

You can also look for information at:

=over 4

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/CAS>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/CAS>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=CAS>

=item * Search CPAN

L<http://search.cpan.org/dist/CAS>

=back

=head1 ACKNOWLEDGEMENTS

=head1 COPYRIGHT & LICENSE

Copyright 2006 Sean P. Quinlan, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of CAS::Config
