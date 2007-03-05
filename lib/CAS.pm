package CAS;

use strict;

=head1 NAME

CAS - Central Authorization Server

=head1 VERSION

Version 0.87

=cut

our $VERSION = '0.87';

=head1 SYNOPSIS

CAS is intended to provide cross project (client), cross platform
authentication and authorization services. CAS allows a user to have a single
username and password, which can be granted access to 0 or more different
clinets. Indeed even fine grained access controls can be granted differently
for any and all of the different clients that use CAS.
    
  use CAS;

  my $client = CAS->new({CLIENT_ID => 2});

or

  my $client = new CAS({CLIENT_NAME => 'Project Foo'});

  my $session = $client->authenticate({USERNAME => 'foo',
    PASSWORD => 'foobar'});
  my $can_do = $client->authorize({USER => $session2,
    RESOURCE => 'resource1', MASK => 'create'});

Code problems and mis-configurations should cause the call to die. Methods
should return undef on failure. Error statements are stored in the
calling objects errstr.

 unless (defined $session) { carp $client->errstr }

=head1 DESCRIPTION

This system provides a set of tools providing access to a central
authorization database.

You first must create a basic CAS client object.
  my $client = CAS->new({CLIENT_ID => 2});

or

  my $client = CAS->new({CLIENT_NAME => 'Project Foo'});

You can fetch information about the client from this object. But its main
purpose is to authenticate users. As the users can be granted access to any
client, the specific client used to create this object doesn't matter if you
just want to confirm the user.

  my $session = $client->authenticate({});

The session token can be used to create a user object, which remembers the
client under which it was created. This user object can be used to fetch
information about the user and check if the user authorizations under that
client. Sessions are tracked, and the session token can be returned to the
caller for later invocations. Security of the token and its use is left to
the discretion of the caller.

=head2 ERROR HANDLING

Methods should return undef on failure. Error statements are stored in the
calling objects errstr.

 unless (defined $session) { carp $client->errstr }

Most methods will also set a RESPONSE_CODE:
	500	ERROR
	000	OK
	401	AUTH_REQUIRED
	403	FORBIDDEN

These values are drawn from Apache's response codes, since this system is
intended to be generally accessed via an Apache server. While error text
will be stored in B<errstr>, the RESPONSE_CODE can be checked to see the
reason for failure.
  if ($user->{RESPONSE_CODE} == ERROR) {
    "Problem handling request: $user->errstr";
  }
  elsif ($user->{RESPONSE_CODE} == FORBIDDEN) {
    "User not authorized: $user->errstr";
  }
  elsif ($user->{RESPONSE_CODE} == OK) { do_something() }

=head2 INTENT

Initially I just want this to work on the same server using mod_perl
handlers. Fairly generic auth handlers and a login
handler are provided in the CAS::Apache bundle.

The next phase would be to provide special mod_perl request handlers for remote
authentication and authorization requests. The response code in the header will
indicate if the user is authorized or not, or if they are allowed to view a
given resource
or not. Handlers would return XML or YAML containing the requested information,
the users ID, the session token and perhaps some digest key to verify the
response. I'd also like to configure the system so that any requests not comming
through SSL are refused.

On the back end the CAS server requires a set of tables in a relational
database. Since
this system is intended as a single point of maintenance of user data we can
control the schema. It would be nice if this could work with an LDAP server as
well as a MySQL (or other DBI supported relational database), or at least
be able to be configured to sync changes with an external system like LDAP so
that admins could have that information on a user (such as username, password,
full name, maybe UID etc) which is used elsewhere for system logins and such is
automatically synced.

=cut



use Scalar::Util qw(blessed);
use CAS::Config;
use CAS::User;
use Digest::MD5 qw(md5_hex);
use Carp qw(cluck confess croak carp);

# otherwise constants don't get exported
#use base qw(CAS::Messaging);
use CAS::Messaging;
our @ISA = qw(CAS::Messaging);
our $AUTOLOAD = '';


# Config fields that subclasses of core should be able to get and set
# Bitmasked with get permission = 1, set = 2, both = 3
my %fields = (
	client                  => 1,
	dbh                     => 1,
	user_info_fields        => 1,
	supl_user_info_fields   => 1,
	admin_email             => 1,
	debug                   => 3,
);


=head1 METHODS

=head2 new

Create a new client object.

PARAMETERS:

CLIENT_ID:	The database ID of the client which is seeking to connect to
CAS.

CLIENT_NAME:	The name of the client which is seeking to connect to
CAS.

CLIENT_DOMAIN:	The domain of the client which is seeking to connect to
CAS.

You can use any one. If more than one is defined they are checked in the order
listed.

OPTIONS:

CONFIG:	Alternate configuration file. Defaults to '/etc/CAS.yaml'.

DEBUG:	Set the DEBUG level for this object.

=cut
sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $HR_params = shift;
	croak("Parameters not passed as a hashref")
		unless ref($HR_params) eq 'HASH';
	
	croak("No client key provided")
		unless defined $HR_params->{CLIENT_ID} || $HR_params->{CLIENT_NAME}
		|| $HR_params->{CLIENT_DOMAIN};
	
	# load config
	my $config = CAS::Config->load($HR_params);
	$config->{_permitted} = \%fields;
	$config->{_users} = {};
	
	my $self = bless ($config,$class);
	$self->_set_result(CREATED,"CAS Client object sucesfully initiatied");
	return $self;
} # new


=head2 authenticate

This function is called to verify the username and password provided by the
user. It will imediatly return undef and set the response code to BAD_REQUEST
unless both the username and password were provided (well, technically,
evaluate to true). It then checks that the password provided matches the one
stored for that user.

Perls crypt function is called using the suplied password as the word and the
password from the db as the salt. If the result matches the stored password,
access will be granted. A session key is generated using md5_hex and the user
ID and time are stored in the db on that key. Also stored are either the users
IP address (if supplied) or the root caller() otherwise.

If authentication fails, NOT_FOUND is returned. If authentication succedes
the md5_hex key is returned. The key is intended
to be used by CAS as a session token for L<authorize> after first
authenticated. Any error message can be found in $client->errstr.

PARAMETERS:

USERNAME:	The username.

PASSWORD:	The users password.

OPTIONS:

IP: The remote connection IP. If present at authentication, the IP will be
required to be provided and match during any subsiquent authorization check.

=cut
sub authenticate {
	my $self = shift;
	$self->error("Not a method call") unless blessed($self);
	$self->_clear_result;
	
	my $HR_params = shift;
	$self->error("Parameters not passed as a hashref")
		unless ref($HR_params) eq 'HASH';
	my $debug = $HR_params->{DEBUG} || $self->{DEBUG} || 0;
	my $dbh = $self->dbh;
	
	warn("Checking authentication for $HR_params->{USERNAME}") if $debug;
	
	unless ($HR_params->{USERNAME}) {
		$self->_set_result(BAD_REQUEST,"No username provided.");
		return undef;
	} # resource to check authorization against required
	
	unless ($HR_params->{PASSWORD}) {
		$self->_set_result(BAD_REQUEST,"No password provided.");
		return undef;
	} # resource to check authorization against required
	
	# OK, now we have a username, lets check the suplied password
	my $Quser = $dbh->quote($HR_params->{USERNAME});
	# now get userID and password for username
	my $HR_user = $dbh->selectrow_hashref("SELECT *
		FROM Users WHERE Username = $Quser");
	$self->error("Database error: " . $dbh->errstr) if $dbh->err;
	
	unless ($HR_user->{User}) {
		$self->_set_result(NOT_FOUND,
			"Invalid account, username $HR_params->{USERNAME} not found.");
		return undef;
	} # unless user id returned
	
	if ($HR_user->{Disabled} eq 'Yes') {
		$self->_set_result(FORBIDDEN,"User has been disabled.");
		return undef;
	} # if user diasabled
	
	
	# OK, the user exists and we should have all the information needed
	# to authenticate
	$self->gripe("Password valid?") if $debug > 1;
	unless ($HR_user->{Password}
			eq crypt($HR_params->{PASSWORD},$HR_user->{Password})) {
		$self->_set_result(AUTH_REQUIRED,"Incorrect password.");
		return undef;
	} # unless password suplied matches users in db
	
	# OK, user authenticated, provide a session token
	$self->gripe("Issue session token") if $debug;
	my $now = localtime;
	my $Skey = md5_hex("$0$HR_user->{Password}$HR_params->{USERNAME}$now");
	my $Qkey = $dbh->quote($Skey);
	
	# now, stick seomthing into IP?
	my $ip = $dbh->quote($HR_params->{IP});
	
	$dbh->do("INSERT INTO Session (ID, User, IP)
		VALUES ($Qkey,$HR_user->{User},$ip)");
	$self->error("Can't log user in: " . $dbh->errstr) if $dbh->err;
	
	$self->_set_result(OK,"User authenticated.");
	return ($Skey);
} # authenticate


=head2 authorize

This checks the database to see if the user is currently logged in and if they
are allowed to use the specified resource.

PARAMETERS:


SESSION:	The session token returned by CAS when the user was authenticated
and logged in. This is used to get the user information required for checking
that user is logged in and that their session has not timed out. ***SECURITY***
It is up to you to make sure that this value is kept private and secure during
the session.

USER:	Alias for SESSION.

RESOURCE:	This is the resource definition that will be checked in the
database.

PERMISSIONS:	This is the type of action you want to check if the user has
permission for relative to the RESOURCE. The allowed values are read, modify,
create and delete. Create refers to permision to create a new record which
uses the refered to resource as a foreign key, or is under the refered resource
'tree'.

OPTIONS:

MASK:	This is an integer mask of permissions to be checked for the specified
RESOURCE. This can optionaly be used instead of PERMISSIONS, and is the only
way to specify requests on more than one type of permission at the same time.
The Values are 8 = read, 4 = modify, 2 = create, 1 = delete. To check for
multiple permissions at the same time simply sum all the permissions you want
to check. For example, to check for read and modify permision, provide 12 (8+4)
as the value for MASK. MASK overides PERMISSIONS if both are specified.

MATCHKEY:	A matchkey can be used to specify a specific element or key
match required. For example, RESOURCE my specify a particular table in a
database, with MATCHLEY specifying the primary key match required. Or if
RESOURCE was a web page, MATCHKEY may indicate a specific form element.

IP: The remote IP of the user. If this was provided during authentication then
it is REQUIRED for authorization and the IP's must match.

=cut
sub authorize {
	my $self = shift;
	$self->error("Not a method call") unless blessed($self);
	$self->_clear_result;
	
	my $HR_params = shift;
	$self->error("Parameters not passed as a hashref")
		unless ref($HR_params) eq 'HASH';
	my $debug = $HR_params->{DEBUG} || $self->debug || 0;
	my $dbh = $self->dbh;
	
	warn("Checking authorization") if $debug;
	
	unless ($self->client->{ID}) {
		$self->_set_result(ERROR,"Client object doesn't know its own ID?!");
		return undef;
	} # client required
	
	unless ($HR_params->{RESOURCE}) {
		$self->_set_result(BAD_REQUEST,"No resource to authorize against "
			. "provided.");
		return undef;
	} # resource to check authorization against required
	
	my $session = $HR_params->{SESSION} || $HR_params->{USER} || undef;
	unless (defined $session && $session =~ /^\S{32}$/) {
		$self->_set_result(BAD_REQUEST, "Missing or bad SESSION($session) "
			. "for authorization on request $HR_params->{RESOURCE}");
		return undef;
	} # session token required
	
	my $qsession  = $dbh->quote($session);
	
	my $logged_ip = $dbh->selectrow_array("SELECT IP
		FROM Session WHERE ID = $qsession");
	$self->error('Problem cheking for logged IP: ' . $dbh->errstr)
		if $dbh->err;
	
	# if an IP was logged when authenticated, the provided IP must match
	if ($logged_ip && $logged_ip ne $HR_params->{IP}) {
		$self->_set_result(FORBIDDEN,
			"Current IP ($HR_params->{IP}) does not match IP "
			. "when you logged on ($logged_ip). This may indicate a 'man in "
			. "the middle' security attack.");
		return undef;
	} # if IP & ip doesn't match
	
	my $timeout = $self->client->{Timeout};
	unless ($timeout) {
		$self->_set_result(ERROR,"Client object does not have a timeout?!");
		return undef;
	} # client required
	
	my $get_timediff = $dbh->prepare("SELECT unix_timestamp()
		- unix_timestamp(TS) FROM Session WHERE ID = $qsession",
		{RaiseError => 1});
	$self->error("Problem preparing timediff statement: " . $dbh->errstr)
		if $dbh->err;
	
	$get_timediff->execute();
	$self->error("Problem executing timediff statement: " . $dbh->errstr)
		if $dbh->err;
	
	my $timediff = $get_timediff->fetchrow_array();
	$self->error("Problem fetching timediff: " . $dbh->errstr)
		if $dbh->err;
	
	$self->gripe("Params appear in place, checking timeout: "
		. "$timediff > $timeout") if $debug;
	my $try = 2;
	unless (defined $timediff) {
		$self->_set_result(ERROR,
			"Session ID $qsession not in database.");
		return undef;
	} # session token not found in db
	
	elsif ($timediff == 0) {
		while ($timediff == 0) {
			sleep(1);
			$get_timediff->execute();
			$self->error("Problem executing timediff statement: "
				. $dbh->errstr) if $dbh->err;
			
			$timediff = $get_timediff->fetchrow_array();
			$self->error("Problem fetching timediff: " . $dbh->errstr)
				if $dbh->err;
			
			last if $try++ == 8;
		} # while timediff not true
		
		unless ($timediff) {
			$self->_set_result(FORBIDDEN,
				"Problem resolving timeout for $qsession.");
			return undef;
		} # unless second query suceeded
	} # session token not found
	
	elsif ($timediff > $timeout) {
		$self->_set_result(AUTH_REQUIRED,"Session has timed out.");
		return undef;
	} # if session timed out
	
	$HR_params->{CLIENT} = $self->client->{ID};
	$HR_params->{USER}   = $self->user($session)->{ID};
	$HR_params->{MATCHKEY} ||= '';
	unless ($dbh->allowed($HR_params)) {
		$self->_set_result(FORBIDDEN,
			"User for session $qsession not authorized to access "
			. "$HR_params->{RESOURCE},$HR_params->{MATCHKEY}:\n\t"
			. $dbh->errstr); 
		return undef;
	} # unless user has permision
	
	$dbh->do("UPDATE Session SET TS=NULL WHERE ID = $qsession");
	$self->error("Problem updating timestamp for $qsession: " .
		$dbh->errstr) if $dbh->err;
	
	$self->_set_result(OK,"User authenticated.");
	return OK;
} # authorize


=head2 user

Access the user object (L<CAS::User>) for authenticated users. Method takes
a single argument, the authenticated users session token.

=cut
sub user {
	my $self = shift;
	$self->error("Not a method call") unless blessed($self);
	$self->_clear_result;
	my $session = shift;
	
	unless (defined $session && $session =~ /^\S{32}$/) {
		$self->_set_result(BAD_REQUEST, "Missing or bad SESSION($session) ");
		return undef;
	} # session token required
	
	# if we've already loaded up the user object, just return it
	if ($self->{_users}{$session}) {
		$self->_set_result(OK,"Cached user object returned.");
		return $self->{_users}{$session};
	} # if user already stored
	
	my $qsession = $self->dbh->quote($session);
	my $id = $self->dbh->selectrow_array("SELECT User FROM Session
		WHERE ID = $qsession");
	$self->error("Problem getting user ID from $qsession: " .
		$self->dbh->errstr) if $self->dbh->err;
	
	# should we be checking for old instances of the same user to delete?
	
	my $user = CAS::User->load({ID => $id, CLIENT_ID => $self->client->{ID},
		CONFIG => $self->{conf_file}});
	unless (defined $user && $user->response_is(CREATED)) {
		$self->_set_result(ERROR,$user->messages);
		return undef;
	} # unless we were able to load user
	
	$self->{_users}{$session} = $user;
	$self->_set_result(OK,"User object created and returned.");
	return $user;
} # user



# Allows fetching of certain CAS attributes
sub AUTOLOAD {
	my $self = shift;
	return if ($AUTOLOAD =~ /DESTROY/);
	my $class = blessed($self);
	$self->error("Not a method call") unless $class;
	$self->_clear_result;
	
	my $name = $AUTOLOAD;
	$name =~ s/.*://; # strip fully-qualified portion
	
	unless (exists $self->{_permitted}->{$name} ) {
	    $self->error("Can't access `$name' field in class $class");
	} # unless access to the data feild is permitted
	
	if (@_) {
		$self->error("Not allowed to set $name")
			unless $self->{_permitted}{$name} & 2;
		# update database
		
		$self->{$name} = $_[0];
		return $self->{$name};
	} # if a new value supplied
	else {
		$self->error("Not allowed to fetch $name")
			unless $self->{_permitted}{$name} & 1;
		return $self->{$name};
	} # else just return current value
} # AUTOLOAD


=head1 AUTHOR

Sean P. Quinlan, C<< <gilant at gmail.com> >>

=head1 development notes

=head2 groups

Groups are always associated with a client. However, groups from one
client can be granted permissions on any other client. Generally all
groups are owned by the CAS Admin client but it is possible to have admin
tools on another client and allow them to manage their own group(s). The
admin user for any client can alter/drop existing groups under that client.
Additionally groups can have a 'Owner' specified. This is generally a user
who also has rights to modify the group and add/remove members, but not to
delete it.

=head1 BUGS

Please report any bugs or feature requests to
C<bug-cas at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=CAS>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.

=head1 HISTORY

=over 8

=item 0.01

Original version; created by module-starter

=item 0.1

Initial code port from CAS. History below to .30_2 ported from CAS.

=item 0.2

Basic required functionality for check auths in place. Apache auth handlers done
as well as simple Login handler. Core tests written and passing, user tests of
Apache handlers pass basic required functionality.

=item 0.21

User module functional and all basic methods in place. No automated tests for it
yet but that will be my next task before moving on to the Apache handlers for
registering a new user and a user view edit account handler. Also started
working on the docs.

=item 0.22

Added tests for user object and disable/enable methods. Small additions to
docs, like fixing my email address in this package! ;)

=item 0.23

Most of the basic Apache stuff has been worked out. The CAS.yaml file was
expanded and commented. I made a CAS.conf for all our Apache config stuff so
admins can just Include it rather than edit the main conf. So far registering
a new user & logging are functional if not quite complete or pretty.

=item 0.3_1

The internals of this module are pretty stable now. I added the
krb5_authentication function and added code to check_authentication to check
krb5 auth if required in conf or specified in user table.

=item 0.30_2

Ported to stub distribution generated by module-starter. Split Apache and
core CAS functionality into two dists. Started removing krb5 support from core
modules. If I continue to support it, it will be as an optional extension.

=back


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc CAS


Please join the CAS mailing list and suggest a final release name for
the package.
http://mail.grendels-den.org/mailman/listinfo/CAS_grendels-den.org

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

The Bioinformatics Group at Massachusetts General Hospital during my
tenure there for development assistance and advice, particularly the QA team
for banging on the project code.


=head1 COPYRIGHT & LICENSE

Copyright 2004-2006 Sean P. Quinlan, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of CAS
