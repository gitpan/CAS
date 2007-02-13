package CAS::DB;

use strict;

=head1 NAME

CAS::DB - DBI wrapper which adds a few CAS specific methods.

=head1 VERSION

Version 0.40_02

=cut

our $VERSION = '0.40_02';

=head1 SYNOPSIS

Connect to CAS database.

  use CAS::DB;
  my $dbh = CAS::DB->connectDB(\%params);
  
Though you shouldn't be connecting directly. Instead, load the CAS::Config data
and get the dbh from there.

    use CAS::Config;
    my $HR_config = CAS::Config->load({CLIENT_ID => n});
    my $dbh = $HR_config->{dbh};


=head1 ABSTRACT

  Wraps the DBI module, extending the database handle with some CAS specific
  methods. This module is not intemded to be used directly - _config.pm
  makes the connection using paramters from the CAS.yaml configuration.

=cut

use vars qw($AUTOLOAD);

use Data::Dumper;
use Scalar::Util qw(blessed);
use DBI;

# otherwise constants don't get exported
#use base qw(CAS::Messaging);
use CAS::Messaging;
our @ISA = qw(CAS::Messaging);
use Carp qw(cluck confess croak carp);


=head1 METHODS


=head2 connectDB

Wrapper for DBI->connect. Mainly does some configuration checking and if the
connection attempt fails will try every three seconds ten times.

PARAMETERS:

user:	Username to connect to the database with.

password:	Password for user.

server:	Type of database server. Defaults to mysql.

host:	Host to connect to. Defaults to localhost.

=cut
sub connectDB {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $self  = {};
	my $HR_params = shift;
	croak("Parameters not passed as a hashref")
		unless ref($HR_params) eq 'HASH';
	
	my $user_name = $HR_params->{user} or die 'No username provided';
	my $password  = $HR_params->{password} or die 'No password provided';
	my $server    = $HR_params->{server} || 'mysql';
	my $host      = $HR_params->{host} || $ENV{DBHost} || 'localhost';
	my $db        = $HR_params->{database};
	
	
	#handle params as nec. such as setting debug or changing env. variables
	my $DEBUG = $HR_params->{'DEBUG'} || 0;
	$^W++ if $DEBUG;
	(require diagnostics && import diagnostics) if $DEBUG >= 2;
	
	$self->{'_created'} = 1;
	$self->{'db'}	   = $db;
	$self->{debug}	  = $DEBUG;  
	
	my $dsn = "DBI:$server:$db:$host";
	my $dbh = '';
	my $attemp_count = 1;
	my $atrb = $HR_params->{DBIconnectAttributes} || { PrintError => 1 };
	warn "DBI->connect($dsn,$user_name,$password,$atrb)\n" if $DEBUG >= 2;
	
	# connect to database
	CONNECT: {
	$dbh = DBI->connect($dsn,$user_name,$password,$atrb);
	unless ($dbh) {
		warn "Have no connection to DB ($dsn,$user_name), retrying in 3";
		sleep(3);
		$attemp_count++;
		redo CONNECT unless $attemp_count > 10;
	} # no connection
	} # CONNECT control block
	
	# die if fail - catch with eval
	die "Failed to get connection $dbh after $attemp_count tries: $DBI::errstr"
		unless $dbh;
	
	$self->{dbh} = $dbh;
	
	# OK, lets internalize any other DB's provided, such as DBAdmin,
	# DBFooBar etc.
	foreach my $field (keys %{$HR_params}) {
		#warn("Setting DB's, field = $field\n");
		$self->{$field} = $HR_params->{$field}
			if $field =~ /DB$/;
		#warn("Set self->{$field} = $self->{$field}\n");
	} # foreach param
	
	my $obj = bless ($self,$class);
	$obj->_set_result(CREATED,"CAS DB object sucesfully initiatied");
	return $obj;
} # end of sub ConnectDB()


=head2 allowed

Does the user have the requested permission on the indicated resource. Return
value is true (actually returns the numeric value of the mask) if allowed, null
(uundef) if not, 0 on error. Call $DBH->error to see any error messages.

This method will check for permissions by both user id ad group memberships.
However it is important to remember that permission granted in any grants
permission, and individual user permision is checked first.

PARAMS:

USER: The database ID of the user.

RESOURCE: The resource we are checking. Could be a database table, a file (such
as a CGI or data archive), a port - whatever.

CLIENT:	The client ID or domain from which this request is being made.

PERMISSION:	This is the type of action you want to check if the user has
permission for relative to the RESOURCE. The allowed values are read, modify,
create and delete. Create refers to permision to create a new record which
uses the refered to resource as a foreign key, or is under the refered resource
'tree'.

OPTIONS:

MASK:	This is an integer mask of permissions to be checked for the specified
RESOURCE. This can optionaly be used instead of PERMISSION, and is the only
way to specify requests on more than one type of permission at the same time.
The Values are 8 = read, 4 = modify, 2 = create, 1 = delete. To check for
multiple permissions at the same time simply sum all the permissions you want
to check. For example, to check for read and modify permision, provide 12 (8+4)
as the value for MASK. MASK overides PERMISSION if both are specified.

MATCHKEY:	A matchkey can be used to specify a specific element or key
match required. For example, RESOURCE my specify a particular table in a
database, with MATCHLEY specifying the primary key match required. Or if
RESOURCE was a web page, MATCHKEY may indicate a specific form element.

Examples:

 # can place orders using fund 8887-009500
 my $can_do = $dbh->allowed({USER => 12345, RESOURCE => 'DNAcoreAdmin.Fund',
	MATCHKEY => '8887,009500', PERMISSION => create});

 # can view oligo OD QC tool CGI
 my $can_do = $dbh->allowed({RESOURCE => 'cgi-bin/synthesis/oligoOD',
	USER => 12345, PERMISSION => 'read'});

 # can delete results file
 my $can_do = $dbh->allowed({RESOURCE => 'sequencing/results/MK453GF67.seq',
	MASK => 1, USER => 12345);

To check the results
  unless($can_do) {
	if ($dbh->response_is('FORBIDDEN')) {
		# give user the bad news
	} # user does not have permission
	else {
		die "Problem checking permissions: $dbh->messages";
	} # otherwise something went wrong
  } # user can't

=cut
sub allowed {
	my $self = shift;
	$self->error("Not a method call") unless blessed($self);
	$self->_clear_result unless __PACKAGE__ eq caller;
	
	my $HR_params = shift;
	$self->error("Parameters not passed as a hashref")
		unless ref($HR_params) eq 'HASH';
	my $debug = $HR_params->{DEBUG} || $self->{debug} || 0;
	my $dbh = $self->{dbh};
	
	# make sure we have required argumants
	unless ($HR_params->{USER} && $HR_params->{USER} =~ /^\d+$/) {
		$self->_set_result(BAD_REQUEST,"No user ID provided.");
		return undef;
	} # userdat hash required
	
	unless ($HR_params->{RESOURCE}) {
		$self->_set_result(BAD_REQUEST,
			"Resource to check against is required.");
		return undef;
	} # RESOURCE  required
	
	unless ($HR_params->{CLIENT} && $HR_params->{CLIENT} =~ /^\d+$/) {
		$self->_set_result(BAD_REQUEST,
			"The client ID for which this resource applies is required.");
		return undef;
	} # client  required
	
	my %from_text_mask = (read => 8, modify => 4, create => 2, delete => 1);
	if ($HR_params->{MASK} && $HR_params->{MASK} =~ /^\d{1,2}$/) {
		$self->_set_result(CONTINUE, "MASK is a number");
	} # if MASK
	elsif ($HR_params->{PERMISSION}
			&& $from_text_mask{$HR_params->{PERMISSION}}) {
		
		$HR_params->{MASK} = $from_text_mask{$HR_params->{PERMISSION}};
		$self->_set_result(CONTINUE, "MASK translated from PERMISSION");
	} # if text permission
	else {
		$self->_set_result(BAD_REQUEST,
			"Need to know what permission to compare against. Either"
			. "PERMISSION or MASK was missing or invalid");
		return undef;
	} # else can't continue
	
	
	# prepare params for use in SQL
	$HR_params->{MATCHKEY} ||= '%';
	my $resource = $dbh->quote($HR_params->{RESOURCE});
	my $key = $dbh->quote($HR_params->{MATCHKEY});
	my $mask = $HR_params->{MASK};
	
	# check for permission by user id
	my $user_qr = "SELECT ModTime
		FROM Permissions
		WHERE Client = $HR_params->{CLIENT} AND User = $HR_params->{USER}
		AND Resource = $resource AND MatchKey LIKE $key
		AND (Permissions & $mask) = $mask";
	$self->gripe("User Query: $user_qr\n") if $debug > 1;
	
	my $has_perm = $dbh->selectrow_array($user_qr);
	if ($DBI::err) {
		$self->_set_result(ERROR,
			"Problem checking permission by user id: $DBI::errstr");
		return undef;
	} # if dbi error
	
	if ($has_perm) {
		$self->_set_result(OK, "Permision granted on user");
		return $has_perm;
	} # if allowed
	
	# user did not have permision directly, now check if any groups
	# grant requested permission
	my $AR_groups = $dbh->selectcol_arrayref("SELECT GroupID FROM Groups
		WHERE User = $HR_params->{USER}");
	if ($DBI::err) {
		$self->_set_result(ERROR,
			"Problem getting users groups: $DBI::errstr");
		return undef;
	} # if dbi error
	unless (@{$AR_groups}) {
		$self->_set_result(ERROR,
			"User $HR_params->{USER} is not a member of any groups");
		return undef;
	} # no groups!?!
	
	my $grp_set = "'" . join(",",@{$AR_groups}) . "'";
	my $group_qr = "SELECT ModTime
		FROM Permissions
		WHERE Client = $HR_params->{CLIENT} AND FIND_IN_SET(GroupID,$grp_set)
		AND Resource = $resource
		AND MatchKey LIKE $key AND (Permissions & $mask) = $mask";
	$self->gripe("Group Query: $group_qr\n") if $debug > 1;
	
	$has_perm = $dbh->selectrow_array($group_qr);
	if ($DBI::err) {
		$self->_set_result(ERROR,
			"Problem checking permission by group: $DBI::errstr");
		return undef;
	} # if dbi error
	
	if ($has_perm) {
		$self->_set_result(OK, "Permision granted on group");
		return $has_perm;
	} # if allowed
	
	$self->gripe("got to end of allowed and got no permisions -\nUser:\n"
		. "\t$user_qr\nGroup:\n\t$group_qr\n") if $debug;
	# nope - permission denied
	
	$self->_set_result(FORBIDDEN,
		"User does not have permission to access $resource ($key)");
	return undef;
} # allowed


=head2 client_info

Returns a hash reference with the info from the clients table.

PARAMETERS:

CLIENT_ID:	The database ID of the client which is seeking to connect to
CAS.

CLIENT_NAME:	The name of the client which is seeking to connect to
CAS.

CLIENT_DOMAIN:	The domain of the client which is seeking to connect to
CAS.

You can use any one. If more than one are defined, the first found in the
order above is used.

client lookup on domain from SQCAS authorization
	my $client = 0;
	if ($HR_params->{CLIENT} =~ /^\d+$/) { $client = $HR_params->{CLIENT} }
	else {
		my $Qdomain = $self->{DBH}->quote($HR_params->{CLIENT});
		$client = $self->{DBH}->selectrow_array("SELECT ID FROM Clients
			WHERE Domain = $Qdomain");
		error("Problem fetching client ID with $Qdomain: "
			. $self->{DBH}->error) if $self->{DBH}->error;
		
		unless ($client) {
			$self->_set_result(ERROR,"No client info provided.");
			return undef;
		} # client required
	} # else look for domain in DB
	

=cut
sub client_info {
	my $self = shift;
	$self->error("Not a method call ($self)") unless blessed($self);
	$self->_clear_result unless __PACKAGE__ eq caller;
	
	my $HR_params = shift;
	$self->error("Parameters not passed as a hashref")
		unless ref($HR_params) eq 'HASH';
	my $debug = $HR_params->{DEBUG} || $self->{debug} || 0;
	my $dbh = $self->{dbh};
	
	my $where = 'BROKEN';
	if (defined $HR_params->{CLIENT_ID}) {
		$where = "WHERE ID = $HR_params->{CLIENT_ID}";
	} # if ID provided
	elsif ($HR_params->{CLIENT_NAME}) {
		my $Qname = $dbh->quote($HR_params->{CLIENT_NAME});
		$where = "WHERE Name = $Qname";
	} # if name provided
	elsif ($HR_params->{CLIENT_DOMAIN}) {
		my $Qdom = $dbh->quote($HR_params->{CLIENT_DOMAIN});
		$where = "WHERE Domain = $Qdom";
	} # if domain provided
	else {
		$self->_set_result(BAD_REQUEST, "No client identification provided.");
		return undef;
	} # else
	
	my $HR_clients = $dbh->selectrow_hashref("SELECT * FROM Clients
		$where") || '';
	if ($DBI::err) {
		$self->_set_result(ERROR,
			"Problem geting client data: $DBI::errstr");
		return undef;
	} # if dbi error
	
	$self->gripe(Dumper($HR_clients)) if $debug > 1;
	
	$self->_set_result(OK, "Returning hash of client data");
	return $HR_clients;
} # client_info


=head2 enum_to_array

Sole argument is the 'DESC <Table_Name> <Field>' to be used. Sets error
if not an enum field. Returns a list of the possible enum (or set) values.

=cut
sub enum_to_array {
	my $self = shift;
	$self->error("Not a method call") unless blessed($self);
	$self->_clear_result unless __PACKAGE__ eq caller;
	my $desc_stmnt = shift or $self->error("DESC statement required");
	
	my $debug = $self->debug || 0;
	my $dbh = $self->{dbh};
	
	unless ($desc_stmnt =~ /^DESC [\w\.]+ \w+$/i) {
		$self->_set_result(BAD_REQUEST,
			"Description statement ($desc_stmnt) does not look correct");
		return undef;
	} # be strict about DB call
	
	my ($field,$enum) = $dbh->selectrow_array($desc_stmnt);
	if ($DBI::err) {
		$self->_set_result(ERROR,
			"Problem getting description of field from '$desc_stmnt: "
			. $DBI::errstr);
		return undef;
	} # SQL problem
	unless ($enum =~ /^enum|^set/i) {
		$self->_set_result(ERROR, "Feild described does not appear to be "
			. "enum or set. Type = $enum.");
		return undef;
	} # not parsable as enum
	
	(my $vals) = $enum =~ /\((.+)\)/;
	$vals =~ s/^'//;
	$vals =~ s/'$//;
	my @enums = split(/','/,$vals);
	unless (@enums) {
		$self->_set_result(ERROR, "No values found from $desc_stmnt.");
		return undef;
	} # if no values found
	
	$self->_set_result(OK, "Returning list of possible values");
	return @enums;
} # enum_to_array


# If it gets to AUTOLOAD, we'll assume it's a DBI method and hand it off
sub AUTOLOAD {
	my $self = shift;
	
	$self->error("Not a method call") unless blessed($self);
	$self->_clear_result unless __PACKAGE__ eq caller;
	
	my $method = $AUTOLOAD;
	$method =~ s/.*:://;
	
#	confess("What is going on with $method!!!");
	
	unless ($self->{dbh}->can($method)) {
		$self->error("DBI/DBD::mysql do not appear to support $method");
	} # unless call is something DBI does
	
	# result code ACCEPTED should only be set here in this module
	$self->_set_result(ACCEPTED,
		"Handing request off to DBI - CAS::DB is done");
	return $self->{dbh}->$method(@_);
} # AUTOLOAD


# allow calls to $self->err and $self->errstr to mimic the use of the DBI vars
# these are designed for external use only!!!
sub err {
	my $self = shift;
	$self->error("Not a method call") unless blessed($self);
	
	# if response code is ACCEPTED then the last thingthis object did
	# should have been an AUTOLOAD call directly to DBI
	return $DBI::err if $self->response_is(ACCEPTED);
	
	# otherwise the only code that should be acceptible once a call is finished
	# is OK
	return 1 unless $self->response_is(OK);
	
	# if not a DBI call and code is OK, there was (we hope) no error
	return 0;
} # err

sub errstr {
	my $self = shift;
	$self->error("Not a method call") unless blessed($self);
	
	# if response code is ACCEPTED then the last thingthis object did
	# should have been an AUTOLOAD call directly to DBI
	return $DBI::errstr if $self->response_is(ACCEPTED);
	
	# if the response code is OK, there is no 'errstr' - the caller can use
	# messages to see all messages generated during last method call
	return '' if $self->response_is(OK);
	
	# if not a DBI call and code is not OK, there was (we hope) no error
	return wantarray ? ($self->messages) : $self->messages;
} # errstr


# this really neads to be called explicitly from a child handler under mod_perl
sub DESTROY {
	my $self = shift;
	
	my $dbh = $self->{dbh};
	
	if ($dbh && $dbh->ping) {
		$dbh->do("UNLOCK TABLES");
		$dbh->disconnect;
	} # if we have a database handle
	
} # object cleanup

=head1 AUTHOR

Sean P. Quinlan, C<< <gilant at gmail.com> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-cas-db at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=CAS>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

	perldoc CAS


The home page for this project is perl-cas.org.

The mailing list for Perl CAS can be found at:
http://mail.perl-cas.org/mailman/listinfo/developers_perl-cas.org

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

1; # End of CAS::DB
