package CAS::User;

=head1 NAME

CAS::User - Creates user objects for accessing and modifying user data.

=head1 SYNOPSIS

  use CAS::User;

  my $user = CAS::User->new(%userinfo);
  die "Couldn't create new user" if $user == ERROR;
  
  my $user = CAS::User->load({ID => 1234567654});
  die "Couldn't load user." if $user == ERROR;
  
Or even better error reporting where appropriate:

  if (! ref $user && $user == ERROR) {
    my @errors = warning_notes();
	die "Failed to load user:\n\t" . join("\n\t",@errors) . "\n";
  } # if error

=head1 ABSTRACT

  Generate user objects for either new or existing users. The object returned
  is used to manage that users data, such as Password, Username, address, etc.

=head1 DESCRIPTION

Generate user objects for either new or existing users. The object returned
is used to manage that users data, such as Password, Username, address, etc.

Currently only the CAS core Users and UserInfo tables are handled. Some
handling of client user tables will be added once this is core part is
functional. Set, get and validate methods are provided for the core tables, for
the client tables only set and get are provided - it is the clients
responsibility to validate their specific user information.

=head2 EXPORT

None by default.

=cut

use 5.008;
use strict;
use CAS;
use CAS::Config;
use Scalar::Util qw(blessed);

# otherwise constants don't get exported
#use base qw(CAS::Messaging);
use CAS::Messaging;
our @ISA = qw(CAS::Messaging);

use Carp qw(cluck confess croak carp);
use Mail::Sendmail;
our $AUTOLOAD = '';

use Data::Dumper;

our $VERSION = '0.60_5';

# Config fields that subclasses of core should be able to get and set
# Bitmasked with get permission = 1, set = 2, both = 3
# all fields in the supplimental users table are set to 3 without
# internal validation
my %fields = (
	ID        => 1,
	Username  => 1,
	Password  => 1,
	Firstname => 3,
	Lastname  => 3,
	Email     => 3,
	Phone     => 3,
	Address1  => 3,
	Address2  => 3,
	City      => 3,
	State     => 3,
	Country   => 3,
	Zip       => 3,
	Disabled  => 3,
	dbh                     => 1,
	user_info_fields        => 1,
	supl_user_info_fields   => 1,
	admin_email             => 1,
	debug                   => 3,
);

=head2 new

Creates user object for a user not yet registered in the CAS system. Invoking
this contructer will generate an object to use for validating new user
information and entering a user in the database. When invoked it requires a
Username and Password for the user, which will be validated. If those pass
validation the user is registered in the database and the object is returned.

This object can now be used to validate additional user data and add it to the
users record. It is highly recommended that you require the users First and Last
names and any contact information you want be provided with the Username,
Password, etc. and that you record all those (that validate) immediately after
getting the user object back.

Please note

PARAMETERS:

Username:	The Username the user will use for logging into the system. Usernames
are therefor unique in the database.

Password:	The Password the user will use when logging in. It is highly
recommended you verify the Password before set it by having a user enter it
twice and compare the two entries.

Email:	An Email address for the user. This Email address will be used by the
system to send Emails to the user for important system notifications, such as
registration notification, systemwide administrative messages, etc. Since Email
addresses are required to be unique within the system, this also discourages
users from registering multiple times.

CLIENT:	The client the user is registering from.

OPTIONS:

GROUP: The default initial group for the user. If not provided the default
group for the client will be used, or, if that is not defined, the general
default group as set in the CAS config file will be used.

=cut
sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $HR_params = shift;
	croak("Parameters not passed as a hashref")
		unless ref($HR_params) eq 'HASH';
	
	my $config = CAS::Config->load($HR_params);
	$config->{_permitted} = \%fields;
	my $self = bless ($config,$class);
	$self->_clear_result;
	my $dbh = $self->{dbh}; # can't autoload yet - no ID in self
	
	# Determine debug level and activate warnings and diagnostics if
	# appropriate
	my $debug = $HR_params->{debug} || $self->{debug} || 0;
	$^W++ if $debug;
	(require diagnostics && import diagnostics) if $debug > 2;
	$self->{debug} = $debug;
	
	
	error("No database connection!") unless $dbh->ping;
	
	my $valid_Username = $self->validate_Username($HR_params);
	my $valid_Password = $self->validate_Password($HR_params);
	my $valid_Email    = $self->validate_Email($HR_params);
	
	unless (defined $valid_Username && defined $valid_Password
			&& defined $valid_Email) {
		$self->error("Some required parameters missing or invalid: "
			. $self->messages);
	} # Username or Password were invalid format
	
	
	# check to see if Username is already used
	my $Quser = $dbh->quote($HR_params->{Username});
	my $already_used = $dbh->selectrow_array("SELECT User FROM
		Users WHERE Username = $Quser");
	$self->error('Problem checking if Username already used: '
		. $dbh->errstr) if $dbh->err;
	$self->error("Username $Quser is already used.") if ($already_used);
	
	# check if email already used
	my $QEmail = $dbh->quote($HR_params->{Email});
	my $email_used = $dbh->selectrow_array("SELECT ID
		FROM UserInfo WHERE Email = $QEmail");
	$self->error('Problem checking if Email already used: '
		. $dbh->errstr) if $dbh->err;
	$self->error("Email $QEmail is already registered.") if ($email_used);
	
	# add user to database and set user ID in object
	my $set_vals = '';
	foreach my $field (keys %{$self->user_info_fields}) {
		my $value = $HR_params->{$field} || undef;
		if ($value) {
			my $validation_method = "validate_$field";
			if ($self->can($validation_method)) {
				$value = $self->$validation_method($value);
			}
			unless (defined $value) {
				$self->_set_result(CONTINUE, "Value for optional field $field "
					. 'invalid or undefined, skipped.');
				next;
			} # don't set invalid fields
			
			$self->{$field} = $value;
			my $Qval = $dbh->quote($value);
			$set_vals .= ", $field = $Qval";
		} # if value for field provided
	} # for each possible field
	$dbh->do("INSERT INTO UserInfo SET regdate = CURRENT_DATE
		$set_vals");
	$self->error('Problem registering user with [$set_vals]: '
		. $dbh->errstr) if $dbh->err;
	
	my $id = $dbh->selectrow_array("SELECT LAST_INSERT_ID()")
		|| $HR_params->{ID};
	$self->error('No ID returned by database?!') unless $id;
	$self->{ID} = $id;
	$self->{Username} = $HR_params->{Username};
	
	
	# add any other user data provided for suplimental table
	my $supl_tbl = $self->{client}{Supplemental_User_Table} || undef;
	if ($supl_tbl) {
		$set_vals = "User = $self->{ID}";
		foreach my $field (keys %{$self->supl_user_info_fields}) {
			my $value = $HR_params->{$field} || undef;
			if ($value) {
				my $validation_method = "validate_$field";
				if ($self->can($validation_method)) {
					$value = $self->$validation_method($value);
				}
				unless (defined $value) {
					$self->_set_result(CONTINUE, 'Value for optional field '
						. "$field invalid or undefined, skipped.");
					next;
				} # don't set invalid fields
				
				$self->{$field} = $value;
				my $Qval = $dbh->quote($value);
				$set_vals .= ", $field = $Qval";
			} # if value for field provided
		} # for each possible field
		$dbh->do("INSERT INTO UserInfo SET  User = $self->{ID}, $set_vals");
		$self->error('Problem entering users Email and generating User ID: '
			. $dbh->errstr) if $dbh->err;
	} # if registering client has suplimental table for users
	
#	my $krb5 = '';
#	if ($HR_params->{KRB5}) {
#		$krb5 = ", KRB5 = " . $dbh->quote($HR_params->{KRB5});
#	} # set KRB5 value if supplied
#	$dbh->do("INSERT INTO Users SET User = $id,
#		Username = $QUsername, Password = $Qpass $krb5");
#	error('Problem registering user in the Users table: '
#		. $dbh->errstr) if $dbh->err;
	
	
	# add to users table
	my $QUsername = $dbh->quote($HR_params->{Username});
	my $cryptpass = $self->crypt_pass($HR_params->{Password});
	my $Qpass = $dbh->quote($cryptpass);
	$dbh->do("INSERT INTO Users (User, Username, Password)
		VALUES ($self->{ID},$QUsername,$Qpass)");
	$self->error('Problem adding user to default group: '
		. $dbh->errstr) if $dbh->err;
	
	
	# add to default group
	my $group = $HR_params->{GROUP} || $self->{client}{Default_Group}
		|| $self->{DEFAULT_GROUP} || undef;
	$self->error('Could not determine initial group for user')
		unless defined $group;
	$dbh->do("INSERT INTO Groups (User,GroupID) VALUES ($self->{ID},$group)");
	$self->error('Problem adding user to default group: '
		. $dbh->errstr) if $dbh->err;
	
	# OK, it looks like the user was added to DB without any real prpblems.
	# Now lets load the real user object
	my $user = $self->load({ID => $self->{ID},
		CLIENT_ID => $self->{client}{ID}, CONFIG => $HR_params->{CONFIG}});
	$self->error('Was not able to create user object for new user, '
		. "ID = $self->{ID}") unless ref($user) eq $class;
	
	# 'inherit' selfs messages
	unshift(@{$user->{messages}},$self->messages);
	
	# FIX ME!!!
	# and email notification
#	$user->new_user_email();
	
	$self->_set_result(CREATED,"User object created and returned.");
	return $user;
} # new


=head2 load

Returns a user object which can be used to access and update user data. Will
emit errors if fields that are expected not to be null (such as First Name)
are.

PARAMETERS:

ID:	The ID of the user.

or

Username:	The users unique Username.

=cut
sub load {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	
	my $HR_params = shift;
	die("Parameters not passed as a hashref")
		unless ref($HR_params) eq 'HASH';
	my $config = CAS::Config->load($HR_params);
	$config->{_permitted} = \%fields;
	my $self = bless ($config,$class);
	$self->_clear_result;
	my $dbh = $self->{dbh}; # can't autoload yet - no ID in self
	
	my $debug = $HR_params->{'DEBUG'} || $self->{debug} || 0;
	$^W++ if $debug;
	(require diagnostics && import diagnostics) if $debug > 2;
	$self->{debug} = $debug;
	
	unless ($HR_params->{ID} || $HR_params->{Username}) {
		$self->error("Either the user ID or Username are required.");
	} # unless unique identifier provided
	
	# get ID if Username provided
	elsif ($HR_params->{Username}) {
		my $Quser = $dbh->quote($HR_params->{Username});
		$HR_params->{ID} = $dbh->selectrow_array("SELECT User FROM
			Users WHERE Username = $Quser");
		$self->error('Problem getting user id: ' . $dbh->errstr)
			if $dbh->err;
		
		$self->error("Username $Quser not found in database.")
			unless $HR_params->{ID};
	} # if usename
	
	my $supl_tbl = $self->{client}{Supplemental_User_Table} || undef;
	if (defined $supl_tbl) {
		foreach my $sup_field (keys %{$self->supl_user_info_fields}) {
			$self->{_permitted}{$sup_field} = 3;
		}
	}
	$self->{ID} = $HR_params->{ID};
	my $rc = $self->_fetch_user_data();
	$self->error('Problem loading user data: ' . $self->messages)
		unless defined $rc;
	
	
	$self->_set_result(CREATED,"User loaded from DB and object returned.");
	return $self;
} # load



# populate user object with user data - used to (re)load user data from db
sub _fetch_user_data {
	my $self = shift;
	
	my $dbh = $self->dbh;
	
	my $getdat = join(", ",keys %{$self->user_info_fields});
	my $HR_userinfo = $dbh->selectrow_hashref("SELECT $getdat
		FROM UserInfo WHERE ID = $self->{ID}");
	$self->error("Problem getting user info: " . $dbh->errstr)
		if $dbh->err;
	
	# email is required, so we'll make an assumption here
	unless ($HR_userinfo->{Email}) {
		$self->_set_result(ERROR,"No user info found for $self->{ID}?");
		return undef;
	}
	
	map { $self->{$_} = $HR_userinfo->{$_} } keys %{$HR_userinfo};
		
	my $table = $self->{client}{Supplemental_User_Table} || undef;
	if (defined $table) {
		$getdat = join(", ",keys %{$self->supl_user_info_fields});
		$HR_userinfo = $dbh->selectrow_hashref("SELECT $getdat
			FROM $table WHERE User = $self->{ID}");
		$self->error("Problem getting user info: " . $dbh->errstr)
			if $dbh->err;
		
		map { $self->{$_} = $HR_userinfo->{$_} } keys %{$HR_userinfo};
	} # if there is a suplimental user info table
	
	$self->_set_result(OK,"Fetched user data");
	return OK
} # fetch_user_data


=head2 save

Saves the current state of the user. 

!! Currently does not handle client table data !!

=cut
sub save {
	my $self = shift;
	$self->_clear_result unless __PACKAGE__ eq caller;
	my $dbh = $self->dbh;
	
	# cheerfully return if there's nothing to save
	# yeah - this prevents people from setting values
	# by hand and avoiding the validation check in set! >:-}
	# hmm ... unless they figure out to set {changed}
	# maybe that should be a separate private variable?
	unless (scalar(keys %{$self->{changed}})) {
		$self->_set_result(OK,"Nothing to save - all done");
		return OK ;
	}
	
	my @updates = ();
	# first update UserInfo fields
	foreach my $field (keys %{$self->user_info_fields}) {
		next unless $self->{changed}{$field};
		
		my $Qval = $dbh->quote($self->{$field});
		push(@updates,"$field = $Qval");
	} # for each possible field
	
	if (@updates) {
		my $updates = join(', ', @updates);
		$dbh->do("UPDATE UserInfo SET $updates WHERE ID = $self->{ID} LIMIT 1");
		$self->error('Problem updateing user info ($updates): '
			. $dbh->errstr) if $dbh->err;
	} # if there are updates besides password
	
	my $table = $self->{client}{Supplemental_User_Table} || undef;
	if (defined $table) {
		@updates = ();
		# first update UserInfo fields
		foreach my $field (keys %{$self->supl_user_info_fields}) {
			next unless $self->{changed}{$field};
			
			my $Qval = $dbh->quote($self->{$field});
			push(@updates,"$field = $Qval");
		} # for each possible field
		
		if (@updates) {
			my $updates = join(', ', @updates);
			$dbh->do("UPDATE $table SET $updates
				WHERE User = $self->{ID} LIMIT 1");
			$self->error('Problem updateing user info ($updates): '
				. $dbh->errstr) if $dbh->err;
		} # if there are updates besides password
	} # if there is a suplimental user info table
	
	unless ($self->{changed}{Password}) {
		$self->_set_result(OK,"All changes saved.");
		return OK ;
	}
	
	# handle password separately
	my $Qpass = $dbh->quote($self->{Password});
	$dbh->do("UPDATE Users SET Password = $Qpass
		WHERE User = $self->{ID} LIMIT 1");
	$self->error('Problem updating password: ' . $dbh->errstr)
		if $dbh->err;
	
	$self->_set_result(OK,"All changes saved.");
	return OK;
} # save



=head2 disable

Mark a user as diabled. Authentication will be denied.

=cut
sub disable {
	my $self = shift;
	$self->_clear_result unless __PACKAGE__ eq caller;
	my $dbh = $self->dbh;
	
	$dbh->do("UPDATE Users SET Disabled = 'Yes'
		WHERE User = $self->{ID} LIMIT 1");
	$self->error("Problem disabling user: " . $dbh->errstr)
		if $dbh->err;
	
	$self->_set_result(OK,"User disabled");
	return OK;
} # disable


=head2 enable

Reset disabled flag to 'No'.

=cut
sub enable {
	my $self = shift;
	$self->_clear_result unless __PACKAGE__ eq caller;
	my $dbh = $self->dbh;
	
	$dbh->do("UPDATE Users SET Disabled = 'No'
		WHERE User = $self->{ID} LIMIT 1");
	$self->error("Problem enabling user: " . $dbh->errstr)
		if $dbh->err;
	
	$self->_set_result(OK,"User enabled");
	return OK;
} # enable



=head2 Accessor, Mutator and Validation methods

Methods in this catagory are provided to access and alter the user data. The
following list describes the user attributes which these methods all work on.
Altering the values of user attributes with the set_ methods does B<not>
change them in the database. Call $user->save; to make any changes permanant.
Further, calling a set_ method automatically invokes the validate_ method,
so there is no need to validate before setting, unless you want to just catch
and handle errors yourself (to regenerate a form with failed fields highlightes
for instance).

=over 4

=item Username [A-Za-z0-9_'-.@]{5,50}

A textual key uniquely indicating one user. This value is supplied by the user
when they register and will function as the name with which they log in to the
system. This is usually a short login handle, such as the common first initial
last name combination (squinlan), however certain sites may wish to require
users to usa they're email address as a username. While the system allows
the use of an email address as a username, it is up to the client to modify the
user registration interface appropriately.

Once registered this field may I<not> be altered via set_Username.

=item Password [^;\s|><]{6,16}

A text string containing almost any plain ASCII non-whitespace text characters.
The system
can optionally require however that the password contain at least one upper
case, one lower case, one number and one non-alphanumeric character by setting
the optional STRICT parameter to true.

Please note that the plain password string is I<not> stored in the database.
Passwords are encrypted before they are stored in the databas.

=item Firstname [\w-' ]{2,20}

The users first name.

=item Lastname [\w-' ]{2,30}

The users last name.

=item Email [\w-.@]{6,50}

A valid email address for the user. The validation measures only examine the
email to see if it looks valid. However when a new user registers an email is
sent to the address provided with the from and reply-to fields set to the
client administrators email address, so they should recieve bounce
notifications.

=item Phone [\d-. )(]{3,20}

A contact phone number for the user.

=item Address1 [\w-.# ]{6,100}

The first address line to be used if a physical letter or package is to be sent
to the user.

=item Address2 [\w-.# ]{6,100}

The second address line to be used if a physical letter or package is to be
sent to the user.

=item City [\w-. ]{2,30}

The city for the users mailing address.

=item State [\w-.]{2,20}

The state for the users mailing address.

=item Country [\w-. ]{2,30}

The country for the users mailing address.

=item Zip [0-9-]{5,10}

The users zip code.

=back

=head2 validate_ 

These methods make sure that the suplied information meets system requirements
most of which are not enforced by the database. Such as forbidding certain
characters or requiring a minimum length. If the specific data is determined
to be 'invalid' then the FORBIDDEN staus code is returned.

All the set_ methods call validation before setting, so there is generally no
need to call the validation yourself unless you are setting multiple fields at
the same time and want them all handled in an all-or-nothing manner so want to
pre-validate them.

=cut

# all of this validation is currently really just some sanity checks on input
# to see if something basically appropriate was provided. I expect to convert
# DB module to a Class::DBI type at some point, and may place some of this
# validation checks as constraints.


sub validate_Username {
	my $self = shift;
	my $value = shift;
	$self->_clear_result unless __PACKAGE__ eq caller;
	
	if (ref($value) eq 'HASH') {
		$value = $value->{Username} || undef;
	}
	
	unless (defined $value) {
		$self->_set_result(BAD_REQUEST, "No Username provided for validation.");
		return undef;
	} # if value not provided
	
	my $errors = 0;
	
	if (length($value) < 3) {
		$self->_set_result(CONTINUE,
			"Username ($value) was missing or too short.");
		$errors++;
	} # Username too short
	
	elsif (length($value) > 50) {
		$self->_set_result(CONTINUE, "Username $value) was too long.");
		$errors++;
	} # Username too long
	
	# we allow [@.-] to allow Emails to be used as Usernames
	(my @bad_characters) = $value =~ /([^\w\'-.@]+)/g;
	if (@bad_characters) {
		$self->_set_result(CONTINUE,
			"Username contains illegal characters (@bad_characters)");
		$errors++;
	} # check for invalid characters
	
	
	if ($errors) {
		$self->_set_result(NOT_MODIFIED,
			"Username does not appear to be valid, unchanged.");
		return undef;
	} # if errors
	$self->_set_result(OK,"Username is valid");
	return $value;
} # validate_Username


sub validate_Password {
	my $self = shift;
	my $value = shift;
	$self->_clear_result unless __PACKAGE__ eq caller;
	
	my $strict = 0;
	if (ref($value) eq 'HASH') {
		$strict = $value->{STRICT} || 0;
		$value = $value->{Password} || undef;
	}
	
	unless (defined $value) {
		$self->_set_result(BAD_REQUEST, "No Password provided for validation.");
		return undef;
	} # if value not provided
	
	
	$self->gripe("Password = $value") if $self->debug > 1;
	
	my $errors = 0;
	if (length($value) < 6) {
		$self->_set_result(CONTINUE, "Password was missing or too short.");
		$errors++;
	} # Password too short
	
	elsif (length($value) > 16) {
		$self->_set_result(CONTINUE, "Password was too long.");
		$errors++;
	} # Password too long
	
	(my @bad_characters) = $value =~ /([;\s\|><]+)/g;
	if (@bad_characters) {
		$self->_set_result(CONTINUE,
			"Password contains illegal characters (@bad_characters)");
		$errors++;
	} # check for invalid characters
	
	
	if ($strict) {
		unless (   $value =~ /\d/
				&& $value =~ /[A-Z]/
				&& $value =~ /[a-z]/
				&& $value =~ /[^\w]/) {
			$self->_set_result(CONTINUE,
				"Password ($value) does not pass strict criteria.");
			$errors++;
		} # unless requirements met
	} # if 'strict' passwords required make sure a range of character types used
	
	if ($errors) {
		$self->_set_result(NOT_MODIFIED,
			"Password does not appear to be valid, unchanged.");
		return undef;
	} # if errors
	$self->_set_result(OK,"validate_Password returned OK");
	return $value;
} # validate_Password


sub validate_Firstname {
	my $self = shift;
	my $value = shift;
	$self->_clear_result unless __PACKAGE__ eq caller;
	
	if (ref($value) eq 'HASH') {
		$value = $value->{Firstname} || undef;
	}
	
	unless (defined $value) {
		$self->_set_result(BAD_REQUEST,
			"No Firstname provided for validation.");
		return undef;
	} # if value not provided
	
	my $errors = 0;
	
	
	if (length($value) < 2 || $value !~ /\w+/) {
		$self->_set_result(CONTINUE,
			'First Name appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($value) > 20) {
		$self->_set_result(CONTINUE, 'First Name appears to be too long.');
		$errors++;
	} # field too long
	
	(my @bad_characters) = $value =~ /([^\w\-\' ]+)/g;
	if (@bad_characters) {
		$self->_set_result(CONTINUE,
			"First Name contains invalid characters (@bad_characters).");
		$errors++;
	} # unless minimally valid
	
	
	if ($errors) {
		$self->_set_result(NOT_MODIFIED,
			"First Name does not appear to be valid, unchanged.");
		return undef;
	} # if errors
	$self->_set_result(OK,"validate_Firstname returned OK");
	return $value;
} # validate_Firstname


sub validate_Lastname {
	my $self = shift;
	my $value = shift;
	$self->_clear_result unless __PACKAGE__ eq caller;
	
	if (ref($value) eq 'HASH') {
		$value = $value->{Lastname} || undef;
	}
	
	unless (defined $value) {
		$self->_set_result(BAD_REQUEST,
			"No Lastname provided for validation.");
		return undef;
	} # if value not provided
	
	my $errors = 0;
	
	
	if (length($value) < 2 || $value !~ /\w+/) {
		$self->_set_result(CONTINUE,
			'Last Name appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($value) > 30) {
		$self->_set_result(CONTINUE, 'Last Name appears to be too long.');
		$errors++;
	} # field too long
	
	(my @bad_characters) = $value =~ /([^\w\-\' ]+)/g;
	if (@bad_characters) {
		$self->_set_result(CONTINUE,
			"Last Name contains invalid characters (@bad_characters).");
		$errors++;
	} # unless minimally valid
	
	
	if ($errors) {
		$self->_set_result(NOT_MODIFIED,
			"Last Name does not appear to be valid, unchanged.");
		return undef;
	} # if errors
	$self->_set_result(OK,"validate_Lastname returned OK");
	return $value;
} # validate_Lastname


sub validate_Phone {
	my $self = shift;
	my $value = shift;
	$self->_clear_result unless __PACKAGE__ eq caller;
	
	if (ref($value) eq 'HASH') {
		$value = $value->{Phone} || undef;
	}
	
	unless (defined $value) {
		$self->_set_result(BAD_REQUEST,
			"No Phone provided for validation.");
		return undef;
	} # if value not provided
	
	my $errors = 0;
	
	
	if (length($value) < 3 || $value !~ /\d+/) {
		$self->_set_result(CONTINUE,
			'Phone Number appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($value) > 20) {
		$self->_set_result(CONTINUE, 'Phone Number appears to be too long.');
		$errors++;
	} # field too long
	
	(my @bad_characters) = $value =~ /([^\d\-. )(]+)/g;
	if (@bad_characters) {
		$self->_set_result(CONTINUE,
			"Phone # contains invalid characters (@bad_characters).");
		$errors++;
	} # unless phone # minimally valid
	
	if ($errors) {
		$self->_set_result(NOT_MODIFIED,
			"Phone does not appear to be valid, unchanged.");
		return undef;
	} # if errors
	$self->_set_result(OK,"validate_Phone returned OK");
	return $value;
} # validate_Phone


sub validate_Email {
	my $self = shift;
	my $value = shift;
	$self->_clear_result unless __PACKAGE__ eq caller;
	
	if (ref($value) eq 'HASH') {
		$value = $value->{Email} || undef;
	}
	
	unless (defined $value) {
		$self->_set_result(BAD_REQUEST,
			"No Email provided for validation.");
		return undef;
	} # if value not provided
	
	my $errors = 0;
	if (length($value) < 6 || $value !~ /\w{2}/) {
		$self->_set_result(CONTINUE,
			'Email Address appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($value) > 50) {
		$self->_set_result(CONTINUE, 'Email Address appears to be too long.');
		$errors++;
	} # field too long
	
	(my @bad_characters) = $value =~ /([^\w\-.\@]+)/g;
	if (@bad_characters) {
		$self->_set_result(CONTINUE,
			"Email '$value' contains invalid characters (@bad_characters).");
		$errors++;
	} # if bad characrters
	
	unless ($value =~ /[\w\-.]+\@[\w\-.]+\.[\w\-.]{2}/) {
		$self->_set_result(CONTINUE,
			"Email provided does not appear to be a valid format.");
		$errors++;
	} # unless Email # minimally valid
	
	
	if ($errors) {
		$self->_set_result(NOT_MODIFIED,
			"Email does not appear to be valid, unchanged.");
		return undef;
	} # if errors
	$self->_set_result(OK,"validate_Email returned OK");
	return $value;
} # validate_Email


sub validate_Address1 {
	my $self = shift;
	my $value = shift;
	$self->_clear_result unless __PACKAGE__ eq caller;
	
	if (ref($value) eq 'HASH') {
		$value = $value->{Address1} || undef;
	}
	
	unless (defined $value) {
		$self->_set_result(BAD_REQUEST,
			"No Address1 provided for validation.");
		return undef;
	} # if value not provided
	
	my $errors = 0;
	
	
	if (length($value) < 6 || $value !~ /\w+/) {
		$self->_set_result(CONTINUE,
			'Address line 1 appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($value) > 100) {
		$self->_set_result(CONTINUE,
			'Address line 1 appears to be too long.');
		$errors++;
	} # field too long
	
	(my @bad_chars) = $value =~ /([^\w\-.# ]+)/g;
	if (@bad_chars) {
		$self->_set_result(CONTINUE,
			"Address line 1 contains bad characters (@bad_chars).");
		$errors++;
	} # line contains bad characters
	
	
	if ($errors) {
		$self->_set_result(NOT_MODIFIED,
			"Address1 does not appear to be valid, unchanged.");
		return undef;
	} # if errors
	$self->_set_result(OK,"validate_Address1 returned OK");
	return $value;
} # validate_Address1


sub validate_Address2 {
	my $self = shift;
	my $value = shift;
	$self->_clear_result unless __PACKAGE__ eq caller;
	
	if (ref($value) eq 'HASH') {
		$value = $value->{Address2} || undef;
	}
	
	unless (defined $value) {
		$self->_set_result(BAD_REQUEST,
			"No Address2 provided for validation.");
		return undef;
	} # if value not provided
	
	my $errors = 0;
	
	
	if (length($value) < 6 || $value !~ /\w+/) {
		$self->_set_result(CONTINUE,
			'Address line 2 appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($value) > 100) {
		$self->_set_result(CONTINUE,
			'Address line 2 appears to be too long.');
		$errors++;
	} # field too long
	
	(my @bad_chars) = $value =~ /([^\w\-.# ]+)/g;
	if (@bad_chars) {
		$self->_set_result(CONTINUE,
			"Address line 2 contains bad characters (@bad_chars).");
		$errors++;
	} # line contains bad characters
	
	
	if ($errors) {
		$self->_set_result(NOT_MODIFIED,
			"Address2 does not appear to be valid, unchanged.");
		return undef;
	} # if errors
	$self->_set_result(OK,"validate_Address2 returned OK");
	return $value;
} # validate_Address2


sub validate_City {
	my $self = shift;
	my $value = shift;
	$self->_clear_result unless __PACKAGE__ eq caller;
	
	if (ref($value) eq 'HASH') {
		$value = $value->{City} || undef;
	}
	
	unless (defined $value) {
		$self->_set_result(BAD_REQUEST,
			"No City provided for validation.");
		return undef;
	} # if value not provided
	
	my $errors = 0;
	
	
	if (length($value) < 2 || $value !~ /\w+/) {
		$self->_set_result(CONTINUE,
			'City appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($value) > 30) {
		$self->_set_result(CONTINUE, 'City appears to be too long.');
		$errors++;
	} # field too long
	
	(my @bad_chars) = $value =~ /([^\w\-. ]+)/g;
	if (@bad_chars) {
		$self->_set_result(CONTINUE,
			"City contains bad characters (@bad_chars).");
		$errors++;
	} # line contains bad characters
	
	
	if ($errors) {
		$self->_set_result(NOT_MODIFIED,
			"City does not appear to be valid, unchanged.");
		return undef;
	} # if errors
	$self->_set_result(OK,"validate_City returned OK");
	return $value;
} # validate_City


sub validate_State {
	my $self = shift;
	my $value = shift;
	$self->_clear_result unless __PACKAGE__ eq caller;
	
	if (ref($value) eq 'HASH') {
		$value = $value->{State} || undef;
	}
	
	unless (defined $value) {
		$self->_set_result(BAD_REQUEST,
			"No State provided for validation.");
		return undef;
	} # if value not provided
	
	my $errors = 0;
	
	
	if (length($value) < 2 || $value !~ /\w+/) {
		$self->_set_result(CONTINUE,
			'State appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($value) > 20) {
		$self->_set_result(CONTINUE, 'State appears to be too long.');
		$errors++;
	} # field too long
	
	(my @bad_chars) = $value =~ /([^\w\-.]+)/g;
	if (@bad_chars) {
		$self->_set_result(CONTINUE,
			"State contains bad characters (@bad_chars).");
		$errors++;
	} # line contains bad characters
	
	
	if ($errors) {
		$self->_set_result(NOT_MODIFIED,
			"State does not appear to be valid, unchanged.");
		return undef;
	} # if errors
	$self->_set_result(OK,"validate_State returned OK");
	return $value;
} # validate_State


sub validate_Country {
	my $self = shift;
	my $value = shift;
	$self->_clear_result unless __PACKAGE__ eq caller;
	
	if (ref($value) eq 'HASH') {
		$value = $value->{Country} || undef;
	}
	
	unless (defined $value) {
		$self->_set_result(BAD_REQUEST,
			"No Country provided for validation.");
		return undef;
	} # if value not provided
	
	my $errors = 0;
	
	
	if (length($value) < 2 || $value !~ /\w+/) {
		$self->_set_result(CONTINUE,
			'Country appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($value) > 30) {
		$self->_set_result(CONTINUE, 'Country appears to be too long.');
		$errors++;
	} # field too long
	
	(my @bad_chars) = $value =~ /([^\w\-. ]+)/g;
	if (@bad_chars) {
		$self->_set_result(CONTINUE,
			"Country contains bad characters (@bad_chars).");
		$errors++;
	} # line contains bad characters
	
	
	if ($errors) {
		$self->_set_result(NOT_MODIFIED,
			"Country does not appear to be valid, unchanged.");
		return undef;
	} # if errors
	$self->_set_result(OK,"validate_Country returned OK");
	return $value;
} # validate_Country


sub validate_Zip {
	my $self = shift;
	my $value = shift;
	$self->_clear_result unless __PACKAGE__ eq caller;
	
	if (ref($value) eq 'HASH') {
		$value = $value->{Zip} || undef;
	}
	
	unless (defined $value) {
		$self->_set_result(BAD_REQUEST,
			"No Zip provided for validation.");
		return undef;
	} # if value not provided
	
	my $errors = 0;
	
	
	if ($value !~ /\d{5}/) {
		$self->_set_result(CONTINUE,
			'Zip appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($value) > 10) {
		$self->_set_result(CONTINUE, 'Zip appears to be too long.');
		$errors++;
	} # field too long
	
	(my @bad_chars) = $value =~ /([^[0-9]\-]+)/g;
	if (@bad_chars) {
		$self->_set_result(CONTINUE,
			"Zip contains bad characters (@bad_chars).");
		$errors++;
	} # line contains bad characters
	
	
	if ($errors) {
		$self->_set_result(NOT_MODIFIED,
			"Zip does not appear to be valid, unchanged.");
		return undef;
	} # if errors
	$self->_set_result(OK,"validate_Zip returned OK");
	return $value;
} # validate_Zip


sub new_user_email {
	my $self = shift;
	my $HR_params = shift;
	$self->error("Parameters not passed as a hashref")
		unless ref($HR_params) eq 'HASH';
	
	my @call = caller(1);
	$call[1] =~ s{.+/}{};
	my $name = $self->{Firstname} . ' ' . $self->{Lastname};
	
	my $notify_emails
		= $self->{CLIENTS}{$HR_params->{CLIENT}}{New_User_Notification_Email};
	my $client_name = $self->{CLIENTS}{$HR_params->{CLIENT}}{Name};
	
	warn "CLIENT = $HR_params->{CLIENT}\n" . Dumper($self->{CLIENTS})
		if $self->{debug} > 1;
	
	my $message = <<BODY;
$client_name, Central Authorization Server

Dear $name,
	You have registered with username $self->{Username} and were added to
the default user group. If you did not register, please reply to this email
and notify the administrator immediately.

	Although this email is sent to indicate that you have successfully
registered on the $client_name Central Authorization Server, you may still
require special permissions to be set. You should notify your administrative
contact for this system to request appropriate access be granted. In most
cases, simply replying to all on this email and entering your request at the
top will initiate the required actions.

Thank you!

Mail generated for $call[1] by CAS::User V$VERSION

BODY
	
	my $from = $self->{ADMIN_EMAIL};
	
	my %mail = (
		To      => $self->{Email},
		Cc      => $notify_emails ,
		From    => $from,
		Message => $message,
		smtp    => 'darwin.bu.edu',
		Subject => "$self->{Username} registered with $client_name CAS",
	);
	sendmail(%mail) or $self->error("Mail error: $Mail::Sendmail::error");
	$self->_set_result(OK,"new_user_email");
} # new_user_email


sub Password {
	my $self = shift;
	my $class = blessed($self);
	$self->error("Not a method call") unless $class;
	$self->_clear_result unless __PACKAGE__ eq caller;
	$self->error('No user ID found in self?!') unless $self->{ID};
	
	if (@_) {
		error('No user ID found in self?!') unless $self->{ID};
		
		my $value = $self->validate_Password(@_);
		return undef unless defined $value;
		
		$self->{Password} = $self->crypt_pass($value);
		$self->{changed}{Password} = 1;
	} # if setting password
	
	$self->_set_result(OK,"Password was set");
	return $self->{Password};
} # set_Password


sub crypt_pass {
	my $self   = shift;
	my $passwd = shift || '';
	
	my @salt  = ('a' .. 'z', 0 .. 9, '/', 'A' .. 'Z', '.');
	my $salt = join('', (@salt[int(rand($#salt)), int(rand($#salt))]));
	
	if ($passwd) {
		$self->_set_result(OK,"crypt_pass");
		return crypt($passwd,$salt);
	} # if we were provided a password, just encrypt
	
	my @chars = ('*', '_', '-', @salt, '#', '!', '@');
	my $word;
	foreach (0 .. int(rand(2))+6) { $word .= $chars[int(rand($#chars))] };
	
	$self->_set_result(OK,"passgen returned OK");
	return ($word,crypt($word,$salt));
} # passgen


# only setting username and password need special handling and all the rest
# are in UserInfo
sub AUTOLOAD {
	my $self = shift;
	return if ($AUTOLOAD =~ /DESTROY/);
	
	my $class = blessed($self);
	$self->error("Not a method call") unless $class;
	
#	confess("What is going on with $class!!!");
	
	$self->_clear_result unless __PACKAGE__ eq caller;
	
	# nice idea - to many calls in new and load though
#	$self->error("No user ID found in self ($class) at $AUTOLOAD?!")
#		if (caller[0])[3] ne 'new' and ! $self->{ID};
	
	my $name = $AUTOLOAD;
	$name =~ s/.*://; # strip fully-qualified portion
	
	unless (exists $self->{_permitted}->{$name} ) {
	    $self->error("Can't access `$name' field in class $class");
	} # unless access to the data feild is permitted
	
	if (@_) {
		$self->error("Not allowed to set $name")
			unless $self->{_permitted}{$name} & 2;
		
		# Simple attributes only accept a value as the only argument
		# some attributes may require more, but those should all be
		# handled by the attributes validation method, which returns
		# the value to set id valid
		my $value = $_[0];
		
		my $validation_method = "validate_$name";
		if ($self->can($validation_method)) {
			# validation methods return the value if valid
			$value = $self->$validation_method(@_);
			unless (defined $value) {
				$self->_set_result(NOT_MODIFIED,
					"$name invalid, attribute not changed");
				return undef;
			}
		} # if attribute requires validation
		
		$self->{changed}{$name} = 1;
		$self->{$name} = $value;
		$self->_set_result(OK,"Set $name");
		return $self->{$name};
	} # if a new value supplied
	
	else {
		$self->error("Not allowed to fetch $name")
			unless $self->{_permitted}{$name} & 1;
		$self->_set_result(OK,"Fetched $name");
		return $self->{$name};
	} # else just return current value
} # AUTOLOAD


1;
__END__

=head1 TO DO

If client id is provided data from the client table should also be loaded into
the user object.

Determine what additional address fields might be advisable. And if addresses
should be placed in a separate table to allow users to have multiple addresses.

=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.22 with options

  -AXC
	-n
	CAS::User

=item 0.2

Base adaption.

=item 0.21

new, load, validate, get an set methods in place as well as stub new user
email notification. Next come the tests.

=item 0.22

Added tests for user object and disable/enable methods. Small additions to docs.

=back


=head1 SEE ALSO

L<CAS>

The home page for this project is perl-cas.org.

The mailing list for Perl CAS can be found at:
http://mail.perl-cas.org/mailman/listinfo/developers_perl-cas.org

=head1 AUTHOR

Sean Quinlan, E<lt>gilant@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2004-2005 by Sean Quinlan

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut
