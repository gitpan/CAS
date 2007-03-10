package CAS::Messaging;

=head1 NAME

CAS::Messaging - Base class for class message & error handling. Not intended
for external use.

=head1 SYNOPSIS

  use CAS::Constants;

=head1 DESCRIPTION

Exports the following constants into callers namespace:
	CONTINUE              => 100
	OK                    => 200
	CREATED               => 201
	ACCEPTED              => 202
	NOT_MODIFIED          => 304
	BAD_REQUEST           => 400
	UNAUTHORIZED          => 401
	AUTH_REQUIRED         => 401
	FORBIDDEN             => 403
	NOT_FOUND             => 404
	METHOD_NOT_ALLOWED    => 405
	NOT_ACCEPTABLE        => 406
	REQUEST_TIME_OUT      => 408
	TIME_EXPIRED          => 408
	CONFLICT              => 409
	GONE                  => 410
	ERROR                 => 500
	INTERNAL_SERVER_ERROR => 500
	NOT_IMPLEMENTED       => 501

Definitions of response codes:

=over 4

=item B<CONTINUE>

The client may continue with its request. Generally only used inside
methods where multiple steps may be required.

=item B<OK>

The request has succeeded. Accept for certain special circumstances where
another code is defined as expected, this is the code that should be set
when any method completes its task sucessfully (as far as we know).

=item B<CREATED>

The is the code set when a new object was succesfully created.

=item B<ACCEPTED>

Indicates the request has been accepted for processing, but the processing has
not been completed.

=item B<NOT_MODIFIED>

A request was made to save or change something that resulted in no actual
change, but no system error occured. Such as when setting an attribute to a
value that is not allowed.

=item B<BAD_REQUEST>

The request could not be understood by the server due to malformed syntax or
missing required arguments.

=item B<UNAUTHORIZED>

The request requires user authentication.

=item B<AUTH_REQUIRED>

As L<UNAUTHORIZED>.

=item B<FORBIDDEN>

The server understood the request, but is refusing to fulfill it because the
user or requesting client lacks the required authorization.

=item B<NOT_FOUND>

The server understood the request, but the requested resource (such as a user
or client) was not found.

=item B<METHOD_NOT_ALLOWED>

The requested method is not allowed in the current context or by the
calling object. 

=item B<REQUEST_TIME_OUT>

The client did not produce a request within the time that the server was
prepared to wait. Or, in the more common context of the user, their log-in
period has timed out and they need to re-authenticate.

=item B<TIME_EXPIRED>

As L<REQUEST_TIME_OUT>.

=item B<CONFLICT>

The request could not be completed due to a conflict with the current state of
the resource.

=item B<ERROR>

The server encountered some condition which prevented it from
fulfilling the request. Serious internal problems, such as malformed SQL
statements will also die. This condition is more commonly set when a request
appeared valid but was impossible to complete, such as a well formed new
user request, but where the username was already taken. All methods initially
set the response code to ERROR and then change it when appropriate.

=item B<INTERNAL_SERVER_ERROR>

As L<ERROR>.

=item B<NOT_IMPLEMENTED>

The server does not support the functionality required to fulfill the request.

=back

These values are drawn from Apache's response codes, since this system is
intended to be generally accessed via an Apache server. While error text
will be stored in B<errstr>, the RESPONSE_CODE can be checked to see the
reason for failure.

=cut

use strict;
use Scalar::Util qw(blessed);
use Carp qw(cluck confess croak carp);
use base qw(Exporter);

our $VERSION = '0.08';
our $AUTOLOAD = '';

our %codes = (
	CONTINUE              => 100,
	OK                    => 200,
	CREATED               => 201,
	ACCEPTED              => 202,
	NOT_MODIFIED          => 304,
	BAD_REQUEST           => 400,
	UNAUTHORIZED          => 401,
	AUTH_REQUIRED         => 401,
	FORBIDDEN             => 403,
	NOT_FOUND             => 404,
	METHOD_NOT_ALLOWED    => 405,
	NOT_ACCEPTABLE        => 406,
	REQUEST_TIME_OUT      => 408,
	TIME_EXPIRED          => 408,
	CONFLICT              => 409,
	GONE                  => 410,
	ERROR                 => 500,
	INTERNAL_SERVER_ERROR => 500,
	NOT_IMPLEMENTED       => 501,
);
use constant \%codes;
use constant {
	CONTINUE              => 100,
	OK                    => 200,
	CREATED               => 201,
	ACCEPTED              => 202,
	NOT_MODIFIED          => 304,
	BAD_REQUEST           => 400,
	UNAUTHORIZED          => 401,
	AUTH_REQUIRED         => 401,
	FORBIDDEN             => 403,
	NOT_FOUND             => 404,
	METHOD_NOT_ALLOWED    => 405,
	NOT_ACCEPTABLE        => 406,
	REQUEST_TIME_OUT      => 408,
	TIME_EXPIRED          => 408,
	CONFLICT              => 409,
	GONE                  => 410,
	ERROR                 => 500,
	INTERNAL_SERVER_ERROR => 500,
	NOT_IMPLEMENTED       => 501,
};

our $Errmsg = '';
our @EXPORT = (keys %codes,qw($Errmsg));

# we need to be able to get the string by value sometimes
# it doesn't matter here if an alias gets lost
our %code_name_by_val = reverse %codes;

# set the result information in self
sub _set_result {
	my $self = shift;
	$self->error("Not a method call") unless blessed($self);
	my $debug = $self->{debug} || 0;
	
	my $code = shift || ERROR; # no code == bad ;)
	$self->error("Unknown result code $code") unless $code_name_by_val{$code};
	$self->{response_code} = $code;
	
	my @call = caller;
	my $msg = shift;
	unless ($msg) {
		$msg = 'No message provided by ' . $call[0];
	} # no message, blame caller
	
	if ($debug) {
		$msg = "($call[0]:" . "[$call[2]]) $msg";
	} # if debugging make sure we know where from
	
	push(@{$self->{messages}}, $msg);
	
	# If debugging is at 2 or more, we're generating very noisy output as well
	$self->gripe("_set_result ($code): $msg") if $self->{debug} >= 2;
} # _set_result


sub _clear_result {
	my $self = shift;
	$self->error("Not a method call") unless blessed($self);
	
	# we set the code to error as any call to _clear_result should be
	# internal, and anything happening before a different result is set that
	# stops processing is almost certainly an error
	$self->{response_code} = ERROR;
	$self->{messages} = [];
} # _sclear_result


# Checks to see if the provided code matches the current response_code
# accept either value or text
sub response_is {
	my $self = shift;
	$self->error("Not a method call") unless blessed($self);
	my $code = shift || $self->error("No response code specified");
	
	if ($codes{$code}) { $code = $codes{$code} }
	
	$self->error("Unknown code $code") unless exists $code_name_by_val{$code};
	
	return 1 if $self->{response_code} == $code;
	return undef;
} # response_is

# returns the text version of the code, useful mostly in error reporting
sub response_code {
	my $self = shift;
	$self->error("Not a method call") unless blessed($self);
	
	# return the key string for the current code
	return $code_name_by_val{$self->{response_code}};
} # response_code

# get the numerical value from the code name
sub code_value {
	my $self = shift;
	$self->error("Not a method call") unless blessed($self);
	
	my $name = shift;
	$self->gripe("Unknown code $name") unless exists $codes{$name};
	return $codes{$name} if exists $codes{$name};
	return undef;
} # response_code


=head2 messages

Messages return any processing messages. While sometimes useful information
can be found here for debugging, generally the only reason to call this method
is to see what happened that caused an error or other invalid response.

  unless ($user->validate_Password($HR_params)) {
    die "Password not validated: $user->messages";
  } # unless valid password provided

Note that in scalar context messages will return a scalar of all messages
generated seperated with '; '. In list context it returns a list of the
messages allowing the caller to format for other display, such as HTML. As
such, the results of the die above would be very different if written as:
  die "Password not validated: ", $user->messages;

When the last method call worked as expected, then the last message in the list
should be the message generated when the result_code was set.

=cut
sub messages {
	my $self = shift;
	my $class = blessed($self);
	$self->error("Not a method call") unless $class;
	
	return wantarray ? @{$self->{messages}}
		: join('; ', $class, @{$self->{messages}});
} # messages


=head2 errstr

Presumes that there was an error, and that the last message generated most
directly relates to the cause of the error and returns only that message. Be
warned however that this might always be correct, or enough information.
Generally the whole message list is prefered.

=cut
sub errstr {
	my $self = shift;
	$self->error("Not a method call") unless blessed($self);
	
	return $self->{messages}[-1];
} # errstr


=head2 error

Throw a fatal exeption. Returns a stack trace (confess) if called when
DEBUG is true. L<gripe> actually does all the work, error just tells
gripe to die.

=cut
sub error {
	my $self = shift;
	confess("Not a method call") unless blessed($self);
	
	$self->gripe(@_,1); # @_ should only contain the message
} # error

=head2 gripe

Generate debug sensitive warnings and exceptions. gripe also writes warnings
to a scratch pad in the calling object so that warning_notes method can
return all warnings generated. This behavior mirrors that of
L<DNAcore::WWW::Exceptions> for objects rather than CGI's.

Suggested debug level usage (as level goes up messages from earlier levels
should continue to be sent):

0:	Production. Perls warnings should _not_ be turned on and no debug
messages should be generated.

1:	Basic development level. Perls warnings are turned on. Basic debug
messages should be generated. L<error> dies with stack trace (confess) and
outputs all stored messages.

2:	Shotgun debugging. Code should now be generating debug messages when
entering and/or exiting important blocks so that program flow can be
observed.

3:	Turns on Perls diagnostics. At this level messages should be generated for
every pass through loops. This would also be the appropriate level to dump
data structures at critical points. Gripe now includes stack trace with every
invocation. It is realistic to expect hundreds of lines of output at _least_ at
this level. This would be the most verbose debug level.

4:	Autodie - gripe will now throw a fatal exception with confess.*

* Currently this happens the first time called. However it realy should only
die the first time a message intended to be sent only at debug levels >= 1.

=cut
sub gripe {
	my $self = shift;
	my $class = blessed($self);
	croak("Not a method call") unless $class;
	my $msg = shift || confess("Class $class threw warning without message");
	my $die = shift || 0;
	
	my @call = caller;
	@call = caller(1) if $die;
	
	# determine debug level, & set to die if told to be extremely verbose
	my $debug = $self->{debug} || 0;
	$die = 1 if $debug > 3;
	
	# just to be paranoid, we'll unlock tables on fatal error
	# tables left locked can block future operations and would require
	# root to unlock by hand
	if ($die && ref $self->{dbh} && $self->{dbh}->ping) {
		$self->{dbh}->do("UNLOCK TABLES");
	} # if dieing and DBH 
	
	if ($debug) {
		$msg = "($call[0]" . "[$call[2]]) $msg";
	} # if debugging
	
	# to make sure we know what class the object that called us belongs to
	$msg = "$class: $msg";
	if (exists $self->{ERRORLOG} && openhandle($self->{ERRORLOG})) {
		my $logmsg = ($die && $debug) || $debug >= 2
			? Carp::longmess($msg) : Carp::shortmess($msg);
		my $fh = $self->{ERRORLOG};
		print $fh $logmsg;
	} # if user wants errors loged
	
	# if we're dying and debug is on
	if ($die && $debug) { confess("$msg\n" . $self->messages) }
	elsif ($die) { croak($msg) } # or die with just the message
	elsif ($debug >= 2) { cluck("$msg\n") } # verbose warn
	else { carp("$msg\n") } # just let em know the basics
} # gripe


=head1 AUTHOR

Sean P. Quinlan, C<< <gilant at gmail.com> >>

=head1 TO DO / development notes

Gripe should have a way to output to a filehandle (provided when object
created) so that output can be optionally logged. Should _set_result also
record each invocation to the log if debugging?

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

Copyright 2006 Sean P. Quinlan, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of CAS::Messaging
