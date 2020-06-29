package Stance::Vault;
use strict;
use warnings;

our $VERSION = "1.0.0";

use LWP::UserAgent qw//;
use JSON           qw//;
use HTTP::Request  qw//;

sub from_json {
	JSON->new->utf8->decode(@_);
}
sub to_json {
	JSON->new->utf8->encode(@_);
}

sub new {
	my ($class, $vault_addr) = @_;
	$vault_addr ||= $ENV{VAULT_ADDR};
	$vault_addr ||= "http://127.0.0.1:8200";
	$vault_addr =~ s|/$||;

	bless {
		 ua    => LWP::UserAgent->new(agent => __PACKAGE__.'/'.$VERSION),
		 vault => $vault_addr,
		_debug => $ENV{STANCE_VAULT_DEBUG} && $ENV{STANCE_VAULT_DEBUG} eq 'on',
		_error => undef,
	}, $class;
}

sub debug {
	my ($self, $on) = @_;
	$self->{_debug} = !!$on;
}

sub url {
	my ($self, $rel) = @_;
	$rel ||= '/';
	$rel =~ s|^/||;

	return "$self->{vault}/$rel";
}

sub get {
	my ($self, $url) = @_;

	my $req = HTTP::Request->new(GET => $self->url($url))
		or die "unable to create GET $url request: $!\n";
	$req->header('Accept' => 'application/json');
	$req->header('X-Vault-Token', '[REDACTED]')
		if $self->{_token};
	if ($self->{_debug}) {
		print STDERR "=====[ GET $url ]========================\n";
		print STDERR $req->as_string;
		print STDERR "\n\n";
	}
	$req->header('X-Vault-Token', $self->{_token})
		if $self->{_token};

	my $res = $self->{ua}->request($req)
		or die "unable to send GET $url request: $!\n";
	if ($self->{_debug}) {
		print STDERR "-----------------------------------------\n";
		print STDERR $res->as_string;
		print STDERR "\n\n";
	}

	my $body = from_json($res->decoded_content);
	if (!$res->is_success) {
		$self->{_error} = $body;
		return undef;
	}
	return $body;
}

sub post {
	my ($self, $url, $payload) = @_;

	my $req = HTTP::Request->new(POST => $self->url($url))
		or die "unable to create POST $url request: $!\n";
	$req->header('Accept' => 'application/json');
	$req->header('Content-Type', 'application/json');
	$req->header('X-Vault-Token', '[REDACTED]')
		if $self->{_token};
	$req->content(to_json($payload)) if $payload;
	if ($self->{_debug}) {
		print STDERR "=====[ POST $url ]========================\n";
		print STDERR $req->as_string;
		print STDERR "\n\n";
	}
	$req->header('X-Vault-Token', $self->{_token})
		if $self->{_token};

	my $res = $self->{ua}->request($req)
		or die "unable to send POST $url request: $!\n";
	if ($self->{_debug}) {
		print STDERR "-----------------------------------------\n";
		print STDERR $res->as_string;
		print STDERR "\n\n";
	}

	my $body = from_json($res->decoded_content);
	if (!$res->is_success) {
		$self->{_error} = $body;
		return undef;
	}
	return $body;
}

sub last_error {
	my ($self) = @_;
	return $self->{_error};
}

sub authenticate {
	my ($self, $method, $creds) = @_;

	if ($method eq 'token') {
		$self->{_token} = $creds;
		return $self;
	}

	if ($method eq 'app_role') {
		my ($ok, $token) = $self->post('/v1/auth/approle/login', {
			role_id   => $creds->{role_id},
			secret_id => $creds->{secret_id},
		});
		if (!$ok) {
			return undef;
		}

		$self->{_token} = $token->{auth}{client_token};
		$self->{_renew} = $token->{auth}{lease_duration};

		my $pid = fork;
		if ($pid) {
			$self->{pid} = $pid;
			return $self;
		}

		# in child process...
		$self->renew();
	}

	die "unrecognized authentication method '$method'!";
}

sub renew {
	my ($self) = @_;
	while ($self->{_renew}) {
		$self->{_renew} /= 2;
		sleep($self->{_renew});

		my ($ok, $renewal) = $self->post('/v1/auth/token/renew-self', {});
		if ($ok) {
			$self->{_renew} = $renewal->{auth}{lease_duration};
		}
	}
}

sub kv_set {
	my ($self, $path, $data) = @_;
	$path =~ s|^/||;
	return $self->post("/v1/secret/data/$path", {
		options => {
			cas => 0,
		},
		data => $data
	});
}

sub kv_get {
	my ($self, $path) = @_;
	$path =~ s|^/||;
	return $self->get("/v1/secret/data/$path");
}

=head1 NAME

Stance::Vault - A Perl Interface to Hashicorp Vault

=head1 DESCRIPTION

C<Stance::Vault> provides an object-oriented interface to the Hashicorp Vault API.

=head1 CONSTRUCTOR METHODS

=head2 new

    my $vault = Stance::Vault->new($VAULT_ADDR);

Create a new Vault client object, pointed at the given remote Vault endpoint,
which must be given as a full HTTP(S) URL, including non-standard ports.

=head1 INSTANCE METHODS

=head2 authenticate

    $vault->authenticate(token => $TOKEN);

Set authentication parameters for subsequent requests to the Vault API.
Currently, only the C<token> authentication scheme is understood.

Returns the client object itself, to allow (and encourage) chaining off
of the C<new()> constructor:

    my $c = Stance::Vault->new()->authenticate(token => $T);

=head2 kv_get

    my $secret = $vault->kv_get('secret/path/to/get')
        or die $vault->last_error;

Retrieves a secret from the Vault.  This will include metadata, and the
Vault API framing; most of the time you'll be looking for attributes under
the C<{data}{data}> subkeys:

    my $secret = $vault->kv_get($path);
    print "the password is: $secret->{data}{data}{password}\n";

=head2 kv_set

    $vault->kv_set('secret/path/to/set', \%attrs)
        or die $vault->last_error;

Writes a secret to the Vault, at the given path.  While in theory tou can
set arbitrarily deep hashes, some tools expect flat, string-based hashes.

=head2 debug

    $vault->debug(1);

Enables or disables debugging.  When debugging is enabled, HTTP
requests and responses will be printed to standard error, to aide
in troubleshooting efforts.

=head2 last_error

    die $vault->last_error;

Whenever a logical failure (above the transport) occurs, the Vault
client stores it for later retrieval.  This method retrieves the most
recently encountered error.

Note that intervening successes will not clear the error, so it's best
to only rely on this method when another method has signaled failure
(i.e. by returning C<undef> in place of an actual result.)

=cut

1;
