package DDNS;

@DDNS::ISA = qw(SOAP::Server::Parameters);

use DBI;
use Digest::MD5 qw(md5);
use Data::Dumper;
use Digest::MD5::File qw(file_md5_hex);
use File::Path;

# ----------------------------------------------------------------------
# Funciones privadas
# ----------------------------------------------------------------------

my $debug = 0;

# Tiempo en minutos en que se vence el sincro.
my $timeout = 3600;

my $dbhost = 'localhost';
my $dbname = 'CfparkNG';
my $dbuser = 'cfparkng';
my $dbpass = '35l0qu3h4y';
my $dbpsaname = 'psa';
my $dbpsauser = 'ddns';
my $dbpsapass = '4ctu4l1z0dns';

my $dbh = DBI->connect("DBI:mysql:$dbname;host=$dbhost", $dbuser, $dbpass) || die "Could not connect to database: $DBI::errstr";
my $dbhpsa = DBI->connect("DBI:mysql:$dbpsaname;host=$dbhost", $dbpsauser, $dbpsapass) || die "Could not connect to database: $DBI::errstr";

my $calculateAuthInfo = sub {
	return md5(join '', 'Passphrase para DDNS', @_);
};

my $checkAuthInfo = sub {
	my $authInfo = shift;
	my $signature = $calculateAuthInfo->(@{$authInfo}{qw(usuario time)});

	if ($signature ne $authInfo->{signature}) {
		logmsg("La firma de la conexion no es valida\n");
		return "ERRSIGERR";
	}
	if (time() > $authInfo->{time}) {
		logmsg("La firma de la conexion ha expirado\n");
		return "ERRTIMEOUT";
	}
	return $authInfo->{usuario};
};

my $makeAuthInfo = sub {
	my $usuario = shift;
	my $time = time()+$timeout*60;
	my $signature = $calculateAuthInfo->($usuario, $time);
#	print STDERR "SIGNATURE: $signature\n";
	return +{time => $time, usuario => $usuario, signature => $signature};
};

# ----------------------------------------------------------------------
# Funciones publicas
# ----------------------------------------------------------------------

sub logmsg {
	print STDERR scalar localtime, ": @_ \n";
}


sub login {
	my $self = shift;

	pop; # last parameter is envelope, don't count it

	die "Error en la validación: login(usuario, password)\n" unless @_ == 2;
	my($usuario, $password) = @_;
	print STDERR "USUARIO: $usuario PASSWORD: $password\n" if ($debug);

	# check credentials, write your own is_valid() function
	#die "Credentials are wrong\n" unless is_valid($email, $password);

	# create and return ticket if everything is ok
	return $makeAuthInfo->($usuario);
}


sub validar_usuario
{
	my $self = shift;
	pop; # last parameter is envelope, don't count it

	if (@_ != 2) {
		return +{time => '', usuario => '', signature => 'NOK'};
	}
	my($usuario, $password) = @_;

	if (($usuario eq '') || ($password eq '')) {
		return +{time => '', usuario => $usuario, signature => 'NOK'};
	}

	$sth = $dbh->prepare("SELECT ID FROM Datos_Cajero WHERE Login = ? AND Password = MD5(?) AND Accede_DDNS LIKE 'Si'");

	$sth->execute($usuario, $password);
	if ($sth->rows == 1) {
		return $makeAuthInfo->($usuario);
	} else {
		return +{time => '', usuario => $usuario, signature => 'NOK'};
	}

}


sub actualizar_dns
{
	print STDERR "ACTUALIZAR DNS\n" if $debug;
	my $self = shift;
#	print STDERR Dumper($self);
	my $usuario = $checkAuthInfo->(pop->valueof('//authInfo'));
	print STDERR "USUARIO: $usuario\n" if $debug;
	return $usuario if ($usuario =~ m/^ERR/);

#	pop; # last parameter is envelope, don't count it

	my($host) = @_;

	my $nombre = '';
	my $last_id = -1;

	# Primero chequea si el registro existe previamente.
	# Si el registro pertence a la playa en cuestion y no
	# figura en la tabla, debe ser dado de alta.

	my $sql_statement = "SELECT id, val FROM dns_recs WHERE host = ?";
	print STDERR "SQL: $sql_statement\n" if $debug;

	$sth = $dbhpsa->prepare($sql_statement);
	$sth->execute($host.".");

	print STDERR "Host: $host\n" if $debug;
	# El registro no existia previamente.
	if ($sth->rows == 0) {
		# Si el registro pertenece a la playa en cuestion, lo da de
		# alta. Si no, lo ignora.
		if ($host eq $usuario) {
#			$sql_statement = "INSERT INTO ".$tabla." (".$campos.") VALUES (".$values.")";
#			my $insert = $dbh->prepare_cached($sql_statement);
#			print STDERR "SQLINS: $sql_statement\n" if $debug;
#
#			$insert->execute(@lineas) or return "NOK";
#			$last_id = $dbh->last_insert_id(undef, undef, $tabla, 'ID');
			logmsg "Host $host no existe. Se debe generar a mano";
		}

	# Si el registro existia previamente mas de uno, no lo inserta
	# y deja registrada esta anomalia en el log.
	} elsif ($sth->rows == 1) {
		my ($id, $ip) = $sth->fetchrow_array();
		my $ip_actual = $ENV{'REMOTE_ADDR'};
#		my $ip_actual = '8.8.8.8';

		if ($ip ne $ip_actual) {
			logmsg "Actualizando ip $ip_actual para el host $host";
			$sql_statement = "UPDATE dns_recs SET displayVal = ?, val = ?, time_stamp = NOW()  WHERE id = ?";
			$sth = $dbhpsa->prepare($sql_statement);
			$sth->execute($ip_actual, $ip_actual, $id);
			system ('sudo /usr/sbin/update_dns.sh');
		}
	}
	return "OK $last_id";
}



1;

