#!/usr/bin/perl

# $Id: Update.pm,v 1.7 2003/10/27 23:57:55 unimlo Exp $

package Net::BGP::Update;

use strict;
use vars qw(
    $VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS
    @BGP_PATH_ATTR_FLAGS
);

## Inheritance and Versioning ##

use Net::BGP::NLRI qw( :origin );

@ISA     = qw( Exporter Net::BGP::NLRI );
$VERSION = '0.06';

## Module Imports ##

use Carp;
use IO::Socket;
use Net::BGP::Notification qw( :errors );

## General Definitions ##

sub TRUE  { 1 }
sub FALSE { 0 }

## BGP Path Attribute Type Enumerations ##

sub BGP_PATH_ATTR_ORIGIN           { 1 }
sub BGP_PATH_ATTR_AS_PATH          { 2 }
sub BGP_PATH_ATTR_NEXT_HOP         { 3 }
sub BGP_PATH_ATTR_MULTI_EXIT_DISC  { 4 }
sub BGP_PATH_ATTR_LOCAL_PREF       { 5 }
sub BGP_PATH_ATTR_ATOMIC_AGGREGATE { 6 }
sub BGP_PATH_ATTR_AGGREGATOR       { 7 }
sub BGP_PATH_ATTR_COMMUNITIES      { 8 }

## BGP Path Attribute Flag Octets ##

@BGP_PATH_ATTR_FLAGS = (
    0x00,
    0x40,
    0x40,
    0x40,
    0x80,
    0x40,
    0x40,
    0xC0,
    0xC0
);

## Export Tag Definitions ##

@EXPORT      = ();
@EXPORT_OK   = ();
%EXPORT_TAGS = (
    ALL    => [ @EXPORT, @EXPORT_OK ]
);

## Public Methods ##

sub new
{
    my $proto = shift;
    my $class = ref $proto || $proto;

    if (ref $_[0] eq 'Net::BGP::NLRI')
     { # Construct from NLRI
       $proto = shift unless ref $proto;
       my $this = $proto->clone;
       bless($this,$class);
       $this->nlri(shift);
       $this->withdrawn(shift);
       return $this;
     };

    my ($arg, $value);
    my @super_arg;
    my %this_arg;
    $this_arg{_withdrawn} = [];
    $this_arg{_nlri} = [];

    while ( defined($arg = shift()) ) {
        $value = shift();

        if ( $arg =~ /nlri/i ) {
            $this_arg{_nlri} = $value;
        }
        elsif ( $arg =~ /withdraw/i ) {
            $this_arg{_withdrawn} = $value;
        }
        else {
            push(@super_arg,$arg,$value);
        }
    }

    my $this = $class->SUPER::new(@super_arg);

    @{$this}{keys %this_arg} = values(%this_arg);

    bless($this, $class);

    return ( $this );
}

sub clone
{
    my $proto = shift;
    my $class = ref $proto || $proto;
    $proto = shift unless ref $proto;

    my $clone = $class->SUPER::clone($proto);

    foreach my $key (qw(_nlri _withdrawn ))
     {
      $clone->{$key} = [ @{$proto->{$key}} ];
     }

    return ( bless($clone, $class) );
}

sub nlri
{
    my $this = shift();

    $this->{_nlri} = @_ ? shift() : $this->{_nlri};
    return ( $this->{_nlri} );
}

sub withdrawn
{
    my $this = shift();

    $this->{_withdrawn} = @_ ? shift() : $this->{_withdrawn};
    return ( $this->{_withdrawn} );
}

sub ashash
{
    my $this = shift();

    my (%res,$nlri);

    $nlri = clone Net::BGP::NLRI($this) if defined($this->{_nlri});

    foreach my $prefix (@{$this->{_nlri}})
     {
      $res{$prefix} = $nlri;
     };

    foreach my $prefix (@{$this->withdrawn})
     {
      $res{$prefix} = undef;
     };

    return \%res;
}

## Private Methods ##

sub _new_from_msg
{
    my ($class, $buffer) = @_;
    my $error;

    my $this = $class->new();

    $error = $this->_decode_message($buffer);

    return ( defined($error) ? $error : $this );
}

sub _encode_attr
{
    my ($this, $type, $data) = @_;
    my $buffer;

    $buffer  = _encode_path_attr_type($type);
    $buffer .= pack('C', length($data));
    $buffer .= $data;

    return ( $buffer );
}

sub _decode_message
{
    my ($this, $buffer) = @_;
    my $offset = 0;
    my ($length, $result, $error);

    # decode the Withdrawn Routes field
    $length = unpack('n', substr($buffer, $offset, 2));
    $offset = 2;

    if ( $length > (length($buffer) - $offset) ) {
        $error = new Net::BGP::Notification(
            ErrorCode    => BGP_ERROR_CODE_UPDATE_MESSAGE,
            ErrorSubCode => BGP_ERROR_SUBCODE_MALFORMED_ATTR_LIST
        );

        return ( $error );
    }

    $result = $this->_decode_withdrawn(substr($buffer, $offset, $length));
    $offset += $length;

    # decode the Path Attributes field
    $length = unpack('n', substr($buffer, $offset, 2));
    $offset += 2;

    if ( $length > (length($buffer) - $offset) ) {
        $error = new Net::BGP::Notification(
            ErrorCode    => BGP_ERROR_CODE_UPDATE_MESSAGE,
            ErrorSubCode => BGP_ERROR_SUBCODE_MALFORMED_ATTR_LIST
        );

        return ( $error );
    }

    $result = $this->_decode_path_attributes(substr($buffer, $offset, $length));
    $offset += $length;

    # decode the Network Layer Reachability Information field
    $result = $this->_decode_nlri(substr($buffer, $offset));

    return ( $result );
}

sub _decode_origin
{
    my ($this, $buffer) = @_;

    $this->{_origin} = unpack('C', $buffer);
    $this->{_attr_mask}->[BGP_PATH_ATTR_ORIGIN] ++;

    return ( undef );
}

sub _decode_as_path
{
    my ($this, $buffer) = @_;

    my $path = Net::BGP::ASPath->_new_from_msg($buffer);

    return new Net::BGP::Notification(
	ErrorCode    => BGP_ERROR_CODE_UPDATE_MESSAGE,
	ErrorSubCode => BGP_ERROR_SUBCODE_BAD_AS_PATH
	) unless defined $path;

    $this->{_as_path} = $path;

    $this->{_attr_mask}->[BGP_PATH_ATTR_AS_PATH] ++;

    return ( undef );
}

sub _decode_next_hop
{
    my ($this, $buffer) = @_;
    my ($error, $data);

    if ( length($buffer) != 0x04 ) {
        $data = $this->_encode_attr(BGP_PATH_ATTR_NEXT_HOP, $buffer);
        $error = new Net::BGP::Notification(
            ErrorCode    => BGP_ERROR_CODE_UPDATE_MESSAGE,
            ErrorSubCode => BGP_ERROR_SUBCODE_BAD_ATTR_LENGTH,
            ErrorData    => $data
        );

        return ( $error );
    }

    # TODO: check if _next_hop is a valid IP host address
    $this->{_next_hop} = inet_ntoa($buffer);
    $this->{_attr_mask}->[BGP_PATH_ATTR_NEXT_HOP] ++;

    return ( undef );
}

sub _decode_med
{
    my ($this, $buffer) = @_;
    my ($error, $data);

    if ( length($buffer) != 0x04 ) {
        $data = $this->_encode_attr(BGP_PATH_ATTR_MULTI_EXIT_DISC, $buffer);
        $error = new Net::BGP::Notification(
            ErrorCode    => BGP_ERROR_CODE_UPDATE_MESSAGE,
            ErrorSubCode => BGP_ERROR_SUBCODE_BAD_ATTR_LENGTH,
            ErrorData    => $data
        );

        return ( $error );
    }

    $this->{_med} = unpack('N', $buffer);
    $this->{_attr_mask}->[BGP_PATH_ATTR_MULTI_EXIT_DISC] ++;

    return ( undef );
}

sub _decode_local_pref
{
    my ($this, $buffer) = @_;
    my ($error, $data);

    if ( length($buffer) != 0x04 ) {
        $data = $this->_encode_attr(BGP_PATH_ATTR_LOCAL_PREF, $buffer);
        $error = new Net::BGP::Notification(
            ErrorCode    => BGP_ERROR_CODE_UPDATE_MESSAGE,
            ErrorSubCode => BGP_ERROR_SUBCODE_BAD_ATTR_LENGTH,
            ErrorData    => $data
        );

        return ( $error );
    }

    $this->{_local_pref} = unpack('N', $buffer);
    $this->{_attr_mask}->[BGP_PATH_ATTR_LOCAL_PREF] ++;

    return ( undef );
}

sub _decode_atomic_aggregate
{
    my ($this, $buffer) = @_;
    my ($error, $data);

    if ( length($buffer) ) {
        $data = $this->_encode_attr(BGP_PATH_ATTR_ATOMIC_AGGREGATE, $buffer);
        $error = new Net::BGP::Notification(
            ErrorCode    => BGP_ERROR_CODE_UPDATE_MESSAGE,
            ErrorSubCode => BGP_ERROR_SUBCODE_BAD_ATTR_LENGTH,
            ErrorData    => $data
        );

        return ( $error );
    }

    $this->{_atomic_agg} = TRUE;
    $this->{_attr_mask}->[BGP_PATH_ATTR_ATOMIC_AGGREGATE] ++;

    return ( undef );
}

sub _decode_aggregator
{
    my ($this, $buffer) = @_;
    my ($error, $data);

    if ( length($buffer) != 0x06 ) {
        $data = $this->_encode_attr(BGP_PATH_ATTR_AGGREGATOR, $buffer);
        $error = new Net::BGP::Notification(
            ErrorCode    => BGP_ERROR_CODE_UPDATE_MESSAGE,
            ErrorSubCode => BGP_ERROR_SUBCODE_BAD_ATTR_LENGTH,
            ErrorData    => $data
        );

        return ( $error );
    }

    $this->{_aggregator}->[0] = unpack('n', substr($buffer, 0, 2));
    $this->{_aggregator}->[1] = inet_ntoa(substr($buffer, 2, 4));
    $this->{_attr_mask}->[BGP_PATH_ATTR_AGGREGATOR] ++;

    return ( undef );
}

sub _decode_communities
{
    my ($this, $buffer) = @_;
    my ($as, $val, $ii, $offset, $count);
    my ($error, $data);

    if ( length($buffer) % 0x04 ) {
        $data = $this->_encode_attr(BGP_PATH_ATTR_COMMUNITIES, $buffer);
        $error = new Net::BGP::Notification(
            ErrorCode    => BGP_ERROR_CODE_UPDATE_MESSAGE,
            ErrorSubCode => BGP_ERROR_SUBCODE_BAD_ATTR_LENGTH,
            ErrorData    => $data
        );

        return ( $error );
    }

    $offset = 0;
    $count = length($buffer) / 4;
    for ( $ii = 0; $ii < $count; $ii++ ) {
        $as  = unpack('n', substr($buffer, $offset, 2));
        $val = unpack('n', substr($buffer, $offset + 2, 2));
        push(@{$this->{_communities}}, join(":", $as, $val));
        $offset += 4;
    }

    $this->{_attr_mask}->[BGP_PATH_ATTR_COMMUNITIES] ++;

    return ( undef );
}

sub _decode_path_attributes
{
    my ($this, $buffer) = @_;
    my ($offset, $data_length);
    my ($flags, $type, $length, $len_format, $len_bytes, $sub, $data);
    my ($error, $error_data, $ii);
    my @decode_sub = (
        undef,
        \&_decode_origin,
        \&_decode_as_path,
        \&_decode_next_hop,
        \&_decode_med,
        \&_decode_local_pref,
        \&_decode_atomic_aggregate,
        \&_decode_aggregator,
        \&_decode_communities
    );

    $offset = 0;
    $data_length = length($buffer);

    while ( $data_length ) {
        $flags   = unpack('C', substr($buffer, $offset++, 1));
        $type    = unpack('C', substr($buffer, $offset++, 1));

        $len_format = 'C';
        $len_bytes  = 1;
        if ( $flags & 0x10 ) {
            $len_format = 'n';
            $len_bytes  = 2;
        }

        $length  = unpack($len_format, substr($buffer, $offset, $len_bytes));
        $offset += $len_bytes;

        $error_data = substr($buffer, $offset - $len_bytes - 2, $length + $len_bytes + 2);
        if ( $BGP_PATH_ATTR_FLAGS[$type] != $flags ) {
            $error = new Net::BGP::Notification(
                ErrorCode    => BGP_ERROR_CODE_UPDATE_MESSAGE,
                ErrorSubCode => BGP_ERROR_SUBCODE_BAD_ATTR_FLAGS,
                ErrorData    => $error_data
            );

            return ( $error );
        }

        if ( $length > ($data_length - ($len_bytes + 2)) ) {
            $data = substr($buffer, $offset - $len_bytes - 2, $length + $len_bytes + 2);
            $error = new Net::BGP::Notification(
                ErrorCode    => BGP_ERROR_CODE_UPDATE_MESSAGE,
                ErrorSubCode => BGP_ERROR_SUBCODE_BAD_ATTR_LENGTH,
                ErrorData    => $error_data
            );

            return ( $error );
        }

        $sub = $decode_sub[$type];
        $this->$sub(substr($buffer, $offset, $length));
        $offset += $length;
        $data_length -= ($length + $len_bytes + 2);
    }

    # Check for missing mandatory well-known attributes
    $error_data = $this->{_attr_mask}->[BGP_PATH_ATTR_ORIGIN]
        ? BGP_PATH_ATTR_ORIGIN : 0;
    $error_data = $this->{_attr_mask}->[BGP_PATH_ATTR_AS_PATH]
        ? BGP_PATH_ATTR_AS_PATH : 0;
    $error_data = $this->{_attr_mask}->[BGP_PATH_ATTR_NEXT_HOP]
        ? BGP_PATH_ATTR_NEXT_HOP : 0;

    if ( $error_data ) {
        $error = new Net::BGP::Notification(
            ErrorCode    => BGP_ERROR_CODE_UPDATE_MESSAGE,
            ErrorSubCode => BGP_ERROR_SUBCODE_MISSING_WELL_KNOWN_ATTR,
            ErrorData    => pack('C', $error_data)
        );
    }

    # Check for repeated attributes
    for ( $ii = BGP_PATH_ATTR_ORIGIN; $ii <= BGP_PATH_ATTR_COMMUNITIES; $ii ++ ) {
        if ( $this->{_attr_mask}->[$ii] > 1 ) {
            $error = new Net::BGP::Notification(
                ErrorCode    => BGP_ERROR_CODE_UPDATE_MESSAGE,
                ErrorSubCode => BGP_ERROR_SUBCODE_MALFORMED_ATTR_LIST
            );

            last;
        }
    }

    return ( $error );
}

sub _decode_prefix_list
{
    my ($this, $buffer) = @_;
    my ($offset, $data_length);
    my ($prefix, $prefix_bits, $prefix_bytes, $ii, @prefix_list);

    $offset = 0;
    $data_length = length($buffer);

    while ( $data_length ) {
        $prefix_bits = unpack('C', substr($buffer, $offset++, 1));
        $prefix_bytes = int($prefix_bits / 8) + (($prefix_bits % 8) ? 1 : 0);

        if ( $prefix_bytes > ($data_length - 1)) {
            return ( FALSE );
        }

        $prefix = 0;
        for ( $ii = 0; $ii < $prefix_bytes; $ii++ ) {
            $prefix |= (unpack('C', substr($buffer, $offset++, 1)) << (24 - ($ii * 8)));
        }

        $prefix = pack('N', $prefix);
        push(@prefix_list, inet_ntoa($prefix) . "/" . $prefix_bits);
        $data_length -= ($prefix_bytes + 1);
    }

    return ( TRUE, @prefix_list );
}

sub _decode_withdrawn
{
    my ($this, $buffer) = @_;
    my ($result, $error, @prefix_list);

    ($result, @prefix_list) = $this->_decode_prefix_list($buffer);
    if ( ! $result ) {
        $error = new Net::BGP::Notification(
            ErrorCode    => BGP_ERROR_CODE_UPDATE_MESSAGE,
            ErrorSubCode => BGP_ERROR_SUBCODE_MALFORMED_ATTR_LIST
        );

        return ( $error );
    }

    push(@{$this->{_withdrawn}}, @prefix_list);

    return ( undef );
}

sub _decode_nlri
{
    my ($this, $buffer) = @_;
    my ($result, $error, @prefix_list);

    ($result, @prefix_list) = $this->_decode_prefix_list($buffer);
    if ( ! $result ) {
        $error = new Net::BGP::Notification(
            ErrorCode    => BGP_ERROR_CODE_UPDATE_MESSAGE,
            ErrorSubCode => BGP_ERROR_SUBCODE_BAD_NLRI
        );

        return ( $error );
    }

    push(@{$this->{_nlri}}, @prefix_list);

    return ( undef );
}

sub _encode_message
{
    my $this = shift();
    my ($buffer, $withdrawn, $path_attr, $nlri);

    # encode the Withdrawn Routes field
    $withdrawn = $this->_encode_prefix_list($this->{_withdrawn});
    $buffer = pack('n', length($withdrawn)) . $withdrawn;

    # encode the Path Attributes field
    $path_attr = $this->_encode_path_attributes();
    $buffer .= (pack('n', length($path_attr)) . $path_attr);

    # encode the Network Layer Reachability Information field
    $buffer .= $this->_encode_prefix_list($this->{_nlri});

    return ( $buffer );
}

sub _encode_prefix
{
    my $prefix = shift();
    my ($buffer, $length, @octets);

    ($prefix, $length) = split('/', $prefix);

    $buffer = pack('C', $length);

    @octets = split(/\./, $prefix);
    while ( $length > 0 ) {
        $buffer .= pack('C', shift(@octets));
        $length -= 8;
    }

    return ( $buffer );
}

sub _encode_prefix_list
{
    my ($this, $prefix_list) = @_;
    my ($prefix, $buffer);

    $buffer = '';
    foreach $prefix ( @{$prefix_list} ) {
        $buffer .= _encode_prefix($prefix);
    }

    return ( $buffer );
}

sub _encode_path_attr_type
{
    my $type = shift();
    my $buffer;

    $buffer  = pack('C', $BGP_PATH_ATTR_FLAGS[$type]);
    $buffer .= pack('C', $type);

    return ( $buffer );
}

sub _encode_origin
{
    my $this = shift();
    my $buffer;

    $buffer  = _encode_path_attr_type(BGP_PATH_ATTR_ORIGIN);
    $buffer .= pack('C', 0x01);
    $buffer .= pack('C', $this->{_origin});

    return ( $buffer );
}

sub _encode_as_path
{
    my $this = shift();

    my $as_buffer = $this->{_as_path}->_encode;

    my $buffer  = _encode_path_attr_type(BGP_PATH_ATTR_AS_PATH);
    $buffer .= pack('C', length($as_buffer));
    $buffer .= $as_buffer;

    return $buffer;
}

sub _encode_next_hop
{
    my $this = shift();
    my $buffer;

    $buffer  = _encode_path_attr_type(BGP_PATH_ATTR_NEXT_HOP);
    $buffer .= pack('C', 0x04);
    $buffer .= inet_aton($this->{_next_hop});

    return ( $buffer );
}

sub _encode_med
{
    my $this = shift();
    my $buffer;

    $buffer  = _encode_path_attr_type(BGP_PATH_ATTR_MULTI_EXIT_DISC);
    $buffer .= pack('C', 0x04);
    $buffer .= pack('N', $this->{_med});

    return ( $buffer );
}

sub _encode_local_pref
{
    my $this = shift();
    my $buffer;

    $buffer  = _encode_path_attr_type(BGP_PATH_ATTR_LOCAL_PREF);
    $buffer .= pack('C', 0x04);
    $buffer .= pack('N', $this->{_local_pref});

    return ( $buffer );
}

sub _encode_atomic_aggregate
{
    my $this = shift();
    my $buffer;

    $buffer  = _encode_path_attr_type(BGP_PATH_ATTR_ATOMIC_AGGREGATE);
    $buffer .= pack('C', 0x00);

    return ( $buffer );
}

sub _encode_aggregator
{
    my $this = shift();
    my $buffer;

    $buffer  = _encode_path_attr_type(BGP_PATH_ATTR_AGGREGATOR);
    $buffer .= pack('C', 0x06);
    $buffer .= pack('n', $this->{_aggregator}->[0]);
    $buffer .= inet_aton($this->{_aggregator}->[1]);

    return ( $buffer );
}

sub _encode_communities
{
    my $this = shift();
    my ($as, $val, $community, @communities);
    my ($buffer, $community_buffer);

    @communities = @{$this->{_communities}};
    foreach $community ( @communities ) {
        ($as, $val) = split(/\:/, $community);
        $community_buffer .= pack('n', $as);
        $community_buffer .= pack('n', $val);
    }

    $buffer  = _encode_path_attr_type(BGP_PATH_ATTR_COMMUNITIES);
    $buffer .= pack('C', scalar(@communities) * 0x04);
    $buffer .= $community_buffer;

    return ( $buffer );
}

sub _encode_path_attributes
{
    my $this = shift();
    my $buffer;

    $buffer = '';

    # do not encode path attributes if no NLRI is present
    unless ((defined $this->{_nlri})
	 && scalar(@{$this->{_nlri}})) {
        return ( $buffer );
    }

    # encode the ORIGIN path attribute
    if ( ! defined($this->{_origin}) ) {
        carp "mandatory path attribute ORIGIN not defined\n";
    }
    $buffer = $this->_encode_origin();

    # encode the AS_PATH path attribute
    if ( ! defined($this->{_as_path}) ) {
        carp "mandatory path attribute AS_PATH not defined\n";
    }
    $buffer .= $this->_encode_as_path();

    # encode the NEXT_HOP path attribute
    if ( ! defined($this->{_next_hop}) ) {
        carp "mandatory path attribute NEXT_HOP not defined\n";
    }
    $buffer .= $this->_encode_next_hop();

    # encode the MULTI_EXIT_DISC path attribute
    if ( defined($this->{_med}) ) {
        $buffer .= $this->_encode_med();
    }

    # encode the LOCAL_PREF path attribute
    if ( defined($this->{_local_pref}) ) {
        $buffer .= $this->_encode_local_pref();
    }

    # encode the ATOMIC_AGGREGATE path attribute
    if ( defined($this->{_atomic_agg}) ) {
        $buffer .= $this->_encode_atomic_aggregate();
    }

    # encode the AGGREGATOR path attribute
    if ( scalar(@{$this->{_aggregator}}) ) {
        $buffer .= $this->_encode_aggregator();
    }

    # encode the COMMUNITIES path attribute
    if ( scalar(@{$this->{_communities}}) ) {
        $buffer .= $this->_encode_communities();
    }

    return ( $buffer );
}

## POD ##

=pod

=head1 NAME

Net::BGP::Update - Class encapsulating BGP-4 UPDATE message

=head1 SYNOPSIS

    use Net::BGP::Update qw( :origin );

    # Constructor
    $update = new Net::BGP::Update(
        NLRI            => [ qw( 10/8 172.168/16 ) ],
        Withdraw        => [ qw( 192.168.1/24 172.10/16 192.168.2.1/32 ) ],
	# For Net::BGP::NLRI
        Aggregator      => [ 64512, '10.0.0.1' ],
        AsPath          => [ 64512, 64513, 64514 ],
        AtomicAggregate => 1,
        Communities     => [ qw( 64512:10000 64512:10001 ) ],
        LocalPref       => 100,
        MED             => 200,
        NextHop         => '10.0.0.1',
        Origin          => INCOMPLETE,
    );

    # Construction from a NLRI object:
    $nlri = new Net::BGP::NLRI( ... );
    $update = new Net::BGP::Update($nlri,$nlri_ref,$withdrawn_ref);

    # Object Copy
    $clone = $update->clone();

    # Accessor Methods
    $nlri_ref         = $update->nlri($nlri_ref);
    $withdrawn_ref    = $update->withdrawn($withdrawn_ref);
    $prefix_hash_ref  = $update->ashash;

    # Comparison
    if ($update1 eq $update2) { ... }
    if ($update1 ne $update2) { ... }

=head1 DESCRIPTION

This module encapsulates the data contained in a BGP-4 UPDATE message.
It provides a constructor, and accessor methods for each of the
message fields and well-known path attributes of an UPDATE. Whenever
a B<Net::BGP::Peer> sends an UPDATE message to its peer, it does so
by passing a B<Net::BGP::Update> object to the peer object's I<update()>
method. Similarly, when the peer receives an UPDATE message from its
peer, the UPDATE callback is called and passed a reference to a
B<Net::BGP::Update> object. The callback function can then examine
the UPDATE message fields by means of the accessor methods.

=head1 CONSTRUCTOR

I<new()> - create a new Net::BGP::Update object

    $update = new Net::BGP::Update(
        NLRI            => [ qw( 10/8 172.168/16 ) ],
        Withdraw        => [ qw( 192.168.1/24 172.10/16 192.168.2.1/32 ) ],
	# For Net::BGP::NLRI
        Aggregator      => [ 64512, '10.0.0.1' ],
        AsPath          => [ 64512, 64513, 64514 ],
        AtomicAggregate => 1,
        Communities     => [ qw( 64512:10000 64512:10001 ) ],
        LocalPref       => 100,
        MED             => 200,
        NextHop         => '10.0.0.1',
        Origin          => INCOMPLETE,
    );

This is the constructor for Net::BGP::Update objects. It returns a
reference to the newly created object. The following named parameters may
be passed to the constructor. See RFC 1771 for the semantics of each
path attribute.

An alternative is to construct an object from a Net::BGP::NLRI object:

    $nlri = new Net::BGP::NLRI( ... );
    $nlri_ref = [ qw( 10/8 172.168/16 ) ];
    $withdrawn_ref = [ qw( 192.168.1/24 172.10/16 192.168.2.1/32 ) ];
    $update = new Net::BGP::Update($nlri,$nlri_ref,$withdrawn_ref);

The NLRI object will not be modified in any way.

=head2 NLRI

This parameter corresponds to the Network Layer Reachability Information (NLRI)
field of an UPDATE message. It represents the route(s) being advertised in this
particular UPDATE. It is expressed as an array reference of route prefixes which
are encoded in a special format as perl strings: XXX.XXX.XXX.XXX/XX. The part
preceding the slash is a dotted-decimal notation IP prefix. Only as many octets
as are significant according to the mask need to be specified. The part following
the slash is the mask which is an integer in the range [0,32] which indicates how
many bits are significant in the prefix. At least one of either the NLRI or Withdraw
parameters is mandatory and must always be provided to the constructor.

=head2 Withdraw

This parameter corresponds to the Withdrawn Routes field of an UPDATE message. It
represents route(s) advertised by a previous UPDATE message which are now being
withdrawn by this UPDATE. It is expressed in the same way as the NLRI parameter.
At least one of either the NLRI or Withdraw parameters is mandatory and must
always be provided to the constructor.

=head1 OBJECT COPY

I<clone()> - clone a Net::BGP::Update object

    $clone = $update->clone();

This method creates an exact copy of the Net::BGP::Update object, with Withdrawn
Routes, Path Attributes, and NLRI fields matching those of the original object.
This is useful for propagating a modified UPDATE message when the original object
needs to remain unchanged.

=head1 ACCESSOR METHODS

I<nlri()>

I<withdrawn()>

These accessor methods return the value(s) of the associated UPDATE message field
if called with no arguments. If called with arguments, they set
the associated field. The representation of parameters and return values is the
same as described for the corresponding named constructor parameters above.

I<ashash()>

This method returns a hash reference index on the prefixes in found in the nlri
and withdrawn fields.  Withdrawn networks has undefined as value, while nlri
prefixes all has the same reference to a Net::BGP::NLRI object matching the
Update object self. 

=head1 EXPORTS

The module does not export anything.

=head1 SEE ALSO

B<RFC 1771>, B<RFC 1997>, B<Net::BGP>, B<Net::BGP::Process>, B<Net::BGP::Peer>,
B<Net::BGP::Notification>, B<Net::BGP::NLRI>

=head1 AUTHOR

Stephen J. Scheck <code@neurosphere.com>

=cut

## End Package Net::BGP::Update ##

1;
