#!/usr/bin/perl -wT

# $Id: Update.t,v 1.1 2003/05/31 18:59:59 unimlo Exp $

use strict;

use Test::More tests => 24;

use Net::BGP::Peer qw( :generic ); # dump_hex

# Use
use_ok('Net::BGP::Update');

# Simple construction
my $empty = new Net::BGP::Update;
ok(ref $empty eq 'Net::BGP::Update','Simple construction');

# Complex construction
my $data = new Net::BGP::Update(
	NLRI		=>	[ '10.0.0.0/8', '192.168.0.0/16' ],
	Withdrawn	=>	[ '127.0.0.0/8' ],
	ASPath		=>	'(65001)'
	);
ok(ref $data eq 'Net::BGP::Update','Complex construction');

# Construction from NLRI
my $nlri = new Net::BGP::NLRI(
	ASPath		=>	'(65001)'
	);

my $data2 = new Net::BGP::Update($nlri,[ '10.0.0.0/8', '192.168.0.0/16' ],[ '127.0.0.0/8' ]);
ok(ref $data eq 'Net::BGP::Update','Construction from Net::BGP::NLRI');

# Copying
my $cloneX = clone Net::BGP::Update($data);
ok(ref $cloneX eq 'Net::BGP::Update','Clone construction');
my $clone = $cloneX->clone;
ok(ref $clone eq 'Net::BGP::Update','Cloning');

# NLRI
ok($clone->nlri->[0] eq '10.0.0.0/8','Accessor: NLRI');
$clone->nlri->[0] = '10.10.0.0/16';
ok($clone->nlri->[0] eq '10.10.0.0/16','Accessor: NLRI reference');
$clone->nlri(['10.0.10.0/24']);
ok($clone->nlri->[0] eq '10.0.10.0/24','Accessor: NLRI modifyer');

# Withdrawn
ok($clone->withdrawn->[0] eq '127.0.0.0/8','Accessor: Withdrawn');
$clone->withdrawn->[0] = '127.0.0.0/16';
ok($clone->withdrawn->[0] eq '127.0.0.0/16','Accessor: Withdrawn reference');
$clone->withdrawn(['127.0.0.0/8']);
ok($clone->withdrawn->[0] eq '127.0.0.0/8','Accessor: Withdrawn modifyer');

# AS Path (sample of inherited method)
ok($clone->as_path->asstring eq '(65001)','Accessor: AS Path (inherited)');
$clone->as_path->prepend_confed(65000);
ok($clone->as_path->asstring eq '(65000 65001)','Accessor: AS Path reference (inherited)');
$clone->as_path('(65001)');
ok($clone->as_path->asstring eq '(65001)','Accessor: AS Path modifyer (inherited)');

# ashash

my $hash = $clone->ashash;
ok(exists $hash->{'127.0.0.0/8'} && ! defined $hash->{'127.0.0.0/8'},'Accessor: As HASH Withdrawn');
ok($hash->{'10.0.10.0/24'}->as_path->asstring eq '(65001)','Accessor: As HASH NLRI');

# Comparison
my $clone1 = $data->clone;
my $clone2 = $data->clone;
my $clone3 = $data->clone;
$clone1->as_path->prepend_confed(65000); # Modify NLRI (parrent)
push(@{$clone2->nlri},'172.16.0.0/24'); # Modify Update (self)
ok($data ne $clone1,'Comparison: Not equal (ne) 1');
ok($data ne $clone2,'Comparison: Not equal (ne) 2');
ok($data eq $clone3,'Comparison: Equal     (eq) 1');
ok($data eq $data2 ,'Comparison: Equal     (eq) 2');

# Encoding / Decoding
my @msgs;
push(@msgs, [ qw (
	00 00 00 14  40 01 01 00  40 02 06 02  02 FD EB FD
        EA 40 03 04  0A FF 67 01  18 0A 02 01
	) ]);
push(@msgs, [ qw (
	00 00 00 2F  40 01 01 00  40 02 0C 03  05 FD F4 FD
	F3 FD F3 FD  F5 FD F5 40  03 04 0A 00  00 01 80 04
	04 00 00 00  00 40 05 04  00 00 00 64  C0 08 04 00
	00 00 64 1E  0A 00 22 00  1E 0A FF 03  00 1E 0A FF
	04 00 1E 0A  FF 67 00 
	) ]);
push(@msgs, [ qw (
	00 00 00 2B  40 01 01 00  40 02 08 03  03 FD F3 FD
	F5 FD F5 40  03 04 0A 00  00 04 80 04  04 00 00 00
	00 40 05 04  00 00 00 64  C0 08 04 00  00 00 64 1E
	0A 00 22 00  1E 0A FF 03  00 1E 0A FF  04 00 1E 0A
	FF 67 00
	) ]);
my $i = 0;
foreach my $list (@msgs)
 {
  my $msg = join('',map { pack('H2',$_); } @{$list});
  my $update = Net::BGP::Update->_new_from_msg($msg);
  my $recode = $update->_encode_message;
  ok($msg eq $recode,'msg = encode(decode(msg)) ' . ++$i);
 };

__END__
