#!/usr/bin/perl -wT

# $Id: 31-Refresh.t 20 2007-07-23 09:54:24Z kbrint $

use strict;

use Test::More tests => 3;

# Use
use_ok('Net::BGP::Refresh');

# Construction
my $default = new Net::BGP::Refresh;
ok(ref $default eq 'Net::BGP::Refresh','simple construction');

my $coded = $default->_encode_message;
ok(Net::BGP::Refresh->_new_from_msg($coded)->_encode_message eq $coded,'encode-decode');

__END__
