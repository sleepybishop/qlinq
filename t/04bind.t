#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use t::Util;
my ($stderr, $stdout) = run_prog('./t/00util/test_transport_bind');
like($stdout, qr/===UNICAST BIND OWNERSHIP OK===/,
     'IPv4 and IPv6 unicast sockets have exclusive ownership') or diag($stderr);
done_testing;
