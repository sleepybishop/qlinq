#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use t::Util;

subtest 'decomposed transport components' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_transport_components');
    like($stdout, qr/===TRANSPORT COMPONENTS OK===/,
         'component ownership and lookup tests pass') or diag($stderr);
};

subtest 'UDP GSO grouping and partial sends' => sub {
    plan skip_all => 'Linux UDP_SEGMENT syscall coverage' if $^O ne 'linux';
    my ($stderr, $stdout) = run_prog('./t/00util/test_udp_gso_prefix');
    like($stdout, qr/UDP GSO grouping and partial-send fault injection passed/,
         'datagrams remain ordered and accepted prefixes are never replayed') or diag($stderr);
};

done_testing;
