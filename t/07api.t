#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use t::Util;

subtest 'native stream API' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_qlinq_api');
    like($stdout, qr/===QLINQ API OK===/,
         'stream subscription and owned record events work') or diag($stderr);
};

subtest 'public delivery modes and content types' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_qlinq_delivery');
    like($stdout, qr/===QLINQ DELIVERY MATRIX OK===/, 'all delivery modes retain stream identity') or diag($stderr);
};

done_testing;
