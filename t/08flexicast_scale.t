use strict;
use warnings;
use Test::More;
use t::Util;

subtest 'Flexicast 1000-member index churn' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_flexicast_scale');
    like($stdout, qr/===FLEXICAST SCALE OK===/,
         'member index accepts, removes, and replaces 1000 members')
        or diag($stderr);
};

done_testing;
