use strict;
use warnings;
use Test::More;
use t::Util;

subtest 'native API reconnect and Flexicast rejoin' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_qlinq_reconnect');
    like($stdout, qr/===QLINQ RECONNECT OK===/,
         'client restores its Flexicast subscription and exact delivery')
        or diag($stderr);
};

done_testing;
