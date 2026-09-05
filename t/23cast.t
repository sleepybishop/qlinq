use strict;
use warnings;
use Test::More;
use t::Util;

subtest 'finite file and stdin fan-out' => sub {
    my ($stderr, $stdout) = run_prog('sh t/00util/test_qlinq_cast.sh');
    is($stdout, "===QLINQ CAST OK===\n",
       'rateless and fixed-FEC transfers complete for one and two receivers')
        or diag($stderr);
};

done_testing;
