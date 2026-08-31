use strict;
use warnings;
use Test::More;
use t::Util;

subtest 'qlinq-app direct transport API' => sub {
    my ($stderr, $stdout) = run_prog('sh t/00util/test_qlinq_app.sh');
    is($stdout, "===QLINQ APP DIRECT API OK===\n",
       'rateless input survives loss without duplicate direct-API delivery');
};

done_testing;
