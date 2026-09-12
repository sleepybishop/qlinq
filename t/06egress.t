use strict;
use warnings;
use Test::More;
use t::Util;

my ($stderr, $stdout) = run_prog('./t/00util/test_egress_errors');
like($stdout, qr/===EGRESS ERRORS OK===/, 'UDP egress errors and queue pressure') or diag($stderr);
done_testing;
