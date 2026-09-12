use strict;
use warnings;
use Test::More;
use t::Util;

my ($stderr, $stdout) = run_prog('./t/00util/test_interleaved_receive');
like($stdout, qr/===INTERLEAVED RECEIVE OK===/, 'incomplete objects survive interleaved records') or diag($stderr);
done_testing;
