use strict;
use warnings;
use Test::More;
use t::Util;
my ($err, $out) = run_prog('./t/00util/test_stream_budget');
like($out, qr/===STREAM BUDGET OK===/, 'reliable queue bounds and ACK ownership') or diag($err);
done_testing;
