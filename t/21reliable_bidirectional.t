use strict;
use warnings;
use Test::More;
use t::Util;

subtest "alternating bidirectional reliable publishing" => sub {
	my ($stderr, $stdout) = run_prog("./t/00util/test_reliable_bidirectional");
	like $stdout, qr/===RELIABLE BIDIRECTIONAL OK===/,
		"reliable publishing reuses streams in both directions";
};

done_testing();
