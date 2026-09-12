use strict;
use warnings;
use Test::More;
use t::Util;
my ($err, $out) = run_prog('./t/00util/test_directional_subscriptions');
like($out, qr/===DIRECTIONAL SUBSCRIPTIONS OK===/, 'independent aliases in every unicast delivery mode') or diag($err);
done_testing;
