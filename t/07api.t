#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use t::Util;
for my $test (['qlinq_delivery', 'QLINQ DELIVERY MATRIX'],
              ['qlinq_event_ownership', 'QLINQ EVENT OWNERSHIP'],
              ['qlinq_event_overflow', 'QLINQ EVENT OVERFLOW'],
              ['qlinq_compat', 'QLINQ COMPATIBILITY'],
              ['qlinq_reconnect', 'QLINQ RECONNECT']) {
  my ($stderr, $stdout) = run_prog("./t/00util/test_$test->[0]");
  like($stdout, qr/===$test->[1] OK===/, $test->[1]) or diag($stderr);
}
done_testing;
