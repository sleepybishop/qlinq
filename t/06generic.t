#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use t::Util;
my ($stderr, $stdout) = run_prog('./t/00util/test_generic_ports');
like($stdout, qr/===GENERIC PORTS OK===/, 'generic transport ports') or diag($stderr);
done_testing;
