use strict;
use warnings;
use Test::More tests => 1;

subtest "multipath nack rateless fec test" => sub {
    my $output = `./t/00util/test_multipath_nack 2>&1`;
    my $exit_code = $? >> 8;
    is($exit_code, 0, "multipath nack rateless fec test completed successfully");
    note $output;
};
