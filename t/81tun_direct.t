#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use t::Util;

my $directory = tempdir(CLEANUP => 1);
my @cases = (['fixed-fec', 0], ['rateless', 0], ['reliable', 0],
             ['datagram', 0], ['fixed-fec', 1]);

for my $index (0 .. $#cases) {
    my ($mode, $verified) = @{$cases[$index]};
    my $label = $verified ? "$mode verified" : $mode;
    my $port = 19940 + $index;
    my $server_log = "$directory/server-$index.log";
    my @security = $verified
        ? ('--cert', 't/assets/verified.crt', '--key',
           't/assets/verified.key', '--ca', 't/assets/verified.crt')
        : ('--insecure-no-verify');
    my $server_pid = fork();
    die "fork failed: $!" unless defined $server_pid;
    if ($server_pid == 0) {
        open STDOUT, '>', $server_log or die "open $server_log: $!";
        open STDERR, '>&', \*STDOUT or die "redirect stderr: $!";
        exec './qlinq-tun', '--listen', $port, '--bind', '127.0.0.1',
            '--auth-token', 'direct-test', @security,
            ($verified ? () : ('--cert', 't/assets/server.crt',
                                '--key', 't/assets/server.key')),
            '--track', 'tun-direct-test', '--mode', $mode, '--mock',
            '--run-ms', '5000';
        die "exec server: $!";
    }
    select undef, undef, undef, 0.2;
    my $client_security = $verified
        ? '--cert t/assets/verified.crt --key t/assets/verified.key ' .
          '--ca t/assets/verified.crt'
        : '--insecure-no-verify';
    my ($stderr, $stdout) = run_prog(
        "./qlinq-tun --peer 127.0.0.1:$port --bind 127.0.0.1 " .
        "--auth-token direct-test $client_security " .
        "--track tun-direct-test --mode $mode --mock --run-ms 3500");
    my $waited = waitpid($server_pid, 0);
    is($waited, $server_pid, "$label listener exited");
    is($? >> 8, 0, "$label listener succeeded");
    open my $log, '<', $server_log or die "open $server_log: $!";
    local $/;
    my $server_output = <$log>;
    like($stdout, qr/direct TUN summary: sent=[1-9]\d* received=[1-9]\d*/,
         "$label client exchanged packets") or diag($stderr);
    like($server_output, qr/direct TUN summary: sent=[1-9]\d* received=[1-9]\d*/,
         "$label listener exchanged packets");
}

done_testing();
