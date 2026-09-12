#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use t::Util;

subtest 'Flexicast shared packet fan-out' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_flexicast_transport');
    like($stdout, qr/===FLEXICAST TRANSPORT OK===/,
         'one protected flow reaches two subscribers') or diag($stderr);
};

subtest 'Flexicast native multicast fan-out' => sub {
    my ($stderr, $stdout) =
        run_prog('./t/00util/test_flexicast_transport --native');
    like($stdout, qr/===FLEXICAST MULTICAST OK===/,
         'one protected multicast datagram reaches two subscribers')
        or diag($stderr);
};

subtest 'Flexicast native IPv6 multicast fan-out' => sub {
    my ($stderr, $stdout) =
        run_prog('./t/00util/test_flexicast_transport --native6');
    like($stdout, qr/===FLEXICAST IPV6 MULTICAST OK===/,
         'IPv6 SSM joins and native-or-unicast fallback reach subscribers')
        or diag($stderr);
};

subtest 'Flexicast membership failure fallback' => sub {
    my ($stderr, $stdout) =
        run_prog('./t/00util/test_flexicast_transport --join-fallback');
    like($stdout, qr/===FLEXICAST JOIN FALLBACK OK===/,
         'a failed local group join retains ordinary unicast delivery')
        or diag($stderr);
};

subtest 'Flexicast feedback timeout fallback' => sub {
    my ($stderr, $stdout) =
        run_prog('./t/00util/test_flexicast_transport --ack-fallback');
    like($stdout, qr/===FLEXICAST ACK FALLBACK OK===/,
         'missing PATH_ACK demotes one member without interrupting delivery')
        or diag($stderr);
};

subtest 'Flexicast concurrent publisher mesh' => sub {
    my ($stderr, $stdout) =
        run_prog('./t/00util/test_flexicast_transport --mesh');
    like($stdout, qr/===FLEXICAST MESH OK===/,
         'two publishers isolate protected flows on one multicast endpoint')
        or diag($stderr);
};

subtest 'Flexicast split-group mesh regression' => sub {
    my ($stderr, $stdout) =
        run_prog('./t/00util/test_flexicast_transport --mesh-split');
    like($stdout, qr/===FLEXICAST MESH OK===/,
         'the previous one-group-per-publisher topology remains supported')
        or diag($stderr);
};

subtest 'Flexicast multicast pacing' => sub {
    my ($stderr, $stdout) =
        run_prog('./t/00util/test_flexicast_transport --pacing');
    like($stdout, qr/===FLEXICAST PACING OK===/,
         'burst is queued and paced using member delivery estimates')
        or diag($stderr);
};

subtest 'Flexicast adaptive congestion controller' => sub {
    my ($stderr, $stdout) =
        run_prog('./t/00util/test_flexicast_transport --adaptive');
    is($stdout, "===FLEXICAST ADAPTIVE CC OK===\n",
       'adaptive controller drives bounded Flexicast pacing');
};

subtest 'Flexicast membership control throttling' => sub {
    my ($stderr, $stdout) =
        run_prog('./t/00util/test_flexicast_transport --control-flood');
    like($stdout, qr/===FLEXICAST CONTROL THROTTLE OK===/,
         'rapid join/leave churn demotes only the abusive member')
        or diag($stderr);
};

subtest 'Flexicast shared rateless repair' => sub {
    my ($stderr, $stdout) =
        run_prog('./t/00util/test_flexicast_transport --repair');
    like($stdout, qr/===FLEXICAST RATELESS REPAIR OK===/,
         'degree-of-freedom feedback emits fresh paced group repairs')
        or diag($stderr);
};

subtest 'Flexicast rateless repair after ESI exhaustion' => sub {
    my ($stderr, $stdout) =
        run_prog('./t/00util/test_flexicast_transport --repair-exhaustion');
    like($stdout, qr/===FLEXICAST RATELESS EXHAUSTION RECOVERY OK===/,
         'bounded ESI exhaustion cycles retained systematic symbols')
        or diag($stderr);
};

subtest 'Flexicast shared indexed repair' => sub {
    my ($stderr, $stdout) =
        run_prog('./t/00util/test_flexicast_transport --repair-indexed');
    like($stdout, qr/===FLEXICAST INDEXED REPAIR OK===/,
         'explicit missing-ESI feedback retains exact indexed repair')
        or diag($stderr);
};

subtest 'Flexicast shared membership lifecycle' => sub {
    my ($stderr, $stdout) =
        run_prog('./t/00util/test_flexicast_transport --membership');
    like($stdout, qr/===FLEXICAST MEMBERSHIP OK===/,
         'two flows share one join and the final leave drops membership')
        or diag($stderr);
};

subtest 'Flexicast shared IPv6 membership lifecycle' => sub {
    my ($stderr, $stdout) =
        run_prog('./t/00util/test_flexicast_transport --membership6');
    like($stdout, qr/===FLEXICAST IPV6 MEMBERSHIP OK===/,
         'two IPv6 flows share one join and the final leave drops membership')
        or diag($stderr);
};

subtest 'Flexicast explicit unsubscribe and rejoin' => sub {
    my ($stderr, $stdout) =
        run_prog('./t/00util/test_flexicast_transport --unsubscribe');
    like($stdout, qr/===FLEXICAST UNSUBSCRIBE OK===/,
         'unsubscribe drops SSM state, rekeys peers, and permits rejoin')
        or diag($stderr);
};

subtest 'Flexicast explicit IPv6 unsubscribe and rejoin' => sub {
    my ($stderr, $stdout) =
        run_prog('./t/00util/test_flexicast_transport --unsubscribe6');
    like($stdout, qr/===FLEXICAST IPV6 UNSUBSCRIBE OK===/,
         'IPv6 unsubscribe drops SSM state and permits a fresh join')
        or diag($stderr);
};

subtest 'adaptive controller matches the multicast correctness matrix' => sub {
    my @cases = (
        ['--base',              qr/===FLEXICAST TRANSPORT OK===/],
        ['--native',            qr/===FLEXICAST MULTICAST OK===/],
        ['--native6',           qr/===FLEXICAST IPV6 MULTICAST OK===/],
        ['--join-fallback',     qr/===FLEXICAST JOIN FALLBACK OK===/],
        ['--ack-fallback',      qr/===FLEXICAST ACK FALLBACK OK===/],
        ['--mesh',              qr/===FLEXICAST MESH OK===/],
        ['--mesh-split',        qr/===FLEXICAST MESH OK===/],
        ['--pacing',            qr/===FLEXICAST PACING OK===/],
        ['--repair',            qr/===FLEXICAST RATELESS REPAIR OK===/],
        ['--repair-exhaustion', qr/===FLEXICAST RATELESS EXHAUSTION RECOVERY OK===/],
        ['--repair-indexed',    qr/===FLEXICAST INDEXED REPAIR OK===/],
        ['--control-flood',     qr/===FLEXICAST CONTROL THROTTLE OK===/],
        ['--membership',        qr/===FLEXICAST MEMBERSHIP OK===/],
        ['--membership6',       qr/===FLEXICAST IPV6 MEMBERSHIP OK===/],
        ['--unsubscribe',       qr/===FLEXICAST UNSUBSCRIBE OK===/],
        ['--unsubscribe6',      qr/===FLEXICAST IPV6 UNSUBSCRIBE OK===/],
    );
    for my $case (@cases) {
        my ($stderr, $stdout) = run_prog(
            "./t/00util/test_flexicast_transport $case->[0] --cc-adaptive");
        like($stdout, $case->[1], "$case->[0] passes with adaptive CC")
            or diag($stderr);
    }
};

done_testing;
