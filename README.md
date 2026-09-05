# qlinq

[![CI](https://github.com/sleepybishop/qlinq/actions/workflows/ci.yml/badge.svg)](https://github.com/sleepybishop/qlinq/actions/workflows/ci.yml)

`qlinq` ("clink") is a QUIC-based swiss army knife for different types of data streams. It combines a high-performance network link path manager with forward error correction and provides interfaces via tun devices or unix sockets.

## Features

- **QUIC-native Tunneling**: Low-latency, connection-migrating packet tunnels.
- **Multipath Link Aggregation**: Dynamic path discovery, performance scheduling, and failover across multiple interfaces (Wi-Fi, Ethernet, Satcom, Cellular).
- **Forward Error Correction**: Recover lost packets on high-loss links without retransmission latency.
- **mTLS Authentication**: Full mutual TLS authentication support using custom or system trusted root authorities.
- **Finite Fanout**: `qlinq-cast` streams files or pipelines to a confirmed
  receiver cohort with ordered recovery and explicit completion.
- **Experimental Flexicast Fanout**: One encrypted unreliable-track packet can
  reach many authenticated subscribers with shared replay protection and
  aggregate acknowledgements. Enable it on every participating daemon with
  `--flexicast`; without a multicast policy qlinq replicates the protected
  packet over unicast. A source sends one native IPv4 or IPv6 SSM datagram by
  also setting `--flexicast-group 232.1.2.3 --flexicast-port 9000
  --flexicast-interface 192.0.2.10`, or an IPv6 `ff3x::/32` group with its
  numeric local IPv6 interface address. Receivers learn the group dynamically
  and may select their membership interface with `--flexicast-interface`.
  IPv6 peer endpoints use bracket notation such as `--peer [2001:db8::2]:8888`.
  Shared keys rotate as membership changes, and receivers with sustained missing
  PATH_ACK feedback fall back to their authenticated unicast path. The default
  `multicast` congestion controller follows the limiting receiver. Select the
  radio-oriented controller with `--flexicast-cc adaptive`; optional
  `--flexicast-cc-startup-rate`, `--flexicast-cc-min-rate`,
  `--flexicast-cc-max-rate`, `--flexicast-cc-aggregate-rate`, and
  `--flexicast-cc-feedback-timeout` values tune it in bytes per second and
  milliseconds. Multicast bursts remain bounded, and queue pressure is exposed
  through the publication API. Member state is dynamically sized and tested
  with 1,000-member cohorts; use `--max-connections N` on a listener to raise
  its default 32-connection/Flexicast-member capacity (hard limit 16,384).

## Building

To compile all targets, run:

```bash
git submodule update --init --recursive
make
```

This produces four main binaries and an embeddable transport library:

- `qlinqd`: The background peer-to-peer network daemon.
- `qlinq-app`: A direct `transport.h` send/receive and mesh test tool; it does
  not use the daemon's Unix data socket.
- `qlinq-cast`: A finite file/stdin fan-out tool built on the native streams api.
- `qlinq-tund`: The lightweight virtual TUN/TAP interface controller.
- `libqlinq.a`: The in-process library.

For example, start a rateless Flexicast sender using the adaptive controller:

```bash
./qlinq-app --listen 8888 --bind 192.0.2.10 \
  --auth-token "$QLINQ_AUTH_TOKEN" --cert peer.crt --key peer.key \
  --input payload.bin --one-shot --mode rateless --flexicast \
  --flexicast-group 232.1.2.3 --flexicast-port 9000 \
  --flexicast-interface 192.0.2.10 --flexicast-cc adaptive \
  --max-repair-requests 16 --max-aggregate-repairs 256
```

A receiver connects directly to the transport API and writes recovered records:

```bash
./qlinq-app --peer 192.0.2.10:8888 --auth-token "$QLINQ_AUTH_TOKEN" \
  --ca mesh-ca.crt --cert peer.crt --key peer.key \
  --output received.bin --mode rateless --flexicast \
  --flexicast-interface 192.0.2.20 --flexicast-cc adaptive
```

The app also supports reliable, plain datagram, fixed-FEC, and rateless modes,
IPv6 bracketed peer endpoints, negotiated repair selection, an explicit QUIC
idle timeout, machine-readable counter snapshots, and `--pv` for pv-style wire
throughput per physical interface. Run `qlinq-app --help` for the complete
interface.

Rateless-coded tracks use negotiated degree-of-freedom repair by default and
fall back to indexed missing-symbol requests with legacy peers. Use
`--repair-mode indexed` to force exact missing-ESI repair for comparison, or
`--repair-mode rateless` to express the rateless preference explicitly (it
still falls back safely when the peer lacks support).

## Security

`qlinqd` requires an application authentication token and verifies peer
certificates by default. Supply the token through `QLINQ_AUTH_TOKEN` or
`--auth-token`, and use `--ca` when peers are signed by a private CA. For local
testing only, certificate verification can be disabled explicitly with
`--insecure-no-verify`.

```bash
QLINQ_AUTH_TOKEN='replace-with-a-secret' \
  ./qlinqd --listen 8888 --cert peer.crt --key peer.key --ca mesh-ca.crt
```

## Testing

To run the test suite:

```bash
make check
```


The private peer protocol is documented in
[docs/wire-protocol.md](docs/wire-protocol.md). Protocol version 1 is required
on both peers; incompatible versions are rejected instead of being guessed.
The implementation boundaries and ownership rules are described in
[docs/transport-architecture.md](docs/transport-architecture.md).
