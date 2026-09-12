# qlinq

[![CI](https://github.com/sleepybishop/qlinq/actions/workflows/ci.yml/badge.svg)](https://github.com/sleepybishop/qlinq/actions/workflows/ci.yml)

`qlinq` ("clink") is a QUIC-based swiss army knife for different types of data streams. It combines a high-performance network link path manager with forward error correction and provides interfaces via tun devices or unix sockets.

## Features

- **QUIC-native Tunneling**: Low-latency, connection-migrating packet tunnels.
- **Multipath Link Aggregation**: Dynamic path discovery, performance scheduling, and failover across multiple interfaces (Wi-Fi, Ethernet, Satcom, Cellular).
- **Forward Error Correction**: Recover lost packets on high-loss links without retransmission latency.
- **mTLS Authentication**: Full mutual TLS authentication support using custom or system trusted root authorities.

## Building

To compile all targets, run:

```bash
git submodule update --init --recursive
make
```

This produces three binaries and an embeddable transport library:

- `qlinqd`: The background peer-to-peer network daemon.
- `qlinq-app`: A direct `transport.h` file/stream sender and receiver that does
  not use the daemon's Unix data socket.
- `qlinq-tund`: The lightweight virtual TUN/TAP interface controller.
- `libqlinq.a`: The in-process `transport.h` API used by `qlinq-app`, plus the
  [native application API](docs/application-api.md) in `qlinq.h` for named
  streams, owned events and endpoint management.

For example, send one 512-byte rateless-protected record:

```bash
./qlinq-app --listen 8888 --bind 127.0.0.1 \
  --cert t/assets/server.crt --key t/assets/server.key \
  --auth-token test --insecure-no-verify --input payload.bin \
  --message-size 512 --count 1 --wait-subscribers 1 --one-shot
```

Receive it with:

```bash
./qlinq-app --peer 127.0.0.1:8888 --auth-token test \
  --insecure-no-verify --output received.bin --receive-count 1
```

The app also supports reliable, plain datagram, fixed-FEC, and rateless modes,
IPv6 bracketed peer endpoints, negotiated repair selection, an explicit QUIC
idle timeout, machine-readable counter snapshots, and `--pv` for pv-style wire
throughput per physical interface. Run `qlinq-app --help` for the complete
interface.

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
