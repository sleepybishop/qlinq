# qlinq-cast

`qlinq-cast` sends a finite byte stream to one or more authenticated receivers.
It reads and writes regular files or standard streams, preserves byte order at
the destination, and exits only after the receiver cohort confirms recovered
completion.

## Basic transfer

The sender listens for receivers. It requires a TLS certificate and private
key, and waits for one receiver by default:

```bash
export QLINQ_CAST_SECRET='replace-with-a-shared-secret'

qlinq-cast send --bind 192.0.2.10 --port 9000 \
  --cert sender.crt --key sender.key --ca mesh-ca.crt image.raw
```

Each receiver connects, authenticates, and writes records in source order:

```bash
export QLINQ_CAST_SECRET='replace-with-a-shared-secret'

qlinq-cast receive --peer 192.0.2.10:9000 \
  --cert receiver.crt --key receiver.key --ca mesh-ca.crt received.raw
```

Use `-` for standard input or output. Diagnostics and progress always go to
standard error, so a pipeline remains binary-clean:

```bash
producer | qlinq-cast send --cert sender.crt --key sender.key \
  --ca mesh-ca.crt -
qlinq-cast receive --peer 192.0.2.10:9000 \
  --cert receiver.crt --key receiver.key --ca mesh-ca.crt - | consumer
```

The sender always requires a certificate and key. When it verifies peers, each
receiver also supplies its certificate and key, and both sides use `--ca` to
select the trust store. The shared secret may be supplied with
`--secret-file FILE` or `--secret TEXT`. The environment or a
permission-restricted file avoids exposing it in the process argument list.
`--insecure` disables peer-certificate verification and is intended only for
isolated testing.

## Receiver cohorts

`--wait-receivers N` makes the sender wait until at least `N` authenticated
subscriptions are present before it reads input. If membership drops below the
threshold while the stream is open, input pauses. End of input freezes the
current cohort and starts finite completion; the sender exits successfully only
when every member confirms recovery. Departed members are reported as failures
and produce a nonzero exit status.

For example, this waits for four receivers:

```bash
qlinq-cast send --wait-receivers 4 \
  --cert sender.crt --key sender.key dataset.bin
```

A receiver that subscribes after the cohort has been frozen is explicitly
aborted and must join a new transfer with a new `--stream` name. Interrupting a
sender queues an abort notification before shutdown.

## Delivery modes

Rateless delivery is the default. `--mode fec` selects fixed-rate FEC. Both
modes use recovery checkpoints and the same finite-completion lifecycle.
`--repair-mode auto` negotiates the best repair form; `indexed` and `rateless`
force a preference for controlled experiments.

`--block-size` controls the application record size and accepts values from 1
through 60,000 bytes. Smaller blocks reduce reordering latency; larger blocks
reduce per-record overhead. The default is 16,384 bytes.

## Group delivery

Without group delivery, the sender uses each authenticated receiver's unicast
path. To enable protected group fan-out, use the existing Flexicast options on
both sides. The sender supplies the group policy:

```bash
qlinq-cast send --flexicast \
  --flexicast-group 232.1.2.3 --flexicast-port 9100 \
  --flexicast-interface 192.0.2.10 --flexicast-cc adaptive \
  --cert sender.crt --key sender.key payload.bin
```

Receivers enable group delivery and select the local membership interface; the
group address, port, and key are learned through the authenticated connection:

```bash
qlinq-cast receive --peer 192.0.2.10:9000 --flexicast \
  --flexicast-interface 192.0.2.20 \
  --cert receiver.crt --key receiver.key --ca mesh-ca.crt payload.bin
```

If group membership is unavailable, delivery falls back to the authenticated
unicast path.

## Progress and exit status

`--stats-ms N` prints periodic record, byte, membership, queue, and loss
snapshots. `--verbose` additionally prints peer and lifecycle transitions. A
final summary is always written to standard error.

- Exit `0`: the complete cohort confirmed recovery and output was flushed.
- Exit `1`: command-line, file, or endpoint setup failed.
- Exit `2`: transfer, recovery, authentication, or output failed.
- Exit `130`: interrupted locally; a sender attempts to notify receivers first.

Run `qlinq-cast --help` for the complete option list.
