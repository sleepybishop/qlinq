# Transport architecture

The public transport API remains in `transport.h`. The Quicly implementation is
split into small internal modules with one-way dependencies toward shared data
types and the wire codec.

| Module | Responsibility |
| --- | --- |
| `transport_quicly.c` | Connection lifecycle, socket event loop, and public control/query API |
| `transport_internal.h` | Private shared transport and connection state |
| `transport_config.c` | Default resolution and validation of resource limits |
| `transport_protocol.c` | HELLO negotiation, stream dispatch, datagram receive, and FEC assembly |
| `transport_publish.c` | Reliable/datagram publication, FEC generation, and grouped data flushes |
| `transport_tracks.c` | Small delivery-class validation and profile derivation |
| `transport_wire.c` | Versioned, bounded byte-level encoding and decoding |
| `transport_stream.c` | Atomic stream-frame construction and emission |
| `transport_subscriptions.c` | Track/alias lookup, allocation, and stream binding |
| `transport_memory.c` | Packet arena and FEC assembler allocation ownership |
| `transport_fec_state.c` | Reusable FEC contexts and sent-object repair cache |
| `transport_paths.c` | QUIC-path mapping and physical-path selection |
| `transport_repair.c` | Bounded NACK symbol reconstruction |
| `transport_scheduler.c` | Per-connection path and redundancy planning |
| `transport_tls.c` | Certificate loading and verifier initialization |
| `transport_egress.c` | Owned, bounded queues for packets awaiting socket writability |
| `transport_udp.c` | Portable UDP batch system calls and Linux GSO acceleration |

The protocol and publication engines operate on private state but do not own the
socket event loop. `transport_quicly.c` coordinates lifecycle and polling while
each module owns its invariants. The public header continues to expose opaque
handles.

## Ownership rules

- `transport_memory` initializes and destroys arenas and frame assemblers.
- `transport_subscriptions` is the only code that allocates aliases or changes
  subscription entries.
- `transport_fec_state` owns cached FEC instances and copies of sent objects.
- `transport_stream` emits complete frames in one Quicly egress operation.
- `transport_egress` copies any QUIC packets not accepted immediately by the
  kernel. Quicly is not asked for another batch unless every possible output
  socket has room for one complete batch.
- `transport_wire` is the only code that reads or writes multibyte wire fields.
- Path measurements and scheduler state belong to a connection; one client's
  RTT, loss, or telemetry must never determine another client's schedule.
- Incoming FEC assemblers share a 64 MiB transport-wide memory budget and each
  connection has eight active assembler slots. Growth must fit both the old
  buffers and their replacements within that budget until copying completes.
  Rejected growth preserves partial data; reusing existing capacity requires
  no additional allocation allowance.
- NACK handling sends at most 64 requested symbols per repair and accepts at
  most 16 repair requests per connection per second.
- Event payload pointers are borrowed and valid only during the callback.
- The creating thread owns a transport. Callbacks run synchronously on that
  thread and may call non-driving APIs; recursive ticks, callback destruction,
  and cross-thread operations are rejected.
- HELLO negotiation completes before `TRANSPORT_EVENT_CONNECTED`, so capability
  and effective-limit snapshots are valid inside the connected callback.

`transport_publish_ex` distinguishes delivery, buffering, no recipients,
partial delivery, backpressure, invalid input, and internal failure. The legacy
boolean wrapper returns false for partial delivery and all failures.

Finite rateless publishers call `transport_finish_track` after their final
application record. Publication assigns internal FEC object IDs, emits a
rolling checkpoint every 32 objects, and sends a reliable completion
watermark. Receivers keep at most eight missing-window bitmaps and retry one
absent object at a time. Cumulative ACKs release source repair-cache entries;
if eight windows remain unacknowledged, publication reports backpressure rather
than evicting recoverable objects.

`transport_get_stats` reports protocol errors, handshake and reconnect counts,
publication outcomes, FEC and repair pressure, thread-contract violations, UDP
would-block/errors, and current/peak egress occupancy.
`transport_get_conn_stats` adds stable connection IDs, negotiated limits,
authentication state, subscriptions, and receive counters.
Checkpoint, completion, ACK, cache-release, cache-backpressure, pending-window,
and oldest-unacknowledged-age counters expose bounded recovery behavior.

Component-level tests cover these ownership and lookup boundaries. End-to-end
tests cover connection establishment, authentication, reliable streams,
datagrams, FEC/NACK recovery, IPv4/IPv6 mutual TLS, reconnect after peer
restart, live interface removal, and multipath behavior.
