# Transport architecture

The low-level public transport API remains in `transport.h`. The application
wrapper in `qlinq.h` adds owned events and named streams; see
[Native application API](application-api.md). The Quicly implementation is
split into small internal modules with one-way dependencies toward shared data
types and the wire codec.

| Module | Responsibility |
| --- | --- |
| `qlinq.c` | Application contexts, endpoints, named streams and owned event queues |
| `transport_quicly.c` | Connection lifecycle, socket event loop, and public control/query API |
| `transport_internal.h` | Private shared transport and connection state |
| `cli_parse.c` | Shared bounded numeric and endpoint parsing for app and daemon |
| `transport_config.c` | Default resolution and validation of resource limits |
| `transport_protocol.c` | HELLO negotiation, stream dispatch, datagram receive, and FEC assembly |
| `transport_publish.c` | Reliable/datagram publication, FEC generation, and grouped data flushes |
| `transport_tracks.c` | Small delivery-class validation and profile derivation |
| `transport_wire.c` | Versioned, bounded byte-level encoding and decoding |
| `transport_stream.c` | Bounded retained stream frames and QUIC acknowledgement accounting |
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

## Timing and connection control

`transport_config_t.fec_assembler_timeout_ms` sets the inactivity timeout for
partial FEC objects; zero preserves the 2000 ms default. Expiration releases
assembler memory and reports `TRANSPORT_EVENT_OBJECT_LOST`, including while
outbound NACKs are rate limited. Poll deadlines include assembler expiration
and deferred aggregate-budget retries.

`initial_rtt_ms` sets Quicly's initial RTT estimate, and
`handshake_timeout_rtt_multiplier` sets its handshake timeout in RTT multiples.
Zero preserves each Quicly default. Neither changes the configured QUIC idle
timeout.

`transport_close_conn_with_error` accepts zero or a tagged
`QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE` value and an optional reason.
It preserves an existing close reason, ignores unknown connections and invalid
error types, and counts a resource-limit close once. `transport_close_conn`
continues to request an ordinary application close.

Server packet routing uses a bounded 256-slot connection cache keyed by the
stable master CID. Hits still pass Quicly's destination check; collisions and
unknown CIDs fall back to the full scan. Entries are invalidated before their
connections are freed. Path scheduling reuses path-stat snapshots and resolves
the common datagram symbol size once per update. IPv6 link matching includes
the scope ID.

## Ownership rules

- `transport_memory` initializes and destroys arenas and frame assemblers.
- `transport_subscriptions` is the only code that allocates aliases or changes
  subscription entries. Send and receive directions have independent alias
  namespaces and subscription limits, so unsubscribing from incoming data does
  not stop publication to a peer. Gap and checkpoint state is allocated only
  for active subscriptions and released on removal or disconnect.
- `transport_fec_state` owns cached FEC instances and copies of sent objects.
- `transport_stream` emits complete frames in one Quicly egress operation.
  Retained allocations include frame payloads, ownership headers, and vector
  capacity. Partial ACKs keep the entire frame charged until QUIC releases it;
  unused vector capacity is compacted as frames drain.
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
  most 16 repair requests per connection per second. An exact NACK is coalesced
  while its reliable frame remains retained, including partial ACKs and later
  ACKed ranges behind a missing prefix. Once released, a lost repair response
  can trigger another request. Queue pressure defers NACKs without spending
  rate tokens or consuming essential-control reserves. Outbound requests also
  share `max_aggregate_nack_requests_per_second` across all peers (default 16,
  maximum 65535). This token bucket permits a one-second burst, then refills
  continuously; zero configuration selects the default. Recovery rotates its
  starting peer after an admitted or coalesced request, and pauses request
  scans until the aggregate budget refills. Assembler expiration continues
  during that pause. These limits are local policy, not wire negotiation.
- Event payload pointers are borrowed and valid only during the callback.
- The creating thread owns a transport. Callbacks run synchronously on that
  thread and may call non-driving APIs; recursive ticks, callback destruction,
  and cross-thread operations are rejected.
- HELLO negotiation completes before `TRANSPORT_EVENT_CONNECTED`, so capability
  and effective-limit snapshots are valid inside the connected callback.

`transport_publish_ex` distinguishes delivery, buffering, no recipients,
partial delivery, backpressure, invalid input, and internal failure. The legacy
boolean wrapper returns false for partial delivery and all failures.
Reliable publication reports backpressure when retained storage is full.
`max_stream_egress_bytes` defaults to 2 MiB per stream and
`max_total_stream_egress_bytes` to 16 MiB per transport. Hard bounds also limit
retained frames to 256 per stream and vector capacity to 8,192 per transport.
Application data and retryable NACKs leave 64 KiB and 16 frames available on a
control stream, plus 2 MiB and 256 vector slots across the transport, for
essential control. Exhausting essential-control capacity closes the connection
with a resource-limit error. Configuration must accommodate one maximum-sized
reliable object plus control space.

Datagram publication checks the smallest negotiated FEC object limit among
eligible receivers before accepting a record into a group or emitting data.
Grouped records include their two-byte length prefixes in this limit. Short
objects use smaller FEC symbols instead of padding every symbol to the maximum
UDP payload. Received objects preserve the subscribed track flags; applications
recognize grouped FEC data when either FEC flag is present.

Finite rateless publishers call `transport_finish_track` after their final
application record. Publication assigns internal FEC object IDs, emits a
rolling checkpoint every 32 objects, and sends a reliable completion
watermark. Receivers keep at most eight missing-window bitmaps and retry one
absent object at a time. Cumulative ACKs release source repair-cache entries;
if eight windows remain unacknowledged, publication reports backpressure rather
than evicting recoverable objects. The source cache also has a configurable
`max_recovery_cache_bytes` payload budget, defaulting to 16 MiB, and admits new
objects only when both byte and entry limits can be met without evicting
protected objects. Configuration must hold a maximum FEC object and one
32-object recovery window at the grouped publication size. Completed cumulative
checkpoints and repeated final watermarks retire obsolete receiver gaps and
partial objects through the acknowledged object ID, preserving other groups,
tracks, and later objects.

`transport_get_stats` reports protocol errors, handshake and reconnect counts,
publication outcomes, FEC and repair pressure, thread-contract violations, UDP
would-block/errors, and current/peak egress occupancy.
`transport_get_conn_stats` adds stable connection IDs, negotiated limits,
authentication state, total active subscriptions across both directions, and
receive counters. Stream statistics include retained bytes, frames, vector
capacity, their peaks, blocked writes, and control failures. Cache statistics
include current and peak payload bytes and entry counts; repair counters
separate coalesced requests from deferred requests.
Checkpoint, completion, ACK, cache-release, cache-backpressure, pending-window,
and oldest-unacknowledged-age counters expose bounded recovery behavior.

Component-level tests cover these ownership and lookup boundaries. End-to-end
tests cover connection establishment, authentication, reliable streams,
datagrams, FEC/NACK recovery, IPv4/IPv6 mutual TLS, reconnect after peer
restart, live interface removal, and multipath behavior.
