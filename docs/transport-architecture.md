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
- `transport_fec_state` owns cached FEC instances and copies of rateless DATA
  objects. Cache slots derive from the configured byte and object limits, up
  to 4,096 objects, matching the receiver's 128 recovery windows of 32 objects.
  An unresolved recovery prefix therefore backpressures publication before
  the sender can exceed the receiver's checkpoint history.
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
  Each available path uses its own congestion-window/RTT rate proxy, expressed
  in full-sized FEC symbol equivalents per second. Missing window/RTT samples
  use 100 symbols/s and missing RTT uses 50 ms one-way latency; another path's
  estimate is never substituted. Rate, RTT/2 plus relative one-way delay, and
  cumulative loss are smoothed every 25 ms. The rate is a sending-rate proxy,
  not a measured link capacity.
  At publication, uninitialized paths are sampled immediately and unsent queue
  inputs are refreshed even between ticks: the path's QUIC DATAGRAM frame count
  plus `ceil(socket_egress_bytes / full_symbol_size)`. The socket backlog is
  shared across peers and is included once for each candidate path's completion
  estimate. Publication also includes outstanding bytes in flight. Kernel and
  network queues are excluded. Admission normally permits 50 ms of work (8–64
  symbols); one complete allocation may exceed that allowance after all prior
  debt drains, within the actual 64-frame path queue. Every transmitted symbol
  is charged, so subsequent allocations wait for debt repayment. Rateless DATA
  preflight counts only systematic source symbols, not speculative parity.
  Queue occupancy is not smoothed, so small queues and completed drains take
  effect immediately. Small single-symbol objects do not change the units of
  the stored rate estimate.
  Debug log events from component `scheduler` include connection and physical
  path identity, object identity, symbol size, raw and used bandwidth/latency/
  loss/queue inputs, and planned data/total symbol allocation. `source` identifies
  `cwnd_rtt`, a cold-start `default`, or a test `override`; `mode` distinguishes
  pathflow from the non-FEC and single-symbol round-robin cases. These events
  describe scheduling decisions, including plans subsequently backpressured.
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

`make check-multipath-demo` runs the dynamically discovered Cellular, Wi-Fi,
Satcom and Ethernet profiles in an isolated user/network namespace. It shapes
delay and loss, not bandwidth. The benchmark reports a shared server-traffic
window after all four paths have been active for 500 ms, and fails if the
window is shorter than one second or Ethernet carries no more than half of
the server's UDP payload bytes. This avoids comparing lifetime totals from
paths that joined at different times. Rates include protocol traffic and are
not capacity measurements. Reported QUIC RTT can include an ACK returned on
another link, so it need not equal the configured same-link round-trip delay.

`./examples/multipath_bw_demo` (or `make check-multipath-bw-demo`) is a separate
bandwidth experiment. All four paths are validated before sending; each has a
20 ms one-way delay and independent forward/reverse HTB caps of 1, 2, 4 and
8 Mbps. There is no injected loss, though overflowing a bounded kernel queue
can still drop packets. Offered application traffic ramps from 2 to 12 Mbps
over four seconds, followed by eight seconds at 12 Mbps and a three-second
drain. Publication backpressure is counted as undelivered offered traffic.

The demo records actual kernel dequeue rates, UDP send shares, sampled kernel
queue occupancy and growth, queue drops, application goodput, delivery, and
mean/p95/p99 completion latency. Goodput counts records completed during the
measurement window; delivery/latency cover records offered in that window,
including completions during the drain. Kernel queue milliseconds include the
configured propagation delay and do not include QUIC or application queues.
The kernel samples omit an additional half-second at the start and quarter-
second at the end of the steady window to allow for sampler timing.

The explicit checks require cap compliance within 5%, increasing dequeue rates
with increasing caps, goodput above the fastest individual link's 8 Mbps cap,
at least 99% delivery of offered records, p99 latency at most 250 ms, no steady
queue drops, and late median kernel queues at most 100 ms with growth at most
50 ms. A failing check returns nonzero and preserves `benchmark.log`,
`queues.json`, and `report.json` in a printed temporary directory. Use
`--output-dir PATH` to choose it, or `--benchmark PATH` to compare a compatible
benchmark built with another transport version. Run the report-validator tests
with `python3 examples/test_multipath_bw_demo.py`.

This is a diagnostic target, not part of `release-check`: the initial per-path
window/RTT and queue-input implementation still fails the saturated profile.
An observed run produced 2.009 Mbps goodput, admitted 207 of 1,499 offered
steady-window records, delivered 205, and reached 923 ms p99 latency. These
are observed results, not relaxed acceptance limits; the benchmark is intended
to expose the remaining capacity-estimation and backpressure behavior.
