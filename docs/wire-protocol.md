# qlinq wire protocol

This document describes qlinq's private peer protocol. All multibyte integers
are unsigned and encoded in network byte order. The current protocol version is
1. A peer must reject an unsupported stream-frame version. Invalid datagrams
are discarded.

Version 1 is the initial versioned layout. It uses 64-bit object identifiers
and preserves object metadata on reliable streams. The legacy unversioned
format is not supported.

## Stream frame envelope

Control messages and reliable track objects use one common envelope:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | Magic bytes `QL` (`0x51 0x4c`) |
| 2 | 1 | Protocol version (`1`) |
| 3 | 1 | Frame type |
| 4 | 4 | Payload length |
| 8 | variable | Frame payload |

The receiver buffers incomplete frames and rejects unknown frame types or
payloads above the configured limit. The reliable-object implementation ceiling
is approximately 1 MiB and may be configured lower; a track-object payload has
a 20-byte metadata header followed by application data.

| Type | Name | Payload |
| ---: | --- | --- |
| 1 | Subscribe | Track descriptor |
| 2 | Unsubscribe | Track descriptor |
| 3 | Unicast | Application bytes |
| 4 | Authentication request | Token bytes, at most 65,535 |
| 5 | Authentication response | One status byte: `0` or `1` |
| 6 | Keyframe request | Track descriptor |
| 7 | Reliable track object | Object metadata followed by object bytes |
| 8 | NACK | NACK descriptor |
| 9 | HELLO | Capability and resource-limit advertisement |
| 10 | Flexicast binding | Flow ID, key epoch, and track alias |
| 11 | Track completion | Alias, group ID, and final FEC object ID |
| 12 | Recovery checkpoint | Alias, group ID, first and final FEC object IDs |
| 13 | Recovery checkpoint ACK | Alias, group ID, and final FEC object ID |
| 14 | Track abort | Alias and three reserved zero bytes |
| 15–255 | Reserved | Rejected by this version |

`HELLO` is the first frame on the bidirectional control stream in each
direction. Application control frames and the public connected event are gated
until both peers have exchanged valid HELLO frames. This is still protocol
version 1: the handshake was added before version 1 had external users.

The HELLO payload is 20 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | Role: client `0`, server `1` |
| 1 | 1 | Reserved zero byte |
| 2 | 2 | Maximum paths |
| 4 | 4 | Capability flags |
| 8 | 4 | Maximum reliable-object bytes |
| 12 | 4 | Maximum FEC-object bytes |
| 16 | 2 | Maximum subscriptions |
| 18 | 2 | Maximum UDP payload bytes |

Defined capabilities are reliable objects (`0x01`), datagrams (`0x02`),
Reed-Solomon FEC (`0x04`), rateless FEC (`0x08`), multipath (`0x10`),
application authentication (`0x20`), and experimental Flexicast datagrams
(`0x40`). Rolling recovery checkpoints and completion acknowledgements use
`0x80`; true rateless repair requests use `0x100`. Unknown capability bits,
duplicate HELLO frames, a peer with the wrong role, or an application frame
before HELLO are protocol errors. Each connection uses the lower local/peer
object, subscription, and UDP-payload limits.

## Experimental Flexicast control

Flexicast is opt-in and currently applies only to unreliable track datagrams.
Reliable objects remain ordinary per-connection QUIC streams. The implemented
backend protects one packet using a flow-wide packet-number space and traffic
secret. With an IPv4 SSM source policy, it sends those bytes once to the
announced multicast group; receivers join the group before returning JOIN.
Without that policy, or when local multicast submission fails, qlinq replicates
the identical bytes to READY members over the existing UDP sockets. Both paths
share group security, replay protection, FEC fanout, and acknowledgement
aggregation.

If a receiver cannot join the announced group, it accepts the announcement but
withholds JOIN. The source therefore keeps that subscriber on its ordinary
authenticated unicast data path instead of treating the local membership error
as a connection protocol failure.

Membership changes rotate the flow secret using a higher-sequence `FC_KEY` and
keep packet numbers monotonic across epochs. Members temporarily return to
ordinary unicast until they acknowledge the new epoch with READY. A member that
has at least 32 unacknowledged packets for one second is sent LEAVE and demoted
to ordinary unicast; stale PATH_ACK frames already queued before demotion are
silently ignored.

Receiver SSM memberships are keyed by address family, source address, group
address, UDP port, and interface index. Multiple Flexicast flows using that
tuple share one kernel membership. IPv4 uses `IP_ADD_SOURCE_MEMBERSHIP` and
`IP_DROP_SOURCE_MEMBERSHIP`; IPv6 uses the RFC 3678
`MCAST_JOIN_SOURCE_GROUP` and `MCAST_LEAVE_SOURCE_GROUP` API. The final flow
drops the membership, and transport shutdown explicitly drops all remaining
memberships before closing the family-specific multicast sockets. IPv4 groups
must be in `232/8`; IPv6 groups must be in the RFC 4607 `ff3x::/32` SSM range.

An application unsubscribe sends the existing reliable `UNSUBSCRIBE` control
frame and retires the receiver's Flexicast flow immediately. A redundant
`FC_STATE(LEAVE)` accelerates source-side removal; a late `LEAVE` for an already
retired source flow is ignored. Re-subscribing starts the bind/announce/join/key
exchange again, so it is also the explicit retry after a route or interface
outage has been repaired.

FEC-backed data receivers retain a bounded 256-object completed-delivery window.
Repair or redundant symbols for an object in that window are discarded before
assembler allocation, so a completed object produces exactly one application
event. Objects older than the window are treated as expired rather than being
resurrected by very late repair traffic.

Checkpoint-capable fixed-FEC and rateless publishers send a reliable 28-byte
`TRACK_CHECKPOINT` after every 32 internal FEC objects. Its payload is the
one-byte track alias, one-byte flags, two reserved zero bytes, and the 64-bit
group, first-object, and final-object IDs. The `BASELINE` flag (`0x01`) tells a
late subscriber where its recovery obligation begins without requesting the
older window. The receiver retains at most eight outstanding 32-object
windows and requests absent objects one at a time every 500 milliseconds;
partially assembled objects continue using symbol-level NACKs. Once every
object in a window has been delivered, it returns a reliable 17-byte
`TRACK_CHECKPOINT_ACK`.

When a finite publisher finishes, it freezes the current receiver cohort,
flushes grouped data, and sends the 17-byte `TRACK_END`. For
checkpoint-capable peers this is the final checkpoint
and is acknowledged through the same ACK frame; older peers retain the final
32-object recovery behavior without sending an ACK. The source protects cached
objects from ring eviction while an all-capable subscribed cohort has
unacknowledged windows. It releases a window only after every member has
acknowledged it. A subscriber arriving after final completion receives the
four-byte `TRACK_ABORT` instead of joining the finished transfer. Unsubscribe
or connection teardown settles that member as failed for completion reporting.
Eight unacknowledged windows exhaust the 256-object repair cache and apply
publication backpressure rather than silently overwriting recoverable data.

`TRACK_ABORT` is also sent when the source application cancels a stream. On
receipt, the receiver discards incomplete assemblers and recovery windows for
the alias and reports a terminal abort. The frame is idempotent; its three
reserved bytes must be zero.

The source holds Flexicast payloads in bounded plaintext queues until a
per-flow token bucket permits transmission. Ordinary data is limited to 256
packets and repair data to 128 packets; the two queues share the configured
per-socket egress byte budget. A pluggable Quicly controller
produces the logical flow rate, burst, inflight target, limiting receiver, and
next feedback timeout. qlinq executes that output and accounts for physical
cost: replicated-unicast transmission charges one packet per recipient, while
native multicast charges one packet total. The `multicast` controller follows
the limiting receiver with conservative additive growth and multiplicative
reduction. The `adaptive` controller adds flat-loss baseline learning,
queue-delay and ECN classification, active-sender-aware growth, median-rate
catch-up, and recovery probes for radio-oriented meshes. The controller name is
an implementation profile, not a wire negotiation value. qlinq also reports
transport-generic queued external work, age, and physical-airtime share. That
signal freezes adaptive growth while work is outstanding; it does not reduce
the total path rate, because doing so would also starve the repair service that
must clear the signal.

The initial receiver ACK in each key epoch is immediate so short flows produce
feedback. Subsequent packets are acknowledged as ranges after the negotiated
delay or packet-frequency threshold, reducing control-path fan-in without
sacrificing startup liveness. Queue exhaustion is reported as publication
backpressure, and token and controller deadlines participate in
`transport_get_first_timeout`. Queuing plaintext ensures a payload delayed
across an epoch change is protected only with the current flow key. Permanent
native-send errors immediately use the identical protected packet on the
replicated-unicast path; only transient would-block errors enter the UDP egress
queue.

Flexicast capability, endpoint announcement, member state, and key exchange use
the transport parameter and `FC_ANNOUNCE`, `FC_STATE`, and `FC_KEY` frames from
`draft-navarre-quic-flexicast-02`. The qlinq binding payload is 16 bytes: alias,
three reserved zero bytes, 64-bit Flow ID, and 32-bit key epoch. It carries only
the application metadata absent from `FC_ANNOUNCE`. Receivers return multicast
packet acknowledgements in MPQUIC `PATH_ACK` frames on their unicast connection,
using the Flow ID as `path_id` as specified by the Flexicast draft.

The protected Flexicast packet format below this control protocol is private
and experimental. It is implemented in the Quicly fork so header protection,
AEAD, shared packet numbers, anti-replay state, and per-member ACK accounting
stay transport invariants rather than qlinq publication policy.

A track descriptor contains alias, track type, flags, one-byte name length,
and up to 63 name bytes. A NACK descriptor contains alias, a flags byte,
64-bit group ID, 64-bit object ID, and a 16-bit count. The count is limited to
1,024. Flag `0x01` requests a whole object. Flag `0x02` selects rateless repair
and is valid only when the peer advertised `0x100` and the track uses rateless
FEC.

In indexed mode, the count is followed by that many 16-bit missing ESIs. A
whole-object request has a zero count. In rateless mode, the 20-byte descriptor
has no ESI list: the count is the number of additional degrees of freedom. A
rateless whole-object request has a zero count because the source derives the
initial bounded deficit from the cached object's source-symbol count. Peers
without the rateless-repair capability continue using indexed NACKs for a
rateless-coded track.

NACK frames remain reliable and private to each receiver's QUIC connection.
For an active Flexicast member, the resulting FEC repair datagrams are sent on
the protected group flow so one physical repair can satisfy the cohort. A
bounded randomized receiver backoff lets an earlier shared repair suppress
later feedback without making NACK contents visible to peers. The source
suppresses exact repeats for 250 milliseconds and enforces both per-peer and
aggregate request token buckets. During a fixed 25 ms holdoff aligned with the
minimum randomized NACK backoff, indexed requests are combined by bounded union
while rateless requests are combined by maximum remaining deficit. At most 64
repair intents can await aggregation and at most
64 symbols are materialized per batch. Rateless repair uses fresh monotonic
RaptorQ ESIs and stops cleanly at the 1,024-symbol implementation bound. A
materialized symbol suppresses duplicate scheduling until it is sent, and an
all-receiver checkpoint ACK cancels obsolete queued repairs through the
acknowledged object.

Reliable-object metadata contains an alias, keyframe flag, priority, one
reserved zero byte, 64-bit group ID, and 64-bit object ID. Each unidirectional
reliable track stream is bound to the alias in its first
object frame. A later frame with a different alias is a protocol error.

## Datagram envelope

Datagrams start with the same magic and version followed by a datagram type.
Type 1 is an FEC symbol and type 2 is telemetry.

The FEC header is 44 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | Magic bytes `QL` |
| 2 | 1 | Protocol version |
| 3 | 1 | Datagram type (`1`) |
| 4 | 1 | Track alias |
| 5 | 1 | Keyframe flag (`0` or `1`) |
| 6 | 1 | Priority |
| 7 | 1 | Path ID |
| 8 | 8 | Group ID |
| 16 | 8 | Object ID |
| 24 | 2 | Symbol index |
| 26 | 2 | Total symbols |
| 28 | 2 | Data symbols |
| 30 | 2 | Symbol size |
| 32 | 4 | Original object size |
| 36 | 8 | Send timestamp in nanoseconds |
| 44 | variable | Exactly one symbol |

The telemetry datagram is exactly 24 bytes: the four-byte envelope, path ID,
three reserved zero bytes, an eight-byte send timestamp, and an eight-byte
receive timestamp.

Connection closes use stable application error codes: `0x100` for malformed or
unsupported protocol input, `0x101` for authentication failures, and `0x102`
for peer-triggered resource-limit violations.

## Evolution rules

- Change the version for incompatible layouts or semantics.
- Add a new type for compatible new messages; older peers will reject
  unknown stream types and discard unknown datagram types.
- Reserved fields must be sent as zero and validated on receipt.
- Never serialize C structs directly. Use the bounded codec in
  `src/common/transport_wire.c` so padding, alignment, and host byte order do
  not affect the wire representation.
