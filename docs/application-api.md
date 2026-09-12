# Native application API

Include `qlinq.h` from `src/common` and link `libqlinq.a` with the same system
libraries as `qlinq-app`. The header exposes no Quicly or internal transport
types and is usable from C and C++. The existing `transport.h` API remains
available, and the two APIs exchange the same wire records.

## Contexts, endpoints and streams

Create a context with `qlinq_context_create`, then create listening endpoints
with `qlinq_listen` or connecting endpoints with `qlinq_connect`. A listener
has no remote addresses; a connecting endpoint has at least one. Both require
a port and one or more local bind addresses. A listener accepts multiple
peers; a connecting endpoint represents one peer, optionally over multiple
paths. Configure certificate verification and an application shared secret
through `qlinq_security_config_t`. Secrets are copied; address and file-name
strings need only remain valid during endpoint creation.

`qlinq_publish` and `qlinq_subscribe` return named stream handles. Each stream
selects content type and datagram, reliable, fixed-FEC or rateless delivery.
Subscriptions created before authentication activate when peers become ready,
and reactivate after a configured client reconnect. Send and receive streams
with the same name are independent. Stream names are nonempty and at most
63 bytes. `qlinq_stream_close` stops use of the handle and unsubscribes receive
streams; it does not define a finite-transfer completion protocol.

Drive progress with `qlinq_service(context, timeout_ms)` and drain events with
`qlinq_next_event`. Zero timeout polls; -1 waits for network or timer activity.
Pending events return immediately. Internal deadlines also service FEC group
flushes and periodic recovery/path measurements. `QLINQ_EVENT_PEER_READY` means
application authentication completed. Subscriber join/leave events and
`QLINQ_EVENT_STREAM_WRITABLE` let publishers discover recipients and resume
sending. The writable event describes a transition to writable, not a promise
that every future record will fit; always check `qlinq_stream_send`'s result.

```c
qlinq_stream_config_t stream_config = {
    .content_type = QLINQ_CONTENT_DATA,
    .delivery = QLINQ_DELIVERY_RELIABLE,
    .name = "telemetry"
};
qlinq_stream_t *publisher = qlinq_publish(endpoint, &stream_config);
/* Check publisher for NULL and service authentication/subscription events. */
qlinq_record_t record = {
    .sequence = 42, .data = "sample", .size = 6
};
qlinq_send_result_t result = qlinq_stream_send(publisher, &record);
/* WOULD_BLOCK is retryable; SENT/BUFFERED/PARTIAL must not be blindly resent. */

qlinq_status_t status = qlinq_service(context, 10);
/* Handle negative status even when the event queue is full. */
qlinq_event_t event;
while (qlinq_next_event(context, &event)) {
    if (event.type == QLINQ_EVENT_RECORD) {
        /* Consume event.record.data and event.record.size. */
    }
    qlinq_event_release(&event);
}
```

`qlinq_endpoint_get_stats`, `qlinq_endpoint_get_peer`, and
`qlinq_stream_get_stats` expose connection state, recovery/queue counters,
subscriber counts and stream readiness. `qlinq_context_last_status` reports
operation errors, including failures that could not be queued as events.

## Record compatibility and ownership

Send payloads are borrowed during `qlinq_stream_send`; callers may reuse the
buffer after it returns. Receive payloads and disconnect reasons are copied
into owned events. Pop each event once and release it exactly once with
`qlinq_event_release`. Do not release multiple copies of the same event.

The queue defaults to 1024 events and 64 MiB, including event metadata and
copied payload/string storage. Popping releases queue capacity; popped events
are separately owned by the application and remain valid until release, even
after context destruction. Endpoint and stream pointers in those events cease
to be valid when the context is destroyed. The application must bound its own
collection of retained, popped events.

Event overflow returns a resource-limit status. If a reliable or FEC record
cannot be retained, the affected connection closes with a resource-limit error;
plain datagram delivery can drop under pressure. A full queue may have no room
for an error event, so applications must inspect service status as well.

FEC DATA publication uses the transport's existing grouped-record format.
The API splits recovered groups into individual payload events without adding
or interpreting a private record envelope. Consequently, received group and
sequence IDs for FEC DATA identify the transport's coding object, and several
records can share them; per-record application IDs must be carried in the
payload when needed. Other modes expose the transport's object metadata.
Existing payload bytes, including bytes resembling an envelope marker, remain
unchanged. Limits on FEC objects include the transport's grouped-record length
prefixes; no extra wrapper-header allowance is needed.

## Timing, lifecycle and threading

Endpoint timing configuration includes `receive_object_timeout_ms`,
`initial_rtt_ms`, and `handshake_timeout_rtt_multiplier`. The first defaults
to 2000 ms; zero for the other fields keeps the underlying default.

`qlinq_endpoint_shutdown` begins an orderly connection shutdown and stops
reconnect. Continue servicing until `qlinq_endpoint_is_drained`, subject to an
application deadline. `qlinq_endpoint_close` releases the transport immediately.
`qlinq_endpoint_reload_credentials` atomically replaces the identity for future
handshakes. Closing an endpoint closes its stream handles. Closed handles remain
allocated until `qlinq_context_destroy`, which releases endpoints, streams and
unpopped events.

All context, endpoint and stream operations use the creating thread. Logging
callbacks execute synchronously and must not call the API. Cross-thread access
and API calls from logging callbacks are rejected. An independently owned,
popped event can be transferred to another thread for consumption and release.

This interface covers unicast use. It does not expose multicast configuration,
listener-initiated mesh connections, or finite-transfer finish/drain/abort
stream states. The separate Quicly keepalive patches remain separate work.
