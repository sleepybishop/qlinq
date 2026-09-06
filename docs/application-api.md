# Native application API

`qlinq.h` is the recommended interface for applications. It presents qlinq as
a collection of named streams carried by authenticated endpoints. The lower
level `transport.h` interface remains available for the daemon and specialized
integrations.

## Model

- A **context** owns endpoints and a bounded event queue.
- An **endpoint** listens for peers or connects to a peer over one or more
  paths.
- A **publishing stream** accepts application records.
- A **subscribed stream** produces owned record events.

An endpoint does not determine application data lifetime or delivery mode.
Each stream independently selects reliable, datagram, fixed-FEC, or rateless
delivery.

## Minimal publisher

```c
#include "qlinq.h"

static const char secret[] = "replace-this-secret";

qlinq_context_t *context = qlinq_context_create(NULL);

qlinq_endpoint_config_t endpoint_config = {
    .bind_addresses = {"192.0.2.10"},
    .bind_address_count = 1,
    .port = 8888,
    .security = {
        .shared_secret = secret,
        .shared_secret_size = sizeof(secret) - 1,
        .certificate_file = "peer.crt",
        .private_key_file = "peer.key",
        .trust_store_file = "mesh-ca.crt",
    },
    .group_delivery = {
        .enabled = true,
        .group_address = "232.1.2.3",
        .port = 9000,
        .interface_address = "192.0.2.10",
        .congestion_control = QLINQ_GROUP_CC_ADAPTIVE,
    },
};

qlinq_endpoint_t *endpoint = qlinq_listen(context, &endpoint_config);
qlinq_stream_t *stream = qlinq_publish(
    endpoint,
    &(qlinq_stream_config_t){.content_type = QLINQ_CONTENT_DATA,
                             .delivery = QLINQ_DELIVERY_RATELESS,
                             .name = "telemetry/position"});

const char payload[] = "record bytes";
qlinq_send_result_t sent = qlinq_stream_send(
    stream, &(qlinq_record_t){.group_id = 7,
                              .sequence = 42,
                              .data = payload,
                              .size = sizeof(payload) - 1,
                              .priority = 1});
```

`QLINQ_SEND_SENT` means the record was accepted by the active transport path;
it does not claim that every subscriber has received it. Finite fixed-FEC and
rateless streams call `qlinq_stream_finish()` after their final record so a
partial coding group is flushed and the completion watermark is sent.

## Minimal subscriber

```c
qlinq_endpoint_config_t endpoint_config = {
    .bind_addresses = {"0.0.0.0"},
    .bind_address_count = 1,
    .remote_addresses = {"192.0.2.10"},
    .remote_address_count = 1,
    .port = 8888,
    .security = {
        .shared_secret = secret,
        .shared_secret_size = sizeof(secret) - 1,
        .trust_store_file = "mesh-ca.crt",
    },
    .group_delivery = {
        .enabled = true,
        .interface_address = "192.0.2.20",
        .congestion_control = QLINQ_GROUP_CC_ADAPTIVE,
    },
};

qlinq_endpoint_t *endpoint = qlinq_connect(context, &endpoint_config);
qlinq_stream_t *stream = qlinq_subscribe(
    endpoint,
    &(qlinq_stream_config_t){.content_type = QLINQ_CONTENT_DATA,
                             .delivery = QLINQ_DELIVERY_RATELESS,
                             .name = "telemetry/position"});

for (;;) {
  if (qlinq_service(context, -1) < 0)
    break;

  qlinq_event_t event;
  while (qlinq_next_event(context, &event)) {
    if (event.type == QLINQ_EVENT_RECORD && event.stream == stream) {
      consume(event.record.data, event.record.size);
    }
    qlinq_event_release(&event);
  }
}
```

A subscription may be created before the connection completes. It is retained
and activated after peer authentication. Event record bytes are copied into
the context's bounded queue and remain valid until `qlinq_event_release()`.
For FEC-backed data streams, the façade preserves each record's group,
sequence, keyframe, and priority metadata inside the grouped transport payload;
receivers using the same API recover the original record boundaries and
metadata.

## Progress and ownership

The thread that creates a context owns that context, its endpoints, and its
streams. `qlinq_service()` drives socket and timer progress and never invokes
application code from a background thread. A context defaults to 1,024 queued
events and 64 MiB of queued event storage; both bounds are configurable.

Closing a stream or endpoint is immediate from the application's perspective.
Handles remain safe to compare with already queued events until the context is
destroyed. Applications must release popped events before destroying their
context.

## Operational lifecycle

Clients can opt into bounded exponential reconnect with
`reconnect_enabled`, `reconnect_initial_delay_ms`, and
`reconnect_max_delay_ms`. Named subscriptions remain registered while the peer
is unavailable and are activated again after the replacement connection is
authenticated. Flexicast subscriptions also renegotiate their flow, group key,
and kernel SSM membership; reconnect does not reuse the previous group key.

`qlinq_endpoint_shutdown()` begins an orderly endpoint close and disables
automatic reconnect. Continue calling `qlinq_service()` until
`qlinq_endpoint_is_drained()` is true, then call `qlinq_endpoint_close()`.
`qlinq_endpoint_reload_credentials()` atomically replaces the certificate and
private key used by future handshakes without changing established TLS
sessions.

`QLINQ_EVENT_PEER_DISCONNECTED` includes the transport error, the raw library
error, whether the error was an application or remote error, the offending
frame type when known, and an owned reason string. The reason remains valid
until `qlinq_event_release()`.

Set `log_callback` and `log_user_data` on `qlinq_context_config_t` to receive
structured component, severity, peer, path, and message fields. Log strings
are borrowed for the duration of the callback. Endpoint statistics expose
reconnect outcomes, group membership and interface fallback/rejoin counts,
control-plane throttling, repair backlog and age, and multicast-versus-repair
physical airtime.

## Stream lifecycle

A publishing stream starts in `QLINQ_STREAM_OPEN`. `qlinq_stream_send()` may
return `QLINQ_SEND_WOULD_BLOCK` when bounded recovery or egress state is full;
`QLINQ_EVENT_STREAM_WRITABLE` is edge-triggered and reports when the stream can
accept records again. `qlinq_stream_is_writable()` provides the current level.

`qlinq_stream_finish()` starts asynchronous completion for a fixed-FEC or
rateless data stream and changes the publisher to `QLINQ_STREAM_FINISHING`.
It snapshots the currently subscribed receivers, flushes the final coding
group, and rejects further sends. A receiver gets
`QLINQ_EVENT_STREAM_FINISHED` only after every object through the terminal
watermark has either arrived or been recovered. The publisher gets
`QLINQ_EVENT_STREAM_DRAINED` after every receiver in the snapshot has
confirmed completion or departed. Its `completion` fields distinguish the
confirmed and failed/departed counts. A transfer with no current subscribers
drains with all three counts equal to zero. A subscriber arriving after the
snapshot receives `QLINQ_EVENT_STREAM_ABORTED`; applications should use a new
stream name for a new finite transfer.

`qlinq_stream_abort()` immediately makes a publishing stream terminal, drops
its queued recovery state, and queues a reliable notification to its current
subscribers.
Both sides observe `QLINQ_EVENT_STREAM_ABORTED`. `qlinq_stream_get_stats()`
reports the current state, accepted and received record counts, subscriber and
group-member counts, completion confirmations, and writability.

## Current boundary

The API operates on bounded records. It does not itself provide a continuous
byte stream, receiver-confirmed per-record delivery token, or automatic peer
discovery. The `qlinq-cast` tool demonstrates how ordered file and pipeline
transfer can be built above the context, endpoint, lifecycle, and named-stream
model without changing existing callers.

A connected receiver is not silent: QUIC still requires handshake, packet
acknowledgement, path validation, and liveness traffic even when application
recovery uses proactive rateless symbols. A genuinely one-way receiver mode
would therefore use QUIC only for an optional authenticated bootstrap, then a
separate protected datagram data plane. Receivers that must be silent from the
first packet would need pre-provisioned keys and transfer metadata instead of a
QUIC connection. That mode is intentionally outside this lifecycle API.
