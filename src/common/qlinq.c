#include "qlinq.h"

#include "portable_sockets.h"
#include "transport.h"

#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

#define QLINQ_DEFAULT_EVENT_COUNT 1024U
#define QLINQ_DEFAULT_EVENT_BYTES (64U * 1024U * 1024U)
#define QLINQ_RECORD_HEADER_SIZE 26U

static const uint8_t qlinq_record_magic[4] = {'Q', 'S', 'R', 1};

typedef enum {
  QLINQ_STREAM_PUBLISH,
  QLINQ_STREAM_SUBSCRIBE
} qlinq_stream_direction_t;

typedef struct qlinq_event_node {
  struct qlinq_event_node *next;
  size_t allocation_size;
  qlinq_event_t event;
  uint8_t storage[];
} qlinq_event_node_t;

typedef struct qlinq_peer_state {
  struct qlinq_peer_state *next;
  transport_conn_t *connection;
  uint32_t id;
  bool ready;
} qlinq_peer_state_t;

struct qlinq_stream {
  struct qlinq_stream *next;
  qlinq_endpoint_t *endpoint;
  moq_track_id_t track;
  qlinq_content_type_t content_type;
  qlinq_delivery_t delivery;
  qlinq_stream_direction_t direction;
  qlinq_stream_state_t state;
  uint64_t records_sent;
  uint64_t records_received;
  uint64_t objects_lost;
  bool writable_known;
  bool last_writable;
  bool active;
};

struct qlinq_endpoint {
  struct qlinq_endpoint *next;
  qlinq_context_t *context;
  transport_t *transport;
  qlinq_stream_t *streams;
  qlinq_peer_state_t *peers;
  uint8_t *shared_secret;
  size_t shared_secret_size;
  size_t ready_peers;
  uint64_t records_received;
  bool listener;
  bool active;
};

struct qlinq_context {
  qlinq_endpoint_t *endpoints;
  qlinq_event_node_t *event_head;
  qlinq_event_node_t *event_tail;
  size_t queued_events;
  size_t queued_event_bytes;
  size_t max_queued_events;
  size_t max_queued_event_bytes;
  qlinq_log_callback_t log_callback;
  void *log_user_data;
  qlinq_status_t last_status;
};

static bool content_type_valid(qlinq_content_type_t type) {
  return type == QLINQ_CONTENT_VIDEO || type == QLINQ_CONTENT_AUDIO ||
         type == QLINQ_CONTENT_INPUT || type == QLINQ_CONTENT_TEXT ||
         type == QLINQ_CONTENT_DATA || type == QLINQ_CONTENT_TELEMETRY;
}

static bool delivery_valid(qlinq_delivery_t delivery) {
  return delivery == QLINQ_DELIVERY_DATAGRAM ||
         delivery == QLINQ_DELIVERY_RELIABLE ||
         delivery == QLINQ_DELIVERY_FIXED_FEC ||
         delivery == QLINQ_DELIVERY_RATELESS;
}

static uint8_t delivery_flags(qlinq_delivery_t delivery) {
  switch (delivery) {
  case QLINQ_DELIVERY_RELIABLE:
    return MOQ_TRACK_FLAG_RELIABLE;
  case QLINQ_DELIVERY_FIXED_FEC:
    return MOQ_TRACK_FLAG_FEC_ENABLED;
  case QLINQ_DELIVERY_RATELESS:
    return MOQ_TRACK_FLAG_FEC_RATELESS;
  case QLINQ_DELIVERY_DATAGRAM:
    return 0;
  }
  return 0;
}

static qlinq_delivery_t flags_delivery(uint8_t flags) {
  if ((flags & MOQ_TRACK_FLAG_RELIABLE) != 0)
    return QLINQ_DELIVERY_RELIABLE;
  if ((flags & MOQ_TRACK_FLAG_FEC_RATELESS) != 0)
    return QLINQ_DELIVERY_RATELESS;
  if ((flags & MOQ_TRACK_FLAG_FEC_ENABLED) != 0)
    return QLINQ_DELIVERY_FIXED_FEC;
  return QLINQ_DELIVERY_DATAGRAM;
}

static bool stream_matches(const qlinq_stream_t *stream,
                           const moq_track_id_t *track) {
  return stream && track && stream->track.type == track->type &&
         stream->delivery == flags_delivery(track->flags) &&
         strcmp(stream->track.name, track->name) == 0;
}

static qlinq_stream_t *find_stream(qlinq_endpoint_t *endpoint,
                                   const moq_track_id_t *track,
                                   qlinq_stream_direction_t direction) {
  for (qlinq_stream_t *stream = endpoint->streams; stream;
       stream = stream->next) {
    if (stream->active && stream->direction == direction &&
        stream_matches(stream, track))
      return stream;
  }
  return NULL;
}

static void set_status(qlinq_context_t *context, qlinq_status_t status) {
  if (context)
    context->last_status = status;
}

static void on_transport_log(void *user_data,
                             const transport_log_event_t *source) {
  qlinq_endpoint_t *endpoint = user_data;
  if (!endpoint || !source || !endpoint->context ||
      !endpoint->context->log_callback)
    return;
  qlinq_log_event_t event = {.level = (qlinq_log_level_t)source->level,
                             .component = source->component,
                             .peer_id = source->connection_id,
                             .path_index = source->path_index,
                             .message = source->message};
  endpoint->context->log_callback(endpoint->context->log_user_data, &event);
}

static bool queue_event(qlinq_context_t *context, const qlinq_event_t *source,
                        const void *payload, size_t payload_size,
                        const char *message) {
  size_t message_size = 0;
  if (message) {
    size_t message_length = strlen(message);
    if (message_length == SIZE_MAX) {
      set_status(context, QLINQ_STATUS_INVALID);
      return false;
    }
    message_size = message_length + 1U;
  }
  if (!context || !source ||
      payload_size > SIZE_MAX - sizeof(qlinq_event_node_t) ||
      message_size > SIZE_MAX - sizeof(qlinq_event_node_t) - payload_size) {
    set_status(context, QLINQ_STATUS_INVALID);
    return false;
  }
  size_t allocation_size =
      sizeof(qlinq_event_node_t) + payload_size + message_size;
  if (context->queued_events >= context->max_queued_events ||
      context->queued_event_bytes > context->max_queued_event_bytes ||
      allocation_size >
          context->max_queued_event_bytes - context->queued_event_bytes) {
    set_status(context, QLINQ_STATUS_RESOURCE_LIMIT);
    return false;
  }

  qlinq_event_node_t *node = calloc(1, allocation_size);
  if (!node) {
    set_status(context, QLINQ_STATUS_NO_MEMORY);
    return false;
  }
  node->allocation_size = allocation_size;
  node->event = *source;
  node->event._private = node;
  node->event.record.data = NULL;
  node->event.message = NULL;
  node->event.disconnect.reason = NULL;
  uint8_t *cursor = node->storage;
  if (payload_size != 0) {
    memcpy(cursor, payload, payload_size);
    node->event.record.data = cursor;
    cursor += payload_size;
  }
  if (message_size != 0) {
    memcpy(cursor, message, message_size);
    node->event.message = (const char *)cursor;
    if (node->event.type == QLINQ_EVENT_PEER_DISCONNECTED)
      node->event.disconnect.reason = (const char *)cursor;
  }

  if (context->event_tail)
    context->event_tail->next = node;
  else
    context->event_head = node;
  context->event_tail = node;
  context->queued_events++;
  context->queued_event_bytes += allocation_size;
  return true;
}

static void queue_error(qlinq_endpoint_t *endpoint, qlinq_status_t status,
                        const char *message) {
  if (!endpoint || !endpoint->context)
    return;
  set_status(endpoint->context, status);
  qlinq_event_t event = {
      .type = QLINQ_EVENT_ERROR, .endpoint = endpoint, .status = status};
  (void)queue_event(endpoint->context, &event, NULL, 0, message);
}

static qlinq_peer_state_t *find_peer(qlinq_endpoint_t *endpoint,
                                     transport_conn_t *connection) {
  for (qlinq_peer_state_t *peer = endpoint->peers; peer; peer = peer->next)
    if (peer->connection == connection)
      return peer;
  return NULL;
}

static qlinq_peer_state_t *add_peer(qlinq_endpoint_t *endpoint,
                                    transport_conn_t *connection) {
  qlinq_peer_state_t *peer = find_peer(endpoint, connection);
  if (peer)
    return peer;
  peer = calloc(1, sizeof(*peer));
  if (!peer) {
    queue_error(endpoint, QLINQ_STATUS_NO_MEMORY,
                "unable to retain connected peer state");
    return NULL;
  }
  peer->connection = connection;
  peer->id = transport_get_conn_id(endpoint->transport, connection);
  peer->next = endpoint->peers;
  endpoint->peers = peer;
  return peer;
}

static uint32_t peer_id(qlinq_endpoint_t *endpoint,
                        transport_conn_t *connection) {
  qlinq_peer_state_t *peer = find_peer(endpoint, connection);
  if (peer)
    return peer->id;
  return transport_get_conn_id(endpoint->transport, connection);
}

static void remove_peer(qlinq_endpoint_t *endpoint,
                        transport_conn_t *connection) {
  qlinq_peer_state_t **cursor = &endpoint->peers;
  while (*cursor) {
    qlinq_peer_state_t *peer = *cursor;
    if (peer->connection == connection) {
      if (peer->ready && endpoint->ready_peers != 0)
        endpoint->ready_peers--;
      *cursor = peer->next;
      free(peer);
      return;
    }
    cursor = &peer->next;
  }
}

static bool secret_equal(const qlinq_endpoint_t *endpoint, const uint8_t *data,
                         size_t size) {
  if (size != endpoint->shared_secret_size)
    return false;
  unsigned int difference = 0;
  for (size_t i = 0; i < size; i++)
    difference |= (unsigned int)(endpoint->shared_secret[i] ^ data[i]);
  return difference == 0;
}

static void fill_event_stream(qlinq_event_t *event, const moq_track_id_t *track,
                              qlinq_stream_t *stream) {
  event->stream = stream;
  event->content_type = (qlinq_content_type_t)track->type;
  event->delivery = flags_delivery(track->flags);
  memcpy(event->stream_name, track->name, sizeof(event->stream_name));
  event->stream_name[sizeof(event->stream_name) - 1U] = '\0';
}

static uint64_t read_u64(const uint8_t *input) {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; i++)
    value = (value << 8) | input[i];
  return value;
}

static uint32_t read_u32(const uint8_t *input) {
  return ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) |
         ((uint32_t)input[2] << 8) | input[3];
}

static void write_u64(uint8_t *output, uint64_t value) {
  for (size_t i = 0; i < 8; i++) {
    output[7U - i] = (uint8_t)value;
    value >>= 8;
  }
}

static void write_u32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)(value >> 24);
  output[1] = (uint8_t)(value >> 16);
  output[2] = (uint8_t)(value >> 8);
  output[3] = (uint8_t)value;
}

static bool queue_record(qlinq_endpoint_t *endpoint, transport_conn_t *conn,
                         const moq_track_id_t *track,
                         const moq_object_t *object, const uint8_t *data,
                         size_t size) {
  qlinq_stream_t *stream = find_stream(endpoint, track, QLINQ_STREAM_SUBSCRIBE);
  if (!stream || stream->state == QLINQ_STREAM_FINISHED ||
      stream->state == QLINQ_STREAM_ABORTED ||
      stream->state == QLINQ_STREAM_CLOSED)
    return true;
  qlinq_event_t event = {.type = QLINQ_EVENT_RECORD,
                         .endpoint = endpoint,
                         .peer_id = peer_id(endpoint, conn),
                         .record = {.group_id = object->group_id,
                                    .sequence = object->object_id,
                                    .data = data,
                                    .size = size,
                                    .keyframe = object->is_keyframe,
                                    .priority = object->priority},
                         .status = QLINQ_STATUS_OK};
  fill_event_stream(&event, track, stream);

  bool framed_track = track->type == MOQ_TRACK_DATA &&
                      (track->flags & (MOQ_TRACK_FLAG_FEC_ENABLED |
                                       MOQ_TRACK_FLAG_FEC_RATELESS)) != 0;
  if (framed_track && size >= QLINQ_RECORD_HEADER_SIZE &&
      memcmp(data, qlinq_record_magic, sizeof(qlinq_record_magic)) == 0 &&
      read_u32(data + 22) == size - QLINQ_RECORD_HEADER_SIZE &&
      data[20] <= 1U) {
    uint32_t encoded_size = read_u32(data + 22);
    event.record.group_id = read_u64(data + 4);
    event.record.sequence = read_u64(data + 12);
    event.record.keyframe = data[20] != 0;
    event.record.priority = data[21];
    event.record.data = data + QLINQ_RECORD_HEADER_SIZE;
    event.record.size = encoded_size;
  }
  bool queued = queue_event(endpoint->context, &event, event.record.data,
                            event.record.size, NULL);
  if (queued)
    endpoint->records_received++;
  if (queued)
    stream->records_received++;
  return queued;
}

static void queue_received_object(qlinq_endpoint_t *endpoint,
                                  const transport_event_t *source) {
  bool grouped_data =
      source->track_id.type == MOQ_TRACK_DATA &&
      (source->track_id.flags &
       (MOQ_TRACK_FLAG_FEC_ENABLED | MOQ_TRACK_FLAG_FEC_RATELESS)) != 0;
  if (!grouped_data) {
    if (!queue_record(endpoint, source->conn, &source->track_id,
                      &source->object, source->object.data,
                      source->object.size))
      queue_error(endpoint, QLINQ_STATUS_RESOURCE_LIMIT,
                  "unable to queue received record");
    return;
  }

  const uint8_t *cursor = source->object.data;
  size_t remaining = source->object.size;
  while (remaining != 0) {
    if (remaining < 2U) {
      queue_error(endpoint, QLINQ_STATUS_INVALID,
                  "malformed grouped record payload");
      return;
    }
    uint16_t size = (uint16_t)(((uint16_t)cursor[0] << 8) | cursor[1]);
    cursor += 2;
    remaining -= 2;
    if (size == 0 || size > remaining) {
      queue_error(endpoint, QLINQ_STATUS_INVALID,
                  "malformed grouped record length");
      return;
    }
    if (!queue_record(endpoint, source->conn, &source->track_id,
                      &source->object, cursor, size)) {
      queue_error(endpoint, QLINQ_STATUS_RESOURCE_LIMIT,
                  "unable to queue recovered record");
      return;
    }
    cursor += size;
    remaining -= size;
  }
}

static void activate_subscriptions(qlinq_endpoint_t *endpoint,
                                   transport_conn_t *connection) {
  for (qlinq_stream_t *stream = endpoint->streams; stream;
       stream = stream->next) {
    if (!stream->active || stream->direction != QLINQ_STREAM_SUBSCRIBE)
      continue;
    if (!transport_subscribe_conn(endpoint->transport, connection,
                                  stream->track))
      queue_error(endpoint, QLINQ_STATUS_STATE,
                  "unable to activate stream subscription");
  }
}

static void mark_peer_ready(qlinq_endpoint_t *endpoint,
                            transport_conn_t *connection) {
  qlinq_peer_state_t *peer = add_peer(endpoint, connection);
  if (!peer || peer->ready)
    return;
  peer->ready = true;
  endpoint->ready_peers++;
  activate_subscriptions(endpoint, connection);
  qlinq_event_t event = {.type = QLINQ_EVENT_PEER_READY,
                         .endpoint = endpoint,
                         .peer_id = peer->id,
                         .status = QLINQ_STATUS_OK};
  (void)queue_event(endpoint->context, &event, NULL, 0, NULL);
}

static void on_transport_event(void *user_data,
                               const transport_event_t *source) {
  qlinq_endpoint_t *endpoint = user_data;
  if (!endpoint || !endpoint->active)
    return;

  switch (source->type) {
  case TRANSPORT_EVENT_CONNECTED:
    (void)add_peer(endpoint, source->conn);
    if (!endpoint->listener &&
        !transport_send_auth(endpoint->transport, source->conn,
                             endpoint->shared_secret,
                             endpoint->shared_secret_size))
      queue_error(endpoint, QLINQ_STATUS_STATE,
                  "unable to authenticate connected peer");
    break;
  case TRANSPORT_EVENT_AUTH: {
    bool accepted =
        endpoint->listener &&
        secret_equal(endpoint, source->auth.token, source->auth.token_len);
    if (!transport_respond_auth(endpoint->transport, source->conn, accepted)) {
      queue_error(endpoint, QLINQ_STATUS_STATE,
                  "unable to send authentication response");
      break;
    }
    if (accepted) {
      mark_peer_ready(endpoint, source->conn);
    } else {
      qlinq_event_t event = {.type = QLINQ_EVENT_PEER_REJECTED,
                             .endpoint = endpoint,
                             .peer_id = peer_id(endpoint, source->conn),
                             .status = QLINQ_STATUS_STATE};
      (void)queue_event(endpoint->context, &event, NULL, 0, NULL);
    }
    break;
  }
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    if (source->auth.success) {
      mark_peer_ready(endpoint, source->conn);
    } else {
      qlinq_event_t event = {.type = QLINQ_EVENT_PEER_REJECTED,
                             .endpoint = endpoint,
                             .peer_id = peer_id(endpoint, source->conn),
                             .status = QLINQ_STATUS_STATE};
      (void)queue_event(endpoint->context, &event, NULL, 0, NULL);
    }
    break;
  case TRANSPORT_EVENT_DISCONNECTED: {
    qlinq_event_t event = {
        .type = QLINQ_EVENT_PEER_DISCONNECTED,
        .endpoint = endpoint,
        .peer_id = peer_id(endpoint, source->conn),
        .disconnect = {.error_code = source->disconnect.error_code,
                       .raw_error = source->disconnect.raw_error,
                       .application_error =
                           source->disconnect.application_error,
                       .offending_frame_type =
                           source->disconnect.offending_frame_type,
                       .remote = source->disconnect.remote},
        .status = QLINQ_STATUS_OK};
    const char *reason =
        source->disconnect.reason && source->disconnect.reason[0] != '\0'
            ? source->disconnect.reason
            : "unspecified";
    (void)queue_event(endpoint->context, &event, NULL, 0, reason);
    remove_peer(endpoint, source->conn);
    break;
  }
  case TRANSPORT_EVENT_SUBSCRIBE:
  case TRANSPORT_EVENT_UNSUBSCRIBE:
  case TRANSPORT_EVENT_KEYFRAME_REQUEST: {
    qlinq_stream_t *stream =
        find_stream(endpoint, &source->track_id, QLINQ_STREAM_PUBLISH);
    qlinq_event_t event = {.type = source->type == TRANSPORT_EVENT_SUBSCRIBE
                                       ? QLINQ_EVENT_SUBSCRIBER_JOINED
                                   : source->type == TRANSPORT_EVENT_UNSUBSCRIBE
                                       ? QLINQ_EVENT_SUBSCRIBER_LEFT
                                       : QLINQ_EVENT_KEYFRAME_REQUESTED,
                           .endpoint = endpoint,
                           .peer_id = peer_id(endpoint, source->conn),
                           .status = QLINQ_STATUS_OK};
    fill_event_stream(&event, &source->track_id, stream);
    (void)queue_event(endpoint->context, &event, NULL, 0, NULL);
    break;
  }
  case TRANSPORT_EVENT_OBJECT:
    queue_received_object(endpoint, source);
    break;
  case TRANSPORT_EVENT_OBJECT_LOST: {
    qlinq_stream_t *stream =
        find_stream(endpoint, &source->track_id, QLINQ_STREAM_SUBSCRIBE);
    qlinq_event_t event = {.type = QLINQ_EVENT_RECORD_LOST,
                           .endpoint = endpoint,
                           .peer_id = peer_id(endpoint, source->conn),
                           .record = {.group_id = source->object.group_id,
                                      .sequence = source->object.object_id},
                           .status = QLINQ_STATUS_OK};
    fill_event_stream(&event, &source->track_id, stream);
    if (stream)
      stream->objects_lost++;
    (void)queue_event(endpoint->context, &event, NULL, 0, NULL);
    break;
  }
  case TRANSPORT_EVENT_TRACK_FINISHED:
  case TRANSPORT_EVENT_TRACK_DRAINED:
  case TRANSPORT_EVENT_TRACK_ABORTED: {
    qlinq_stream_direction_t direction =
        source->type == TRANSPORT_EVENT_TRACK_DRAINED ? QLINQ_STREAM_PUBLISH
                                                      : QLINQ_STREAM_SUBSCRIBE;
    qlinq_stream_t *stream =
        find_stream(endpoint, &source->track_id, direction);
    if (!stream)
      break;
    qlinq_event_type_t type = source->type == TRANSPORT_EVENT_TRACK_FINISHED
                                  ? QLINQ_EVENT_STREAM_FINISHED
                              : source->type == TRANSPORT_EVENT_TRACK_DRAINED
                                  ? QLINQ_EVENT_STREAM_DRAINED
                                  : QLINQ_EVENT_STREAM_ABORTED;
    stream->state = source->type == TRANSPORT_EVENT_TRACK_ABORTED
                        ? QLINQ_STREAM_ABORTED
                        : QLINQ_STREAM_FINISHED;
    stream->last_writable = false;
    stream->writable_known = true;
    qlinq_event_t event = {
        .type = type,
        .endpoint = endpoint,
        .peer_id = peer_id(endpoint, source->conn),
        .completion = {.peers_total = source->completion.peers_total,
                       .peers_completed = source->completion.peers_completed,
                       .peers_failed = source->completion.peers_failed},
        .status = QLINQ_STATUS_OK};
    fill_event_stream(&event, &source->track_id, stream);
    (void)queue_event(endpoint->context, &event, NULL, 0, NULL);
    break;
  }
  }
}

static void map_limits(const qlinq_limits_t *input,
                       transport_limits_t *output) {
  output->max_connections = input->max_connections;
  output->max_subscriptions_per_connection = input->max_subscriptions_per_peer;
  output->max_assemblers_per_connection =
      input->max_active_receive_objects_per_peer;
  output->max_repair_requests_per_second =
      input->max_repair_requests_per_second;
  output->max_aggregate_repair_requests_per_second =
      input->max_aggregate_repair_requests_per_second;
  output->max_egress_packets_per_socket = input->max_egress_packets_per_socket;
  output->max_egress_bytes_per_socket = input->max_egress_bytes_per_socket;
  output->max_assembler_memory_bytes = input->max_receive_memory_bytes;
  output->max_reliable_object_size = input->max_reliable_record_bytes;
  output->max_fec_object_size = input->max_fec_record_bytes;
  output->max_udp_payload_size = input->max_udp_payload_bytes;
  output->max_packets_per_tick = input->max_packets_per_service;
}

static transport_repair_mode_t map_repair_mode(qlinq_repair_mode_t mode) {
  switch (mode) {
  case QLINQ_REPAIR_INDEXED:
    return TRANSPORT_REPAIR_MODE_INDEXED;
  case QLINQ_REPAIR_RATELESS:
    return TRANSPORT_REPAIR_MODE_RATELESS;
  case QLINQ_REPAIR_AUTO:
    return TRANSPORT_REPAIR_MODE_AUTO;
  }
  return TRANSPORT_REPAIR_MODE_AUTO;
}

static qlinq_endpoint_t *open_endpoint(qlinq_context_t *context,
                                       const qlinq_endpoint_config_t *config,
                                       bool listener) {
  if (!context || !config || config->port == 0 ||
      config->bind_address_count == 0 ||
      config->bind_address_count > QLINQ_MAX_PATHS ||
      config->remote_address_count > QLINQ_MAX_PATHS ||
      (listener && config->remote_address_count != 0) ||
      (!listener && config->remote_address_count == 0) ||
      (listener && (!config->security.certificate_file ||
                    !config->security.private_key_file)) ||
      (config->security.shared_secret_size != 0 &&
       !config->security.shared_secret) ||
      config->security.shared_secret_size > UINT16_MAX ||
      (config->repair_mode != QLINQ_REPAIR_AUTO &&
       config->repair_mode != QLINQ_REPAIR_INDEXED &&
       config->repair_mode != QLINQ_REPAIR_RATELESS) ||
      (config->group_delivery.congestion_control !=
           QLINQ_GROUP_CC_CONSERVATIVE &&
       config->group_delivery.congestion_control != QLINQ_GROUP_CC_ADAPTIVE)) {
    set_status(context, QLINQ_STATUS_INVALID);
    return NULL;
  }
  for (size_t i = 0; i < config->bind_address_count; i++) {
    if (!config->bind_addresses[i]) {
      set_status(context, QLINQ_STATUS_INVALID);
      return NULL;
    }
  }
  for (size_t i = 0; i < config->remote_address_count; i++) {
    if (!config->remote_addresses[i]) {
      set_status(context, QLINQ_STATUS_INVALID);
      return NULL;
    }
  }

  qlinq_endpoint_t *endpoint = calloc(1, sizeof(*endpoint));
  if (!endpoint) {
    set_status(context, QLINQ_STATUS_NO_MEMORY);
    return NULL;
  }
  endpoint->context = context;
  endpoint->listener = listener;
  endpoint->active = true;
  if (config->security.shared_secret_size != 0) {
    endpoint->shared_secret = malloc(config->security.shared_secret_size);
    if (!endpoint->shared_secret) {
      free(endpoint);
      set_status(context, QLINQ_STATUS_NO_MEMORY);
      return NULL;
    }
    memcpy(endpoint->shared_secret, config->security.shared_secret,
           config->security.shared_secret_size);
    endpoint->shared_secret_size = config->security.shared_secret_size;
  }

  transport_config_t transport_config = {0};
  for (size_t i = 0; i < config->bind_address_count; i++)
    transport_config.bind_hosts[transport_config.num_bind_hosts++] =
        config->bind_addresses[i];
  for (size_t i = 0; i < config->remote_address_count; i++)
    transport_config.remote_hosts[transport_config.num_remote_hosts++] =
        config->remote_addresses[i];
  transport_config.port = config->port;
  transport_config.quic_idle_timeout_ms = config->idle_timeout_ms;
  transport_config.reconnect_enabled = config->reconnect_enabled;
  transport_config.reconnect_initial_delay_ms =
      config->reconnect_initial_delay_ms;
  transport_config.reconnect_max_delay_ms = config->reconnect_max_delay_ms;
  transport_config.cert_file = config->security.certificate_file;
  transport_config.key_file = config->security.private_key_file;
  transport_config.ca_file = config->security.trust_store_file;
  transport_config.allow_insecure_peer = config->security.allow_insecure_peer;
  transport_config.verify_peer =
      config->security.verify_peer || !config->security.allow_insecure_peer;
  transport_config.enable_flexicast = config->group_delivery.enabled;
  transport_config.flexicast_group = config->group_delivery.group_address;
  transport_config.flexicast_group_port = config->group_delivery.port;
  transport_config.flexicast_interface =
      config->group_delivery.interface_address;
  transport_config.flexicast_cc_mode =
      config->group_delivery.congestion_control == QLINQ_GROUP_CC_ADAPTIVE
          ? TRANSPORT_FLEXICAST_CC_ADAPTIVE
          : TRANSPORT_FLEXICAST_CC_MULTICAST;
  transport_config.flexicast_cc_startup_rate =
      config->group_delivery.startup_rate_bytes_per_second;
  transport_config.flexicast_cc_minimum_rate =
      config->group_delivery.minimum_rate_bytes_per_second;
  transport_config.flexicast_cc_maximum_rate =
      config->group_delivery.maximum_rate_bytes_per_second;
  transport_config.flexicast_cc_aggregate_rate_limit =
      config->group_delivery.aggregate_rate_bytes_per_second;
  transport_config.flexicast_cc_feedback_timeout_ms =
      config->group_delivery.feedback_timeout_ms;
  transport_config.repair_mode = map_repair_mode(config->repair_mode);
  transport_config.repair_feedback_seed = config->repair_feedback_seed;
  map_limits(&config->limits, &transport_config.limits);
  transport_config.callback = on_transport_event;
  transport_config.user_data = endpoint;
  transport_config.log_callback = on_transport_log;
  transport_config.log_user_data = endpoint;

  endpoint->transport = transport_create(&transport_config);
  if (!endpoint->transport) {
    if (endpoint->shared_secret)
      OPENSSL_cleanse(endpoint->shared_secret, endpoint->shared_secret_size);
    free(endpoint->shared_secret);
    free(endpoint);
    set_status(context, QLINQ_STATUS_IO);
    return NULL;
  }
  endpoint->next = context->endpoints;
  context->endpoints = endpoint;
  set_status(context, QLINQ_STATUS_OK);
  return endpoint;
}

qlinq_context_t *qlinq_context_create(const qlinq_context_config_t *config) {
  qlinq_context_t *context = calloc(1, sizeof(*context));
  if (!context)
    return NULL;
  context->max_queued_events = config && config->max_queued_events != 0
                                   ? config->max_queued_events
                                   : QLINQ_DEFAULT_EVENT_COUNT;
  context->max_queued_event_bytes =
      config && config->max_queued_event_bytes != 0
          ? config->max_queued_event_bytes
          : QLINQ_DEFAULT_EVENT_BYTES;
  context->log_callback = config ? config->log_callback : NULL;
  context->log_user_data = config ? config->log_user_data : NULL;
  if (context->max_queued_events == 0 ||
      context->max_queued_event_bytes < sizeof(qlinq_event_node_t) ||
      portable_socket_init() != 0) {
    free(context);
    return NULL;
  }
  context->last_status = QLINQ_STATUS_OK;
  return context;
}

static void free_endpoint(qlinq_endpoint_t *endpoint) {
  if (endpoint->transport)
    transport_destroy(endpoint->transport);
  while (endpoint->streams) {
    qlinq_stream_t *stream = endpoint->streams;
    endpoint->streams = stream->next;
    free(stream);
  }
  while (endpoint->peers) {
    qlinq_peer_state_t *peer = endpoint->peers;
    endpoint->peers = peer->next;
    free(peer);
  }
  if (endpoint->shared_secret) {
    OPENSSL_cleanse(endpoint->shared_secret, endpoint->shared_secret_size);
    free(endpoint->shared_secret);
  }
  free(endpoint);
}

void qlinq_context_destroy(qlinq_context_t *context) {
  if (!context)
    return;
  while (context->endpoints) {
    qlinq_endpoint_t *endpoint = context->endpoints;
    context->endpoints = endpoint->next;
    free_endpoint(endpoint);
  }
  while (context->event_head) {
    qlinq_event_node_t *event = context->event_head;
    context->event_head = event->next;
    free(event);
  }
  portable_socket_cleanup();
  free(context);
}

qlinq_endpoint_t *qlinq_listen(qlinq_context_t *context,
                               const qlinq_endpoint_config_t *config) {
  return open_endpoint(context, config, true);
}

qlinq_endpoint_t *qlinq_connect(qlinq_context_t *context,
                                const qlinq_endpoint_config_t *config) {
  return open_endpoint(context, config, false);
}

qlinq_status_t qlinq_endpoint_shutdown(qlinq_endpoint_t *endpoint,
                                       const char *reason) {
  if (!endpoint || !endpoint->active || !endpoint->transport)
    return QLINQ_STATUS_STATE;
  transport_shutdown(endpoint->transport, reason);
  set_status(endpoint->context, QLINQ_STATUS_OK);
  return QLINQ_STATUS_OK;
}

bool qlinq_endpoint_is_drained(qlinq_endpoint_t *endpoint) {
  return endpoint && endpoint->active && endpoint->transport &&
         transport_is_drained(endpoint->transport);
}

qlinq_status_t qlinq_endpoint_reload_credentials(qlinq_endpoint_t *endpoint,
                                                 const char *certificate_file,
                                                 const char *private_key_file) {
  if (!endpoint || !endpoint->active || !endpoint->transport ||
      !certificate_file || !private_key_file) {
    if (endpoint)
      set_status(endpoint->context, QLINQ_STATUS_INVALID);
    return QLINQ_STATUS_INVALID;
  }
  if (!transport_reload_credentials(endpoint->transport, certificate_file,
                                    private_key_file)) {
    set_status(endpoint->context, QLINQ_STATUS_IO);
    return QLINQ_STATUS_IO;
  }
  set_status(endpoint->context, QLINQ_STATUS_OK);
  return QLINQ_STATUS_OK;
}

void qlinq_endpoint_close(qlinq_endpoint_t *endpoint) {
  if (!endpoint || !endpoint->active)
    return;
  endpoint->active = false;
  for (qlinq_stream_t *stream = endpoint->streams; stream;
       stream = stream->next) {
    stream->state = QLINQ_STREAM_CLOSED;
    stream->active = false;
  }
  if (endpoint->transport) {
    transport_destroy(endpoint->transport);
    endpoint->transport = NULL;
  }
  while (endpoint->peers) {
    qlinq_peer_state_t *peer = endpoint->peers;
    endpoint->peers = peer->next;
    free(peer);
  }
  endpoint->ready_peers = 0;
}

static qlinq_stream_t *open_stream(qlinq_endpoint_t *endpoint,
                                   const qlinq_stream_config_t *config,
                                   qlinq_stream_direction_t direction) {
  if (!endpoint || !endpoint->active || !endpoint->transport || !config ||
      !config->name || config->name[0] == '\0' ||
      strlen(config->name) >= QLINQ_STREAM_NAME_CAPACITY ||
      !content_type_valid(config->content_type) ||
      !delivery_valid(config->delivery)) {
    if (endpoint)
      set_status(endpoint->context, QLINQ_STATUS_INVALID);
    return NULL;
  }

  moq_track_id_t track = {.type = (moq_track_type_t)config->content_type,
                          .flags = delivery_flags(config->delivery)};
  memcpy(track.name, config->name, strlen(config->name) + 1U);
  if (find_stream(endpoint, &track, direction)) {
    set_status(endpoint->context, QLINQ_STATUS_STATE);
    return NULL;
  }

  qlinq_stream_t *stream = calloc(1, sizeof(*stream));
  if (!stream) {
    set_status(endpoint->context, QLINQ_STATUS_NO_MEMORY);
    return NULL;
  }
  stream->endpoint = endpoint;
  stream->track = track;
  stream->content_type = config->content_type;
  stream->delivery = config->delivery;
  stream->direction = direction;
  stream->state = QLINQ_STREAM_OPEN;
  stream->active = true;
  stream->next = endpoint->streams;
  endpoint->streams = stream;

  bool activation_failed = false;
  if (direction == QLINQ_STREAM_SUBSCRIBE) {
    for (qlinq_peer_state_t *peer = endpoint->peers; peer; peer = peer->next) {
      if (peer->ready &&
          !transport_subscribe_conn(endpoint->transport, peer->connection,
                                    stream->track)) {
        activation_failed = true;
        queue_error(endpoint, QLINQ_STATUS_STATE,
                    "unable to activate stream subscription");
      }
    }
  }
  if (!activation_failed)
    set_status(endpoint->context, QLINQ_STATUS_OK);
  return stream;
}

qlinq_stream_t *qlinq_publish(qlinq_endpoint_t *endpoint,
                              const qlinq_stream_config_t *config) {
  return open_stream(endpoint, config, QLINQ_STREAM_PUBLISH);
}

qlinq_stream_t *qlinq_subscribe(qlinq_endpoint_t *endpoint,
                                const qlinq_stream_config_t *config) {
  return open_stream(endpoint, config, QLINQ_STREAM_SUBSCRIBE);
}

void qlinq_stream_close(qlinq_stream_t *stream) {
  if (!stream || !stream->active)
    return;
  if (stream->direction == QLINQ_STREAM_SUBSCRIBE &&
      stream->endpoint->transport)
    (void)transport_unsubscribe(stream->endpoint->transport, stream->track);
  stream->state = QLINQ_STREAM_CLOSED;
  stream->active = false;
}

bool qlinq_stream_is_writable(qlinq_stream_t *stream) {
  return stream && stream->active && stream->state == QLINQ_STREAM_OPEN &&
         stream->direction == QLINQ_STREAM_PUBLISH &&
         stream->endpoint->transport &&
         transport_is_track_ready(stream->endpoint->transport, &stream->track);
}

static qlinq_send_result_t map_send_result(transport_publish_result_t result) {
  switch (result) {
  case TRANSPORT_PUBLISH_DELIVERED:
    return QLINQ_SEND_SENT;
  case TRANSPORT_PUBLISH_BUFFERED:
    return QLINQ_SEND_BUFFERED;
  case TRANSPORT_PUBLISH_NO_RECIPIENTS:
    return QLINQ_SEND_NO_SUBSCRIBERS;
  case TRANSPORT_PUBLISH_PARTIAL:
    return QLINQ_SEND_PARTIAL;
  case TRANSPORT_PUBLISH_BACKPRESSURE:
    return QLINQ_SEND_WOULD_BLOCK;
  case TRANSPORT_PUBLISH_INVALID:
    return QLINQ_SEND_INVALID;
  case TRANSPORT_PUBLISH_ERROR:
    return QLINQ_SEND_FAILED;
  }
  return QLINQ_SEND_FAILED;
}

qlinq_send_result_t qlinq_stream_send(qlinq_stream_t *stream,
                                      const qlinq_record_t *record) {
  if (!stream || !record || !stream->active ||
      stream->state != QLINQ_STREAM_OPEN ||
      stream->direction != QLINQ_STREAM_PUBLISH ||
      !stream->endpoint->transport || (record->size != 0 && !record->data))
    return QLINQ_SEND_INVALID;

  moq_object_t object = {.track_id = stream->track,
                         .group_id = record->group_id,
                         .object_id = record->sequence,
                         .data = record->data,
                         .size = record->size,
                         .is_keyframe = record->keyframe,
                         .priority = record->priority};
  uint8_t *encoded = NULL;
  bool frame_record = stream->content_type == QLINQ_CONTENT_DATA &&
                      (stream->delivery == QLINQ_DELIVERY_FIXED_FEC ||
                       stream->delivery == QLINQ_DELIVERY_RATELESS);
  if (frame_record) {
    if (record->size > UINT16_MAX - QLINQ_RECORD_HEADER_SIZE ||
        record->size > UINT32_MAX)
      return QLINQ_SEND_INVALID;
    size_t encoded_size = QLINQ_RECORD_HEADER_SIZE + record->size;
    encoded = malloc(encoded_size);
    if (!encoded)
      return QLINQ_SEND_FAILED;
    memcpy(encoded, qlinq_record_magic, sizeof(qlinq_record_magic));
    write_u64(encoded + 4, record->group_id);
    write_u64(encoded + 12, record->sequence);
    encoded[20] = record->keyframe ? 1U : 0U;
    encoded[21] = record->priority;
    write_u32(encoded + 22, (uint32_t)record->size);
    if (record->size != 0)
      memcpy(encoded + QLINQ_RECORD_HEADER_SIZE, record->data, record->size);
    object.data = encoded;
    object.size = encoded_size;
  }

  transport_publish_result_t result =
      transport_publish_ex(stream->endpoint->transport, &object);
  free(encoded);
  qlinq_send_result_t mapped = map_send_result(result);
  if (mapped == QLINQ_SEND_SENT || mapped == QLINQ_SEND_BUFFERED ||
      mapped == QLINQ_SEND_PARTIAL)
    stream->records_sent++;
  if (mapped == QLINQ_SEND_WOULD_BLOCK) {
    stream->writable_known = true;
    stream->last_writable = false;
  }
  return mapped;
}

qlinq_status_t qlinq_stream_finish(qlinq_stream_t *stream) {
  if (!stream || !stream->active || stream->state != QLINQ_STREAM_OPEN ||
      stream->direction != QLINQ_STREAM_PUBLISH ||
      stream->content_type != QLINQ_CONTENT_DATA ||
      (stream->delivery != QLINQ_DELIVERY_FIXED_FEC &&
       stream->delivery != QLINQ_DELIVERY_RATELESS) ||
      !stream->endpoint->transport) {
    if (stream)
      set_status(stream->endpoint->context, QLINQ_STATUS_STATE);
    return QLINQ_STATUS_STATE;
  }
  if (!transport_finish_track(stream->endpoint->transport, stream->track)) {
    set_status(stream->endpoint->context, QLINQ_STATUS_STATE);
    return QLINQ_STATUS_STATE;
  }
  stream->state = QLINQ_STREAM_FINISHING;
  stream->writable_known = true;
  stream->last_writable = false;
  set_status(stream->endpoint->context, QLINQ_STATUS_OK);
  return QLINQ_STATUS_OK;
}

qlinq_status_t qlinq_stream_abort(qlinq_stream_t *stream) {
  if (!stream || !stream->active ||
      (stream->state != QLINQ_STREAM_OPEN &&
       stream->state != QLINQ_STREAM_FINISHING) ||
      stream->direction != QLINQ_STREAM_PUBLISH ||
      !stream->endpoint->transport) {
    if (stream)
      set_status(stream->endpoint->context, QLINQ_STATUS_STATE);
    return QLINQ_STATUS_STATE;
  }
  if (!transport_abort_track(stream->endpoint->transport, stream->track)) {
    set_status(stream->endpoint->context, QLINQ_STATUS_STATE);
    return QLINQ_STATUS_STATE;
  }
  stream->state = QLINQ_STREAM_ABORTED;
  stream->writable_known = true;
  stream->last_writable = false;
  qlinq_event_t event = {.type = QLINQ_EVENT_STREAM_ABORTED,
                         .endpoint = stream->endpoint,
                         .stream = stream,
                         .content_type = stream->content_type,
                         .delivery = stream->delivery,
                         .status = QLINQ_STATUS_OK};
  memcpy(event.stream_name, stream->track.name, sizeof(event.stream_name));
  event.stream_name[sizeof(event.stream_name) - 1U] = '\0';
  (void)queue_event(stream->endpoint->context, &event, NULL, 0, NULL);
  set_status(stream->endpoint->context, QLINQ_STATUS_OK);
  return QLINQ_STATUS_OK;
}

static void refresh_writable_events(qlinq_context_t *context) {
  for (qlinq_endpoint_t *endpoint = context->endpoints; endpoint;
       endpoint = endpoint->next) {
    if (!endpoint->active || !endpoint->transport)
      continue;
    for (qlinq_stream_t *stream = endpoint->streams; stream;
         stream = stream->next) {
      if (!stream->active || stream->direction != QLINQ_STREAM_PUBLISH ||
          stream->state != QLINQ_STREAM_OPEN)
        continue;
      bool writable =
          transport_is_track_ready(endpoint->transport, &stream->track);
      bool became_writable =
          writable && (!stream->writable_known || !stream->last_writable);
      stream->writable_known = true;
      stream->last_writable = writable;
      if (!became_writable)
        continue;
      qlinq_event_t event = {.type = QLINQ_EVENT_STREAM_WRITABLE,
                             .endpoint = endpoint,
                             .stream = stream,
                             .content_type = stream->content_type,
                             .delivery = stream->delivery,
                             .status = QLINQ_STATUS_OK};
      memcpy(event.stream_name, stream->track.name, sizeof(event.stream_name));
      event.stream_name[sizeof(event.stream_name) - 1U] = '\0';
      (void)queue_event(context, &event, NULL, 0, NULL);
    }
  }
}

qlinq_status_t qlinq_service(qlinq_context_t *context, int timeout_ms) {
  if (!context || timeout_ms < -1)
    return QLINQ_STATUS_INVALID;
  if (context->event_head)
    return context->last_status < 0 ? context->last_status : QLINQ_STATUS_OK;
  set_status(context, QLINQ_STATUS_OK);

  size_t endpoint_count = 0;
  for (qlinq_endpoint_t *endpoint = context->endpoints; endpoint;
       endpoint = endpoint->next) {
    if (endpoint->active && endpoint->transport) {
      transport_tick(endpoint->transport);
      endpoint_count++;
    }
  }
  refresh_writable_events(context);
  if (context->event_head)
    return context->last_status < 0 ? context->last_status : QLINQ_STATUS_OK;
  if (endpoint_count == 0) {
    set_status(context, QLINQ_STATUS_STATE);
    return QLINQ_STATUS_STATE;
  }

  if (endpoint_count > SIZE_MAX / (TRANSPORT_MAX_PATHS + 2U) ||
      endpoint_count * (TRANSPORT_MAX_PATHS + 2U) >
          SIZE_MAX / sizeof(struct pollfd)) {
    set_status(context, QLINQ_STATUS_RESOURCE_LIMIT);
    return QLINQ_STATUS_RESOURCE_LIMIT;
  }
  size_t capacity = endpoint_count * (TRANSPORT_MAX_PATHS + 2U);
  struct pollfd *fds = calloc(capacity, sizeof(*fds));
  if (!fds) {
    set_status(context, QLINQ_STATUS_NO_MEMORY);
    return QLINQ_STATUS_NO_MEMORY;
  }
  size_t count = 0;
  int wait_ms = timeout_ms;
  int64_t now = transport_get_time_ms();
  for (qlinq_endpoint_t *endpoint = context->endpoints; endpoint;
       endpoint = endpoint->next) {
    if (!endpoint->active || !endpoint->transport)
      continue;
    count += transport_get_poll_fds(endpoint->transport, fds + count,
                                    capacity - count);
    int64_t deadline = transport_get_first_timeout(endpoint->transport);
    if (deadline >= 0) {
      int64_t remaining = deadline <= now ? 0 : deadline - now;
      int timer_wait = remaining > INT_MAX ? INT_MAX : (int)remaining;
      if (wait_ms < 0 || timer_wait < wait_ms)
        wait_ms = timer_wait;
    }
  }

  int result = poll(fds, count, wait_ms);
  free(fds);
  if (result < 0 && SOCKET_ERROR_CODE != SOCKET_EINTR) {
    set_status(context, QLINQ_STATUS_IO);
    return QLINQ_STATUS_IO;
  }
  if (result < 0) {
    set_status(context, QLINQ_STATUS_AGAIN);
    return QLINQ_STATUS_AGAIN;
  }
  for (qlinq_endpoint_t *endpoint = context->endpoints; endpoint;
       endpoint = endpoint->next)
    if (endpoint->active && endpoint->transport)
      transport_tick(endpoint->transport);
  refresh_writable_events(context);
  if (context->last_status < 0)
    return context->last_status;
  set_status(context, QLINQ_STATUS_OK);
  return QLINQ_STATUS_OK;
}

bool qlinq_next_event(qlinq_context_t *context, qlinq_event_t *event) {
  if (!context || !event || !context->event_head)
    return false;
  qlinq_event_node_t *node = context->event_head;
  context->event_head = node->next;
  if (!context->event_head)
    context->event_tail = NULL;
  context->queued_events--;
  context->queued_event_bytes -= node->allocation_size;
  node->next = NULL;
  *event = node->event;
  return true;
}

void qlinq_event_release(qlinq_event_t *event) {
  if (!event)
    return;
  free(event->_private);
  memset(event, 0, sizeof(*event));
}

qlinq_status_t qlinq_context_last_status(const qlinq_context_t *context) {
  return context ? context->last_status : QLINQ_STATUS_INVALID;
}

bool qlinq_endpoint_get_stats(qlinq_endpoint_t *endpoint,
                              qlinq_endpoint_stats_t *stats) {
  if (!endpoint || !endpoint->active || !endpoint->transport || !stats)
    return false;
  transport_stats_t transport_stats;
  if (!transport_get_stats(endpoint->transport, &transport_stats))
    return false;
  *stats = (qlinq_endpoint_stats_t){
      .connections_accepted = transport_stats.connections_accepted,
      .connections_rejected = transport_stats.connections_rejected,
      .connections_closed = transport_stats.connections_closed,
      .reconnect_attempts = transport_stats.reconnect_attempts,
      .reconnect_succeeded = transport_stats.reconnect_succeeded,
      .reconnect_failed = transport_stats.reconnect_failed,
      .protocol_errors = transport_stats.protocol_errors,
      .internal_state_recoveries = transport_stats.internal_state_recoveries,
      .records_received = endpoint->records_received,
      .fec_objects_recovered = transport_stats.fec_objects_recovered,
      .fec_objects_lost = transport_stats.fec_objects_lost,
      .repair_requests_sent = transport_stats.repair_requests_sent,
      .repair_requests_received = transport_stats.repair_requests_received,
      .repair_symbols_sent = transport_stats.repair_symbols_sent,
      .repair_commit_failures = transport_stats.repair_commit_failures,
      .group_packets_sent = transport_stats.flexicast_packets_sent,
      .group_packets_received = transport_stats.flexicast_packets_received,
      .group_native_packets_sent =
          transport_stats.flexicast_native_packets_sent,
      .group_fallbacks = transport_stats.flexicast_fallbacks,
      .group_feedback_fallbacks = transport_stats.flexicast_feedback_fallbacks,
      .group_control_frames_throttled =
          transport_stats.flexicast_control_frames_throttled,
      .group_rekeys = transport_stats.flexicast_rekeys,
      .group_interface_fallbacks =
          transport_stats.flexicast_interface_fallbacks,
      .group_interface_rejoins = transport_stats.flexicast_interface_rejoins,
      .group_rate_bytes_per_second =
          transport_stats.flexicast_cc_rate_bytes_per_second,
      .group_physical_bytes_sent =
          transport_stats.flexicast_physical_bytes_sent,
      .repair_physical_bytes_sent = transport_stats.repair_physical_bytes_sent,
      .repair_oldest_age_ms = transport_stats.repair_oldest_age_ms,
      .active_connections = transport_stats.active_connections,
      .active_group_flows = transport_stats.flexicast_active_flows,
      .active_group_memberships = transport_stats.flexicast_active_memberships,
      .active_group_members = transport_stats.flexicast_active_members,
      .repair_queued_packets = transport_stats.repair_queued_packets,
      .repair_queued_bytes = transport_stats.repair_queued_bytes,
      .queued_packets = transport_stats.flexicast_queued_packets +
                        transport_stats.repair_queued_packets +
                        transport_stats.egress_current_packets,
      .queued_bytes = transport_stats.flexicast_queued_bytes +
                      transport_stats.repair_queued_bytes +
                      transport_stats.egress_current_bytes};
  return true;
}

bool qlinq_stream_get_stats(qlinq_stream_t *stream,
                            qlinq_stream_stats_t *stats) {
  if (!stream || !stats)
    return false;
  memset(stats, 0, sizeof(*stats));
  stats->state = stream->state;
  stats->records_sent = stream->records_sent;
  stats->records_received = stream->records_received;
  stats->objects_lost = stream->objects_lost;
  stats->writable = qlinq_stream_is_writable(stream);
  if (!stream->active || !stream->endpoint->active ||
      !stream->endpoint->transport)
    return true;
  transport_track_stats_t transport_stats;
  if (!transport_get_track_stats(stream->endpoint->transport, &stream->track,
                                 &transport_stats))
    return false;
  stats->subscribers = transport_stats.subscribers;
  stats->group_members = transport_stats.group_members;
  stats->confirmations_pending = transport_stats.confirmations_pending;
  stats->confirmations_completed = transport_stats.confirmations_completed;
  stats->confirmations_failed = transport_stats.confirmations_failed;
  return true;
}
