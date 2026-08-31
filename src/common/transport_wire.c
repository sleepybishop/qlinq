#include "transport_wire.h"

#include <limits.h>
#include <string.h>

#define QLINQ_WIRE_MAGIC_0 0x51U
#define QLINQ_WIRE_MAGIC_1 0x4cU
static void write_u16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)(value >> 8);
  dst[1] = (uint8_t)value;
}

static void write_u32(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)(value >> 24);
  dst[1] = (uint8_t)(value >> 16);
  dst[2] = (uint8_t)(value >> 8);
  dst[3] = (uint8_t)value;
}

static void write_u64(uint8_t *dst, uint64_t value) {
  for (size_t i = 0; i < 8; i++)
    dst[i] = (uint8_t)(value >> (56U - i * 8U));
}

static uint16_t read_u16(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8) | src[1]);
}

static uint32_t read_u32(const uint8_t *src) {
  return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
         ((uint32_t)src[2] << 8) | src[3];
}

static uint64_t read_u64(const uint8_t *src) {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; i++)
    value = (value << 8) | src[i];
  return value;
}

static qlinq_wire_result_t check_envelope(const uint8_t *src, size_t len,
                                          uint8_t kind) {
  if (!src)
    return QLINQ_WIRE_INVALID;
  if (len < 4)
    return QLINQ_WIRE_NEED_MORE;
  if (src[0] != QLINQ_WIRE_MAGIC_0 || src[1] != QLINQ_WIRE_MAGIC_1 ||
      src[3] != kind)
    return QLINQ_WIRE_INVALID;
  if (src[2] != QLINQ_WIRE_VERSION)
    return QLINQ_WIRE_UNSUPPORTED_VERSION;
  return QLINQ_WIRE_OK;
}

bool qlinq_wire_frame_type_is_known(uint8_t type) {
  return type >= QLINQ_WIRE_SUBSCRIBE &&
         type <= QLINQ_WIRE_TRACK_CHECKPOINT_ACK;
}

qlinq_wire_result_t
qlinq_wire_encode_frame_header(uint8_t *dst, size_t capacity, uint8_t type,
                               size_t payload_len, size_t max_payload_len) {
  if (!dst || !qlinq_wire_frame_type_is_known(type))
    return QLINQ_WIRE_INVALID;
  if (payload_len > max_payload_len || payload_len > UINT32_MAX)
    return QLINQ_WIRE_TOO_LARGE;
  if (capacity < QLINQ_WIRE_FRAME_HEADER_SIZE)
    return QLINQ_WIRE_TOO_LARGE;

  dst[0] = QLINQ_WIRE_MAGIC_0;
  dst[1] = QLINQ_WIRE_MAGIC_1;
  dst[2] = QLINQ_WIRE_VERSION;
  dst[3] = type;
  write_u32(dst + 4, (uint32_t)payload_len);
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t qlinq_wire_encode_frame(uint8_t *dst, size_t capacity,
                                            uint8_t type, const void *payload,
                                            size_t payload_len,
                                            size_t max_payload_len,
                                            size_t *written) {
  if (!written || (payload_len > 0 && !payload))
    return QLINQ_WIRE_INVALID;
  if (payload_len > SIZE_MAX - QLINQ_WIRE_FRAME_HEADER_SIZE ||
      capacity < QLINQ_WIRE_FRAME_HEADER_SIZE + payload_len)
    return QLINQ_WIRE_TOO_LARGE;

  qlinq_wire_result_t result = qlinq_wire_encode_frame_header(
      dst, capacity, type, payload_len, max_payload_len);
  if (result != QLINQ_WIRE_OK)
    return result;
  if (payload_len > 0)
    memcpy(dst + QLINQ_WIRE_FRAME_HEADER_SIZE, payload, payload_len);
  *written = QLINQ_WIRE_FRAME_HEADER_SIZE + payload_len;
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t qlinq_wire_decode_datagram_type(const uint8_t *src,
                                                    size_t len, uint8_t *type) {
  if (!src || !type)
    return QLINQ_WIRE_INVALID;
  if (len < 4)
    return QLINQ_WIRE_NEED_MORE;
  if (src[0] != QLINQ_WIRE_MAGIC_0 || src[1] != QLINQ_WIRE_MAGIC_1)
    return QLINQ_WIRE_INVALID;
  if (src[2] != QLINQ_WIRE_VERSION)
    return QLINQ_WIRE_UNSUPPORTED_VERSION;
  if (src[3] != QLINQ_WIRE_DATAGRAM_FEC &&
      src[3] != QLINQ_WIRE_DATAGRAM_TELEMETRY)
    return QLINQ_WIRE_INVALID;
  *type = src[3];
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t qlinq_wire_decode_frame(const uint8_t *src, size_t len,
                                            size_t max_payload_len,
                                            qlinq_wire_frame_t *frame) {
  if (!src || !frame)
    return QLINQ_WIRE_INVALID;
  if (len < QLINQ_WIRE_FRAME_HEADER_SIZE)
    return QLINQ_WIRE_NEED_MORE;
  if (src[0] != QLINQ_WIRE_MAGIC_0 || src[1] != QLINQ_WIRE_MAGIC_1)
    return QLINQ_WIRE_INVALID;
  if (src[2] != QLINQ_WIRE_VERSION)
    return QLINQ_WIRE_UNSUPPORTED_VERSION;
  if (!qlinq_wire_frame_type_is_known(src[3]))
    return QLINQ_WIRE_INVALID;

  size_t payload_len = read_u32(src + 4);
  if (payload_len > max_payload_len)
    return QLINQ_WIRE_TOO_LARGE;
  if (payload_len > SIZE_MAX - QLINQ_WIRE_FRAME_HEADER_SIZE)
    return QLINQ_WIRE_TOO_LARGE;
  size_t frame_len = QLINQ_WIRE_FRAME_HEADER_SIZE + payload_len;
  if (len < frame_len)
    return QLINQ_WIRE_NEED_MORE;

  frame->type = src[3];
  frame->payload = src + QLINQ_WIRE_FRAME_HEADER_SIZE;
  frame->payload_len = payload_len;
  frame->consumed = frame_len;
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t qlinq_wire_encode_track(uint8_t *dst, size_t capacity,
                                            const qlinq_wire_track_t *track,
                                            size_t *written) {
  if (!dst || !track || !written)
    return QLINQ_WIRE_INVALID;
  size_t name_len = strnlen(track->name, sizeof(track->name));
  if (name_len > QLINQ_WIRE_MAX_TRACK_NAME || capacity < 4U + name_len)
    return QLINQ_WIRE_TOO_LARGE;
  dst[0] = track->alias;
  dst[1] = track->track_type;
  dst[2] = track->flags;
  dst[3] = (uint8_t)name_len;
  if (name_len > 0)
    memcpy(dst + 4, track->name, name_len);
  *written = 4U + name_len;
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t qlinq_wire_decode_track(const uint8_t *src, size_t len,
                                            qlinq_wire_track_t *track) {
  if (!src || !track)
    return QLINQ_WIRE_INVALID;
  if (len < 4)
    return QLINQ_WIRE_INVALID;
  size_t name_len = src[3];
  if (name_len > QLINQ_WIRE_MAX_TRACK_NAME || len != 4U + name_len)
    return QLINQ_WIRE_INVALID;
  memset(track, 0, sizeof(*track));
  track->alias = src[0];
  track->track_type = src[1];
  track->flags = src[2];
  if (name_len > 0)
    memcpy(track->name, src + 4, name_len);
  track->name[name_len] = '\0';
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t
qlinq_wire_encode_nack(uint8_t *dst, size_t capacity, uint8_t alias,
                       uint8_t flags, uint64_t group_id, uint64_t object_id,
                       const uint16_t *missing, uint16_t missing_count,
                       size_t *written) {
  bool whole_object = (flags & QLINQ_WIRE_NACK_WHOLE_OBJECT) != 0;
  bool rateless = (flags & QLINQ_WIRE_NACK_RATELESS) != 0;
  if (!dst || !written ||
      (flags & ~(QLINQ_WIRE_NACK_WHOLE_OBJECT | QLINQ_WIRE_NACK_RATELESS)) !=
          0 ||
      (rateless ? (!whole_object && missing_count == 0) || missing != NULL
                : (whole_object ? missing_count != 0
                                : (missing_count == 0 || !missing))))
    return QLINQ_WIRE_INVALID;
  if (missing_count > QLINQ_WIRE_MAX_NACK_SYMBOLS)
    return QLINQ_WIRE_TOO_LARGE;
  size_t needed = 20U + (rateless ? 0U : (size_t)missing_count * 2U);
  if (capacity < needed)
    return QLINQ_WIRE_TOO_LARGE;
  dst[0] = alias;
  dst[1] = flags;
  write_u64(dst + 2, group_id);
  write_u64(dst + 10, object_id);
  write_u16(dst + 18, missing_count);
  if (!rateless)
    for (size_t i = 0; i < missing_count; i++)
      write_u16(dst + 20 + i * 2, missing[i]);
  *written = needed;
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t qlinq_wire_decode_nack(const uint8_t *src, size_t len,
                                           qlinq_wire_nack_t *nack) {
  if (!src || !nack || len < 20 ||
      (src[1] & ~(QLINQ_WIRE_NACK_WHOLE_OBJECT | QLINQ_WIRE_NACK_RATELESS)) !=
          0)
    return QLINQ_WIRE_INVALID;
  uint16_t count = read_u16(src + 18);
  if (count > QLINQ_WIRE_MAX_NACK_SYMBOLS)
    return QLINQ_WIRE_TOO_LARGE;
  bool whole_object = (src[1] & QLINQ_WIRE_NACK_WHOLE_OBJECT) != 0;
  bool rateless = (src[1] & QLINQ_WIRE_NACK_RATELESS) != 0;
  if (rateless ? (!whole_object && count == 0)
               : (whole_object ? count != 0 : count == 0))
    return QLINQ_WIRE_INVALID;
  if (len != 20U + (rateless ? 0U : (size_t)count * 2U))
    return QLINQ_WIRE_INVALID;
  nack->alias = src[0];
  nack->flags = src[1];
  nack->group_id = read_u64(src + 2);
  nack->object_id = read_u64(src + 10);
  nack->missing_count = count;
  nack->encoded_indices = rateless ? NULL : src + 20;
  return QLINQ_WIRE_OK;
}

bool qlinq_wire_nack_index(const qlinq_wire_nack_t *nack, size_t index,
                           uint16_t *symbol_index) {
  if (!nack || !symbol_index || index >= nack->missing_count ||
      !nack->encoded_indices)
    return false;
  *symbol_index = read_u16(nack->encoded_indices + index * 2U);
  return true;
}

qlinq_wire_result_t
qlinq_wire_encode_track_object(uint8_t *dst, size_t capacity,
                               const qlinq_wire_track_object_t *object) {
  if (!dst || !object)
    return QLINQ_WIRE_INVALID;
  if (capacity < QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE)
    return QLINQ_WIRE_TOO_LARGE;
  dst[0] = object->alias;
  dst[1] = object->is_keyframe ? 1U : 0U;
  dst[2] = object->priority;
  dst[3] = 0;
  write_u64(dst + 4, object->group_id);
  write_u64(dst + 12, object->object_id);
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t
qlinq_wire_decode_track_object(const uint8_t *src, size_t len,
                               qlinq_wire_track_object_t *object,
                               const uint8_t **payload, size_t *payload_len) {
  if (!src || !object || !payload || !payload_len)
    return QLINQ_WIRE_INVALID;
  if (len < QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE)
    return QLINQ_WIRE_INVALID;
  if (src[1] > 1 || src[3] != 0)
    return QLINQ_WIRE_INVALID;
  object->alias = src[0];
  object->is_keyframe = src[1] != 0;
  object->priority = src[2];
  object->group_id = read_u64(src + 4);
  object->object_id = read_u64(src + 12);
  *payload = src + QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE;
  *payload_len = len - QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE;
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t
qlinq_wire_encode_fec_header(uint8_t *dst, size_t capacity,
                             const qlinq_wire_fec_header_t *header) {
  if (!dst || !header)
    return QLINQ_WIRE_INVALID;
  if (capacity < QLINQ_WIRE_FEC_HEADER_SIZE)
    return QLINQ_WIRE_TOO_LARGE;
  dst[0] = QLINQ_WIRE_MAGIC_0;
  dst[1] = QLINQ_WIRE_MAGIC_1;
  dst[2] = QLINQ_WIRE_VERSION;
  dst[3] = QLINQ_WIRE_DATAGRAM_FEC;
  dst[4] = header->alias;
  dst[5] = header->is_keyframe ? 1U : 0U;
  dst[6] = header->priority;
  dst[7] = header->path_id;
  write_u64(dst + 8, header->group_id);
  write_u64(dst + 16, header->object_id);
  write_u16(dst + 24, header->symbol_index);
  write_u16(dst + 26, header->total_symbols);
  write_u16(dst + 28, header->data_symbols);
  write_u16(dst + 30, header->symbol_size);
  write_u32(dst + 32, header->original_size);
  write_u64(dst + 36, header->send_time_ns);
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t
qlinq_wire_decode_fec_header(const uint8_t *src, size_t len,
                             qlinq_wire_fec_header_t *header) {
  if (!header)
    return QLINQ_WIRE_INVALID;
  qlinq_wire_result_t result =
      check_envelope(src, len, QLINQ_WIRE_DATAGRAM_FEC);
  if (result != QLINQ_WIRE_OK)
    return result;
  if (len < QLINQ_WIRE_FEC_HEADER_SIZE)
    return QLINQ_WIRE_NEED_MORE;
  if (src[5] > 1)
    return QLINQ_WIRE_INVALID;
  header->alias = src[4];
  header->is_keyframe = src[5] != 0;
  header->priority = src[6];
  header->path_id = src[7];
  header->group_id = read_u64(src + 8);
  header->object_id = read_u64(src + 16);
  header->symbol_index = read_u16(src + 24);
  header->total_symbols = read_u16(src + 26);
  header->data_symbols = read_u16(src + 28);
  header->symbol_size = read_u16(src + 30);
  header->original_size = read_u32(src + 32);
  header->send_time_ns = read_u64(src + 36);
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t
qlinq_wire_encode_telemetry(uint8_t *dst, size_t capacity,
                            const qlinq_wire_telemetry_t *telemetry) {
  if (!dst || !telemetry)
    return QLINQ_WIRE_INVALID;
  if (capacity < QLINQ_WIRE_TELEMETRY_SIZE)
    return QLINQ_WIRE_TOO_LARGE;
  dst[0] = QLINQ_WIRE_MAGIC_0;
  dst[1] = QLINQ_WIRE_MAGIC_1;
  dst[2] = QLINQ_WIRE_VERSION;
  dst[3] = QLINQ_WIRE_DATAGRAM_TELEMETRY;
  dst[4] = telemetry->path_id;
  dst[5] = 0;
  dst[6] = 0;
  dst[7] = 0;
  write_u64(dst + 8, telemetry->send_time_ns);
  write_u64(dst + 16, telemetry->recv_time_ns);
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t
qlinq_wire_decode_telemetry(const uint8_t *src, size_t len,
                            qlinq_wire_telemetry_t *telemetry) {
  if (!telemetry)
    return QLINQ_WIRE_INVALID;
  qlinq_wire_result_t result =
      check_envelope(src, len, QLINQ_WIRE_DATAGRAM_TELEMETRY);
  if (result != QLINQ_WIRE_OK)
    return result;
  if (len != QLINQ_WIRE_TELEMETRY_SIZE)
    return QLINQ_WIRE_INVALID;
  if (src[5] != 0 || src[6] != 0 || src[7] != 0)
    return QLINQ_WIRE_INVALID;
  telemetry->path_id = src[4];
  telemetry->send_time_ns = read_u64(src + 8);
  telemetry->recv_time_ns = read_u64(src + 16);
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t qlinq_wire_encode_hello(uint8_t *dst, size_t capacity,
                                            const qlinq_wire_hello_t *hello) {
  if (!dst || !hello || capacity < QLINQ_WIRE_HELLO_SIZE ||
      hello->role > QLINQ_WIRE_ROLE_SERVER || hello->max_paths == 0 ||
      hello->max_subscriptions == 0 || hello->max_datagram_size == 0 ||
      hello->max_reliable_object_size == 0 || hello->max_fec_object_size == 0 ||
      (hello->capabilities & ~QLINQ_WIRE_CAP_KNOWN) != 0)
    return QLINQ_WIRE_INVALID;

  dst[0] = hello->role;
  dst[1] = 0;
  write_u16(dst + 2, hello->max_paths);
  write_u32(dst + 4, hello->capabilities);
  write_u32(dst + 8, hello->max_reliable_object_size);
  write_u32(dst + 12, hello->max_fec_object_size);
  write_u16(dst + 16, hello->max_subscriptions);
  write_u16(dst + 18, hello->max_datagram_size);
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t qlinq_wire_decode_hello(const uint8_t *src, size_t len,
                                            qlinq_wire_hello_t *hello) {
  if (!src || !hello || len != QLINQ_WIRE_HELLO_SIZE || src[1] != 0)
    return QLINQ_WIRE_INVALID;
  memset(hello, 0, sizeof(*hello));
  hello->role = src[0];
  hello->max_paths = read_u16(src + 2);
  hello->capabilities = read_u32(src + 4);
  hello->max_reliable_object_size = read_u32(src + 8);
  hello->max_fec_object_size = read_u32(src + 12);
  hello->max_subscriptions = read_u16(src + 16);
  hello->max_datagram_size = read_u16(src + 18);
  if (hello->role > QLINQ_WIRE_ROLE_SERVER || hello->max_paths == 0 ||
      hello->max_subscriptions == 0 || hello->max_datagram_size == 0 ||
      hello->max_reliable_object_size == 0 || hello->max_fec_object_size == 0 ||
      (hello->capabilities & ~QLINQ_WIRE_CAP_KNOWN) != 0)
    return QLINQ_WIRE_INVALID;
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t
qlinq_wire_encode_flexicast_bind(uint8_t *dst, size_t capacity,
                                 const qlinq_wire_flexicast_bind_t *bind) {
  if (!dst || !bind)
    return QLINQ_WIRE_INVALID;
  if (capacity < QLINQ_WIRE_FLEXICAST_BIND_SIZE)
    return QLINQ_WIRE_TOO_LARGE;
  if (bind->flow_id == 0 || bind->key_epoch == 0)
    return QLINQ_WIRE_INVALID;
  dst[0] = bind->alias;
  dst[1] = 0;
  dst[2] = 0;
  dst[3] = 0;
  write_u64(dst + 4, bind->flow_id);
  write_u32(dst + 12, bind->key_epoch);
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t
qlinq_wire_decode_flexicast_bind(const uint8_t *src, size_t len,
                                 qlinq_wire_flexicast_bind_t *bind) {
  if (!src || !bind || len != QLINQ_WIRE_FLEXICAST_BIND_SIZE || src[1] != 0 ||
      src[2] != 0 || src[3] != 0)
    return QLINQ_WIRE_INVALID;
  bind->alias = src[0];
  bind->flow_id = read_u64(src + 4);
  bind->key_epoch = read_u32(src + 12);
  return bind->flow_id != 0 && bind->key_epoch != 0 ? QLINQ_WIRE_OK
                                                    : QLINQ_WIRE_INVALID;
}

qlinq_wire_result_t
qlinq_wire_encode_track_end(uint8_t *dst, size_t capacity,
                            const qlinq_wire_track_end_t *end) {
  if (!dst || !end)
    return QLINQ_WIRE_INVALID;
  if (capacity < QLINQ_WIRE_TRACK_END_SIZE)
    return QLINQ_WIRE_TOO_LARGE;
  dst[0] = end->alias;
  write_u64(dst + 1, end->group_id);
  write_u64(dst + 9, end->final_object_id);
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t qlinq_wire_decode_track_end(const uint8_t *src, size_t len,
                                                qlinq_wire_track_end_t *end) {
  if (!src || !end || len != QLINQ_WIRE_TRACK_END_SIZE)
    return QLINQ_WIRE_INVALID;
  end->alias = src[0];
  end->group_id = read_u64(src + 1);
  end->final_object_id = read_u64(src + 9);
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t qlinq_wire_encode_track_checkpoint(
    uint8_t *dst, size_t capacity,
    const qlinq_wire_track_checkpoint_t *checkpoint) {
  if (!dst || !checkpoint ||
      (checkpoint->flags & ~QLINQ_WIRE_CHECKPOINT_BASELINE) != 0 ||
      checkpoint->first_object_id > checkpoint->final_object_id)
    return QLINQ_WIRE_INVALID;
  if (capacity < QLINQ_WIRE_TRACK_CHECKPOINT_SIZE)
    return QLINQ_WIRE_TOO_LARGE;
  dst[0] = checkpoint->alias;
  dst[1] = checkpoint->flags;
  dst[2] = 0;
  dst[3] = 0;
  write_u64(dst + 4, checkpoint->group_id);
  write_u64(dst + 12, checkpoint->first_object_id);
  write_u64(dst + 20, checkpoint->final_object_id);
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t
qlinq_wire_decode_track_checkpoint(const uint8_t *src, size_t len,
                                   qlinq_wire_track_checkpoint_t *checkpoint) {
  if (!src || !checkpoint || len != QLINQ_WIRE_TRACK_CHECKPOINT_SIZE)
    return QLINQ_WIRE_INVALID;
  checkpoint->alias = src[0];
  checkpoint->flags = src[1];
  checkpoint->group_id = read_u64(src + 4);
  checkpoint->first_object_id = read_u64(src + 12);
  checkpoint->final_object_id = read_u64(src + 20);
  return src[2] == 0 && src[3] == 0 &&
                 (checkpoint->flags & ~QLINQ_WIRE_CHECKPOINT_BASELINE) == 0 &&
                 checkpoint->first_object_id <= checkpoint->final_object_id
             ? QLINQ_WIRE_OK
             : QLINQ_WIRE_INVALID;
}

qlinq_wire_result_t qlinq_wire_encode_track_checkpoint_ack(
    uint8_t *dst, size_t capacity,
    const qlinq_wire_track_checkpoint_ack_t *ack) {
  if (!dst || !ack)
    return QLINQ_WIRE_INVALID;
  if (capacity < QLINQ_WIRE_TRACK_CHECKPOINT_ACK_SIZE)
    return QLINQ_WIRE_TOO_LARGE;
  dst[0] = ack->alias;
  write_u64(dst + 1, ack->group_id);
  write_u64(dst + 9, ack->final_object_id);
  return QLINQ_WIRE_OK;
}

qlinq_wire_result_t
qlinq_wire_decode_track_checkpoint_ack(const uint8_t *src, size_t len,
                                       qlinq_wire_track_checkpoint_ack_t *ack) {
  if (!src || !ack || len != QLINQ_WIRE_TRACK_CHECKPOINT_ACK_SIZE)
    return QLINQ_WIRE_INVALID;
  ack->alias = src[0];
  ack->group_id = read_u64(src + 1);
  ack->final_object_id = read_u64(src + 9);
  return QLINQ_WIRE_OK;
}
