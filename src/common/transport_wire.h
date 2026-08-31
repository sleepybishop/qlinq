#ifndef QLINQ_TRANSPORT_WIRE_H
#define QLINQ_TRANSPORT_WIRE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define QLINQ_WIRE_VERSION 1U
#define QLINQ_WIRE_FRAME_HEADER_SIZE 8U
#define QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE 20U
#define QLINQ_WIRE_FEC_HEADER_SIZE 44U
#define QLINQ_WIRE_TELEMETRY_SIZE 24U
#define QLINQ_WIRE_HELLO_SIZE 20U
#define QLINQ_WIRE_FLEXICAST_BIND_SIZE 16U
#define QLINQ_WIRE_TRACK_END_SIZE 17U
#define QLINQ_WIRE_TRACK_CHECKPOINT_SIZE 28U
#define QLINQ_WIRE_TRACK_CHECKPOINT_ACK_SIZE 17U
#define QLINQ_WIRE_MAX_TRACK_NAME 63U
#define QLINQ_WIRE_MAX_NACK_SYMBOLS 1024U
#define QLINQ_WIRE_NACK_WHOLE_OBJECT 0x01U
#define QLINQ_WIRE_NACK_RATELESS 0x02U
#define QLINQ_WIRE_CHECKPOINT_BASELINE 0x01U

typedef enum {
  QLINQ_WIRE_OK = 0,
  QLINQ_WIRE_NEED_MORE,
  QLINQ_WIRE_INVALID,
  QLINQ_WIRE_UNSUPPORTED_VERSION,
  QLINQ_WIRE_TOO_LARGE
} qlinq_wire_result_t;

typedef enum {
  QLINQ_WIRE_SUBSCRIBE = 1,
  QLINQ_WIRE_UNSUBSCRIBE = 2,
  QLINQ_WIRE_UNICAST = 3,
  QLINQ_WIRE_AUTH_REQUEST = 4,
  QLINQ_WIRE_AUTH_RESPONSE = 5,
  QLINQ_WIRE_KEYFRAME_REQUEST = 6,
  QLINQ_WIRE_TRACK_OBJECT = 7,
  QLINQ_WIRE_NACK = 8,
  QLINQ_WIRE_HELLO = 9,
  QLINQ_WIRE_FLEXICAST_BIND = 10,
  QLINQ_WIRE_TRACK_END = 11,
  QLINQ_WIRE_TRACK_CHECKPOINT = 12,
  QLINQ_WIRE_TRACK_CHECKPOINT_ACK = 13
} qlinq_wire_frame_type_t;

#define QLINQ_WIRE_ROLE_CLIENT 0U
#define QLINQ_WIRE_ROLE_SERVER 1U

#define QLINQ_WIRE_CAP_RELIABLE 0x00000001U
#define QLINQ_WIRE_CAP_DATAGRAM 0x00000002U
#define QLINQ_WIRE_CAP_FEC_REED_SOLOMON 0x00000004U
#define QLINQ_WIRE_CAP_FEC_RATELESS 0x00000008U
#define QLINQ_WIRE_CAP_MULTIPATH 0x00000010U
#define QLINQ_WIRE_CAP_AUTHENTICATION 0x00000020U
#define QLINQ_WIRE_CAP_FLEXICAST_DATAGRAM 0x00000040U
#define QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS 0x00000080U
#define QLINQ_WIRE_CAP_RATELESS_REPAIR 0x00000100U
#define QLINQ_WIRE_CAP_KNOWN                                                   \
  (QLINQ_WIRE_CAP_RELIABLE | QLINQ_WIRE_CAP_DATAGRAM |                         \
   QLINQ_WIRE_CAP_FEC_REED_SOLOMON | QLINQ_WIRE_CAP_FEC_RATELESS |             \
   QLINQ_WIRE_CAP_MULTIPATH | QLINQ_WIRE_CAP_AUTHENTICATION |                  \
   QLINQ_WIRE_CAP_FLEXICAST_DATAGRAM | QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS |   \
   QLINQ_WIRE_CAP_RATELESS_REPAIR)

typedef enum {
  QLINQ_WIRE_DATAGRAM_FEC = 1,
  QLINQ_WIRE_DATAGRAM_TELEMETRY = 2
} qlinq_wire_datagram_type_t;

typedef struct {
  uint8_t type;
  const uint8_t *payload;
  size_t payload_len;
  size_t consumed;
} qlinq_wire_frame_t;

typedef struct {
  uint8_t alias;
  uint8_t track_type;
  uint8_t flags;
  char name[QLINQ_WIRE_MAX_TRACK_NAME + 1U];
} qlinq_wire_track_t;

typedef struct {
  uint8_t alias;
  uint8_t flags;
  uint64_t group_id;
  uint64_t object_id;
  uint16_t missing_count;
  /* In rateless mode, missing_count is the requested additional degree-of-
   * freedom count and encoded_indices is NULL. */
  const uint8_t *encoded_indices;
} qlinq_wire_nack_t;

typedef struct {
  uint8_t alias;
  bool is_keyframe;
  uint8_t priority;
  uint64_t group_id;
  uint64_t object_id;
} qlinq_wire_track_object_t;

typedef struct {
  uint8_t alias;
  bool is_keyframe;
  uint8_t priority;
  uint8_t path_id;
  uint64_t group_id;
  uint64_t object_id;
  uint16_t symbol_index;
  uint16_t total_symbols;
  uint16_t data_symbols;
  uint16_t symbol_size;
  uint32_t original_size;
  uint64_t send_time_ns;
} qlinq_wire_fec_header_t;

typedef struct {
  uint8_t path_id;
  uint64_t send_time_ns;
  uint64_t recv_time_ns;
} qlinq_wire_telemetry_t;

typedef struct {
  uint8_t role;
  uint16_t max_paths;
  uint32_t capabilities;
  uint32_t max_reliable_object_size;
  uint32_t max_fec_object_size;
  uint16_t max_subscriptions;
  uint16_t max_datagram_size;
} qlinq_wire_hello_t;

typedef struct {
  uint8_t alias;
  uint64_t flow_id;
  uint32_t key_epoch;
} qlinq_wire_flexicast_bind_t;

typedef struct {
  uint8_t alias;
  uint64_t group_id;
  uint64_t final_object_id;
} qlinq_wire_track_end_t;

typedef struct {
  uint8_t alias;
  uint8_t flags;
  uint64_t group_id;
  uint64_t first_object_id;
  uint64_t final_object_id;
} qlinq_wire_track_checkpoint_t;

typedef struct {
  uint8_t alias;
  uint64_t group_id;
  uint64_t final_object_id;
} qlinq_wire_track_checkpoint_ack_t;

bool qlinq_wire_frame_type_is_known(uint8_t type);

qlinq_wire_result_t
qlinq_wire_encode_frame_header(uint8_t *dst, size_t capacity, uint8_t type,
                               size_t payload_len, size_t max_payload_len);
qlinq_wire_result_t qlinq_wire_encode_frame(uint8_t *dst, size_t capacity,
                                            uint8_t type, const void *payload,
                                            size_t payload_len,
                                            size_t max_payload_len,
                                            size_t *written);
qlinq_wire_result_t qlinq_wire_decode_frame(const uint8_t *src, size_t len,
                                            size_t max_payload_len,
                                            qlinq_wire_frame_t *frame);

qlinq_wire_result_t qlinq_wire_encode_track(uint8_t *dst, size_t capacity,
                                            const qlinq_wire_track_t *track,
                                            size_t *written);
qlinq_wire_result_t qlinq_wire_decode_track(const uint8_t *src, size_t len,
                                            qlinq_wire_track_t *track);

qlinq_wire_result_t
qlinq_wire_encode_nack(uint8_t *dst, size_t capacity, uint8_t alias,
                       uint8_t flags, uint64_t group_id, uint64_t object_id,
                       const uint16_t *missing, uint16_t missing_count,
                       size_t *written);
qlinq_wire_result_t qlinq_wire_decode_nack(const uint8_t *src, size_t len,
                                           qlinq_wire_nack_t *nack);
bool qlinq_wire_nack_index(const qlinq_wire_nack_t *nack, size_t index,
                           uint16_t *symbol_index);

qlinq_wire_result_t
qlinq_wire_encode_track_object(uint8_t *dst, size_t capacity,
                               const qlinq_wire_track_object_t *object);
qlinq_wire_result_t
qlinq_wire_decode_track_object(const uint8_t *src, size_t len,
                               qlinq_wire_track_object_t *object,
                               const uint8_t **payload, size_t *payload_len);

qlinq_wire_result_t
qlinq_wire_encode_fec_header(uint8_t *dst, size_t capacity,
                             const qlinq_wire_fec_header_t *header);
qlinq_wire_result_t
qlinq_wire_decode_fec_header(const uint8_t *src, size_t len,
                             qlinq_wire_fec_header_t *header);

qlinq_wire_result_t qlinq_wire_decode_datagram_type(const uint8_t *src,
                                                    size_t len, uint8_t *type);

qlinq_wire_result_t
qlinq_wire_encode_telemetry(uint8_t *dst, size_t capacity,
                            const qlinq_wire_telemetry_t *telemetry);
qlinq_wire_result_t
qlinq_wire_decode_telemetry(const uint8_t *src, size_t len,
                            qlinq_wire_telemetry_t *telemetry);

qlinq_wire_result_t qlinq_wire_encode_hello(uint8_t *dst, size_t capacity,
                                            const qlinq_wire_hello_t *hello);
qlinq_wire_result_t qlinq_wire_decode_hello(const uint8_t *src, size_t len,
                                            qlinq_wire_hello_t *hello);

qlinq_wire_result_t
qlinq_wire_encode_flexicast_bind(uint8_t *dst, size_t capacity,
                                 const qlinq_wire_flexicast_bind_t *bind);
qlinq_wire_result_t
qlinq_wire_decode_flexicast_bind(const uint8_t *src, size_t len,
                                 qlinq_wire_flexicast_bind_t *bind);
qlinq_wire_result_t
qlinq_wire_encode_track_end(uint8_t *dst, size_t capacity,
                            const qlinq_wire_track_end_t *end);
qlinq_wire_result_t qlinq_wire_decode_track_end(const uint8_t *src, size_t len,
                                                qlinq_wire_track_end_t *end);
qlinq_wire_result_t qlinq_wire_encode_track_checkpoint(
    uint8_t *dst, size_t capacity,
    const qlinq_wire_track_checkpoint_t *checkpoint);
qlinq_wire_result_t
qlinq_wire_decode_track_checkpoint(const uint8_t *src, size_t len,
                                   qlinq_wire_track_checkpoint_t *checkpoint);
qlinq_wire_result_t qlinq_wire_encode_track_checkpoint_ack(
    uint8_t *dst, size_t capacity,
    const qlinq_wire_track_checkpoint_ack_t *ack);
qlinq_wire_result_t
qlinq_wire_decode_track_checkpoint_ack(const uint8_t *src, size_t len,
                                       qlinq_wire_track_checkpoint_ack_t *ack);
#endif
