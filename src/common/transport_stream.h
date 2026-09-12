#ifndef QLINQ_TRANSPORT_STREAM_H
#define QLINQ_TRANSPORT_STREAM_H

#include "transport.h"
#include "transport_wire.h"

#include "quicly.h"
#include "quicly/streambuf.h"

#define TRANSPORT_WIRE_MAX_STREAM_PAYLOAD                                      \
  (TRANSPORT_MAX_RELIABLE_OBJECT_SIZE + QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE)

/* Allocation budgets, including retained frame headers and vector capacity.
 * Application data and retryable repair requests leave room for authentication
 * and checkpoints. */
#define TRANSPORT_STREAM_MAX_FRAMES 256U
#define TRANSPORT_STREAM_MAX_BYTES TRANSPORT_DEFAULT_STREAM_EGRESS_BYTES
#define TRANSPORT_STREAM_ENDPOINT_MAX_BYTES                                    \
  TRANSPORT_DEFAULT_TOTAL_STREAM_EGRESS_BYTES
#define TRANSPORT_STREAM_ENDPOINT_MAX_VECTORS 8192U
#define TRANSPORT_STREAM_CONTROL_BYTE_RESERVE (64U * 1024U)
#define TRANSPORT_STREAM_CONTROL_FRAME_RESERVE 16U
#define TRANSPORT_STREAM_ENDPOINT_CONTROL_BYTE_RESERVE (2U * 1024U * 1024U)
#define TRANSPORT_STREAM_ENDPOINT_CONTROL_VECTOR_RESERVE 256U

typedef struct {
  quicly_streambuf_t streambuf;
  transport_t *owner;
  size_t retained_frame_bytes;
  bool is_control;
  bool alias_bound;
  uint8_t alias;
} transport_stream_ctx_t;

/* frame_len includes the qlinq frame header. Application data and retryable
 * requests preserve the essential-control reserve. This is advisory; writers
 * enforce bounds atomically on the transport owner thread. */
bool transport_stream_can_accept(quicly_stream_t *stream, size_t frame_len,
                                 bool preserve_control_reserve);
/* Preflight one frame per distinct stream, accumulating endpoint budget for
 * an owner-thread broadcast. Does not reserve or allocate actual storage. */
bool transport_stream_can_accept_batch(quicly_stream_t *stream,
                                       size_t frame_len, size_t *bytes,
                                       size_t *vectors);
/* Match exact frames still owned by the reliable stream. QUIC handles their
 * retransmission; application retries can enqueue again after ACK release. */
bool transport_stream_has_retained_frame(quicly_stream_t *stream, uint8_t type,
                                         const void *payload,
                                         size_t payload_len);
void transport_stream_egress_shift(quicly_stream_t *stream, size_t delta);
void transport_stream_destroy(quicly_stream_t *stream, quicly_error_t err);

bool transport_stream_write_parts(quicly_stream_t *stream, uint8_t type,
                                  const void *prefix, size_t prefix_len,
                                  const void *payload, size_t payload_len);
bool transport_stream_write_frame(quicly_stream_t *stream, uint8_t type,
                                  const void *payload, size_t payload_len);
bool transport_stream_write_track_frame(quicly_stream_t *stream, uint8_t type,
                                        uint8_t alias,
                                        const moq_track_id_t *track_id);
bool transport_stream_write_object_frame(quicly_stream_t *stream, uint8_t alias,
                                         const moq_object_t *object);
bool transport_stream_write_track_end_frame(quicly_stream_t *stream,
                                            uint8_t alias, uint64_t group_id,
                                            uint64_t final_object_id);
bool transport_stream_write_track_checkpoint_frame(
    quicly_stream_t *stream, uint8_t alias, uint64_t group_id,
    uint64_t first_object_id, uint64_t final_object_id, bool baseline);
bool transport_stream_write_track_checkpoint_ack_frame(
    quicly_stream_t *stream, uint8_t alias, uint64_t group_id,
    uint64_t final_object_id);

#endif
