#ifndef QLINQ_TRANSPORT_RECOVERY_STATE_H
#define QLINQ_TRANSPORT_RECOVERY_STATE_H
#include "transport.h"

#define QLINQ_RECOVERY_WINDOW_OBJECTS TRANSPORT_RECOVERY_WINDOW_OBJECTS
#define QLINQ_RECOVERY_MAX_WINDOWS 8U
#define QLINQ_RECOVERY_HISTORY_OBJECTS                                         \
  (QLINQ_RECOVERY_WINDOW_OBJECTS * QLINQ_RECOVERY_MAX_WINDOWS)

typedef struct {
  bool active;
  uint64_t group_id;
  uint64_t first_object_id;
  uint64_t final_object_id;
  uint32_t missing_mask;
  uint8_t cursor;
  int64_t last_request_ms;
} transport_recovery_window_t;

typedef struct {
  uint64_t last_seen;
  bool seen_initialized;
  uint64_t pending_base;
  uint32_t pending_mask;
  uint64_t group_id;
  int64_t detected_at_ms;
  uint64_t largest_delivered;
  uint64_t delivered_mask[QLINQ_RECOVERY_HISTORY_OBJECTS / 64U];
  bool delivered_initialized;
  bool checkpoint_initialized;
  uint64_t last_checkpoint_object_id;
  transport_recovery_window_t recovery_windows[QLINQ_RECOVERY_MAX_WINDOWS];
} transport_object_gap_state_t;

typedef struct {
  bool participating;
  bool sent_initialized;
  uint64_t sent_group_id;
  uint64_t sent_object_id;
  int64_t oldest_unacked_sent_at_ms;
  bool acked_initialized;
  uint64_t acked_group_id;
  uint64_t acked_object_id;
} transport_checkpoint_ack_state_t;

typedef struct {
  uint64_t generation;
  transport_object_gap_state_t object_gap;
  transport_checkpoint_ack_state_t checkpoint_ack;
} transport_subscription_state_t;

#endif
