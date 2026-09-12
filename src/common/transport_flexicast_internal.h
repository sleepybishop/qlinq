#ifndef QLINQ_TRANSPORT_FLEXICAST_INTERNAL_H
#define QLINQ_TRANSPORT_FLEXICAST_INTERNAL_H

#include "transport_internal.h"

/* Internal module boundary. Membership owns flow/member lifetime and epochs.
 * Dispatch owns plaintext queues and resumable protected-packet submission.
 * Repair owns pending intents, requester observations, and repair selection.
 * All run on the transport service thread; membership mutation must never run
 * inside dispatch, which borrows queue and member entries until it returns.
 * No group ciphertext may enter the generic UDP egress queue. */

void tf_advance_delivery_epoch(transport_flexicast_flow_t *flow);
size_t tf_cancel_flow_repairs(transport_t *t, transport_flexicast_flow_t *flow,
                              bool entire_track, uint64_t group_id,
                              uint64_t object_id);
size_t tf_clear_flow_queue(transport_flexicast_flow_t *flow);
void tf_drain_paced_payloads(transport_t *t, transport_flexicast_flow_t *flow);
void tf_emit_ready_shadow_observations(transport_t *t,
                                       transport_flexicast_flow_t *flow,
                                       int64_t now);
void tf_materialize_pending_repairs(transport_t *t,
                                    transport_flexicast_flow_t *flow,
                                    int64_t now);
size_t tf_pending_repair_symbol_count(
    const transport_flexicast_pending_repair_t *pending);
transport_flexicast_queued_payload_t *
tf_queue_at(transport_flexicast_queue_t *queue, size_t index);
const transport_flexicast_queued_payload_t *
tf_queue_at_const(const transport_flexicast_queue_t *queue, size_t index);
size_t tf_queue_clear(transport_flexicast_queue_t *queue);
void tf_queue_dispose(transport_flexicast_queue_t *queue);
bool tf_queue_push(transport_flexicast_queue_t *queue,
                   const transport_flexicast_queued_payload_t *payload);
size_t tf_repair_symbol_count(const uint64_t *symbols);
uint64_t tf_saturating_add_u64(uint64_t left, uint64_t right);

#endif
