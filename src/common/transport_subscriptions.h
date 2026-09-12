#ifndef QLINQ_TRANSPORT_SUBSCRIPTIONS_H
#define QLINQ_TRANSPORT_SUBSCRIPTIONS_H

#include "transport.h"
#include "transport_recovery_state.h"

#include "quicly.h"

typedef struct {
  moq_track_id_t track_id;
  uint8_t alias;
  bool active;
  quicly_stream_t *stream;         /* egress stream for publishing */
  quicly_stream_t *ingress_stream; /* ingress stream received from peer */
} track_subscription_t;

typedef struct {
  track_subscription_t *entries;
  size_t capacity;
  transport_subscription_state_t *states[UINT8_MAX + 1U];
} transport_subscription_table_t;

static inline transport_subscription_state_t *
transport_subscriptions_get_state(const transport_subscription_table_t *table,
                                  uint8_t alias) {
  return table ? table->states[alias] : NULL;
}

bool transport_subscriptions_init(transport_subscription_table_t *table,
                                  size_t capacity);
void transport_subscriptions_destroy(transport_subscription_table_t *table);
size_t
transport_subscriptions_count(const transport_subscription_table_t *table);

int transport_subscriptions_find_by_alias(
    const transport_subscription_table_t *table, uint8_t alias,
    moq_track_id_t *out_track);
int transport_subscriptions_find_alias(
    const transport_subscription_table_t *table, const moq_track_id_t *track,
    uint8_t *out_alias);
track_subscription_t *
transport_subscriptions_find(transport_subscription_table_t *table,
                             const moq_track_id_t *track);
const track_subscription_t *
transport_subscriptions_find_const(const transport_subscription_table_t *table,
                                   const moq_track_id_t *track);
bool transport_subscriptions_contains(
    const transport_subscription_table_t *table, const moq_track_id_t *track);
bool transport_subscriptions_add(transport_subscription_table_t *table,
                                 moq_track_type_t type, uint8_t flags,
                                 const char *name, uint8_t alias);
void transport_subscriptions_remove(transport_subscription_table_t *table,
                                    moq_track_type_t type, const char *name);
void transport_subscriptions_clear_stream(transport_subscription_table_t *table,
                                          quicly_stream_t *stream);
bool transport_subscriptions_bind_stream(transport_subscription_table_t *table,
                                         uint8_t alias,
                                         quicly_stream_t *stream);
int transport_subscriptions_next_alias(
    const transport_subscription_table_t *table, int first_dynamic_alias);

#endif
