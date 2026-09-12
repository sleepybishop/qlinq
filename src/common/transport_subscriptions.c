#include "transport_subscriptions.h"

#include "quicly/streambuf.h"

#include <stdlib.h>
#include <string.h>

bool transport_subscriptions_init(transport_subscription_table_t *table,
                                  size_t capacity) {
  if (!table || capacity == 0 || capacity > TRANSPORT_HARD_MAX_SUBSCRIPTIONS)
    return false;
  track_subscription_t *entries = calloc(capacity, sizeof(*entries));
  if (!entries)
    return false;
  transport_subscriptions_destroy(table);
  table->entries = entries;
  table->capacity = capacity;
  return true;
}

void transport_subscriptions_destroy(transport_subscription_table_t *table) {
  if (!table)
    return;
  for (size_t alias = 0; alias <= UINT8_MAX; alias++)
    free(table->states[alias]);
  free(table->entries);
  memset(table, 0, sizeof(*table));
}

size_t
transport_subscriptions_count(const transport_subscription_table_t *table) {
  if (!table)
    return 0;
  size_t count = 0;
  for (size_t i = 0; i < table->capacity; i++)
    count += table->entries[i].active ? 1U : 0U;
  return count;
}

static bool ensure_initialized(transport_subscription_table_t *table) {
  return table &&
         (table->entries || transport_subscriptions_init(
                                table, TRANSPORT_DEFAULT_MAX_SUBSCRIPTIONS));
}

static bool track_matches(const moq_track_id_t *track, moq_track_type_t type,
                          const char *name) {
  return track && name && track->type == type && strcmp(track->name, name) == 0;
}

int transport_subscriptions_find_by_alias(
    const transport_subscription_table_t *table, uint8_t alias,
    moq_track_id_t *out_track) {
  if (!table || !out_track)
    return -1;
  memset(out_track, 0, sizeof(*out_track));
  for (size_t i = 0; i < table->capacity; i++) {
    const track_subscription_t *entry = &table->entries[i];
    if (entry->active && entry->alias == alias) {
      *out_track = entry->track_id;
      return 0;
    }
  }
  return -1;
}

int transport_subscriptions_find_alias(
    const transport_subscription_table_t *table, const moq_track_id_t *track,
    uint8_t *out_alias) {
  if (!table || !track || !out_alias)
    return -1;
  for (size_t i = 0; i < table->capacity; i++) {
    const track_subscription_t *entry = &table->entries[i];
    if (entry->active &&
        track_matches(&entry->track_id, track->type, track->name)) {
      *out_alias = entry->alias;
      return 0;
    }
  }
  return -1;
}

track_subscription_t *
transport_subscriptions_find(transport_subscription_table_t *table,
                             const moq_track_id_t *track) {
  if (!table || !track)
    return NULL;
  for (size_t i = 0; i < table->capacity; i++) {
    track_subscription_t *entry = &table->entries[i];
    if (entry->active &&
        track_matches(&entry->track_id, track->type, track->name))
      return entry;
  }
  return NULL;
}

const track_subscription_t *
transport_subscriptions_find_const(const transport_subscription_table_t *table,
                                   const moq_track_id_t *track) {
  if (!table || !track)
    return NULL;
  for (size_t i = 0; i < table->capacity; i++) {
    const track_subscription_t *entry = &table->entries[i];
    if (entry->active &&
        track_matches(&entry->track_id, track->type, track->name))
      return entry;
  }
  return NULL;
}

bool transport_subscriptions_contains(
    const transport_subscription_table_t *table, const moq_track_id_t *track) {
  return transport_subscriptions_find_const(table, track) != NULL;
}

bool transport_subscriptions_add(transport_subscription_table_t *table,
                                 moq_track_type_t type, uint8_t flags,
                                 const char *name, uint8_t alias) {
  if (!ensure_initialized(table) || !name ||
      strnlen(name, sizeof(table->entries[0].track_id.name)) >=
          sizeof(table->entries[0].track_id.name))
    return false;
  for (size_t i = 0; i < table->capacity; i++) {
    const track_subscription_t *entry = &table->entries[i];
    if (entry->active && entry->alias == alias &&
        !track_matches(&entry->track_id, type, name))
      return false;
  }
  for (size_t i = 0; i < table->capacity; i++) {
    track_subscription_t *entry = &table->entries[i];
    if (entry->active && track_matches(&entry->track_id, type, name)) {
      if (entry->track_id.flags != flags)
        return false; /* An active subscription has one immutable mode. */
      if (entry->alias != alias) {
        table->states[alias] = table->states[entry->alias];
        table->states[entry->alias] = NULL;
        memset(table->states[alias], 0, sizeof(*table->states[alias]));
        table->states[alias]->generation = ++table->next_generation;
      }
      entry->alias = alias;
      entry->track_id.flags = flags;
      return true;
    }
  }
  for (size_t i = 0; i < table->capacity; i++) {
    track_subscription_t *entry = &table->entries[i];
    if (!entry->active) {
      transport_subscription_state_t *state = calloc(1, sizeof(*state));
      if (!state)
        return false;
      state->generation = ++table->next_generation;
      table->states[alias] = state;
      memset(entry, 0, sizeof(*entry));
      entry->track_id.type = type;
      entry->track_id.flags = flags;
      size_t name_len = strnlen(name, sizeof(entry->track_id.name));
      if (name_len >= sizeof(entry->track_id.name))
        return false;
      memcpy(entry->track_id.name, name, name_len + 1U);
      entry->alias = alias;
      entry->active = true;
      return true;
    }
  }
  return false;
}

void transport_subscriptions_remove(transport_subscription_table_t *table,
                                    moq_track_type_t type, const char *name) {
  if (!table || !name)
    return;
  for (size_t i = 0; i < table->capacity; i++) {
    track_subscription_t *entry = &table->entries[i];
    if (entry->active && track_matches(&entry->track_id, type, name)) {
      entry->active = false;
      free(table->states[entry->alias]);
      table->states[entry->alias] = NULL;
      if (entry->stream)
        quicly_streambuf_egress_shutdown(entry->stream);
      entry->stream = NULL;
      entry->ingress_stream = NULL;
      return;
    }
  }
}

void transport_subscriptions_clear_stream(transport_subscription_table_t *table,
                                          quicly_stream_t *stream) {
  if (!table || !stream)
    return;
  for (size_t i = 0; i < table->capacity; i++) {
    track_subscription_t *entry = &table->entries[i];
    if (entry->active) {
      if (entry->stream == stream)
        entry->stream = NULL;
      if (entry->ingress_stream == stream)
        entry->ingress_stream = NULL;
    }
  }
}

bool transport_subscriptions_bind_stream(transport_subscription_table_t *table,
                                         uint8_t alias,
                                         quicly_stream_t *stream) {
  if (!table || !stream)
    return false;
  for (size_t i = 0; i < table->capacity; i++) {
    track_subscription_t *entry = &table->entries[i];
    if (entry->active && entry->alias == alias) {
      entry->ingress_stream = stream;
      return true;
    }
  }
  return false;
}

int transport_subscriptions_next_alias(
    const transport_subscription_table_t *table, int first_dynamic_alias) {
  if (!table || first_dynamic_alias < 0 || first_dynamic_alias > UINT8_MAX)
    return -1;
  for (int alias = first_dynamic_alias; alias <= UINT8_MAX; alias++) {
    bool used = false;
    for (size_t i = 0; i < table->capacity; i++)
      if (table->entries[i].active && table->entries[i].alias == alias) {
        used = true;
        break;
      }
    if (!used)
      return alias;
  }
  return -1;
}
