#ifndef QLINQ_TRANSPORT_MEMORY_H
#define QLINQ_TRANSPORT_MEMORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TRANSPORT_ARENA_MAX_FALLBACKS 1024U

typedef struct {
  uint8_t *buffer;
  size_t capacity;
  size_t offset;
  void *fallbacks[TRANSPORT_ARENA_MAX_FALLBACKS];
  size_t fallback_count;
} arena_t;

bool transport_arena_init(arena_t *arena, size_t capacity);
void transport_arena_destroy(arena_t *arena);
void *transport_arena_alloc(arena_t *arena, size_t size);
void transport_arena_reset(arena_t *arena);

typedef struct {
  uint8_t track_id;
  uint64_t group_id;
  uint64_t object_id;
  uint16_t total_symbols;
  uint16_t data_symbols;
  uint16_t symbol_size;
  uint32_t original_size;
  uint16_t received_count;
  uint16_t capacity_symbols;
  uint16_t capacity_symbol_size;
  uint8_t **buffers;
  uint8_t *buffer_storage;
  bool *received_mask;
  bool *missing_mask;
  uint16_t *missing_indices;
  bool decoded;
  bool shared_delivery;
  uint8_t priority;
  bool nack_sent;
  uint16_t nack_attempt;
  int64_t first_symbol_time_ms;
  int64_t last_activity_time_ms;
  int64_t last_nack_time_ms;
} frame_assembler_t;

void transport_assembler_release(frame_assembler_t *assembler);
bool transport_assembler_grow(frame_assembler_t *assembler, uint16_t symbols,
                              uint16_t symbol_size);
size_t transport_assembler_capacity_bytes(const frame_assembler_t *assembler);
size_t transport_assembler_required_bytes(uint16_t symbols,
                                          uint16_t symbol_size);

#endif
