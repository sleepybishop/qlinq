#include "transport_config.h"

#include <stdio.h>
#include <string.h>

#define QLINQ_MIN_EGRESS_PACKETS 64U
#define QLINQ_MIN_EGRESS_BYTES (64U * 1500U)

static size_t value_or_default(size_t value, size_t fallback) {
  return value == 0 ? fallback : value;
}

static bool fail(char *error, size_t capacity, const char *message) {
  if (error && capacity > 0)
    snprintf(error, capacity, "%s", message);
  return false;
}

bool transport_limits_resolve(const transport_limits_t *configured,
                              transport_limits_t *resolved, char *error,
                              size_t error_capacity) {
  if (!configured || !resolved)
    return fail(error, error_capacity, "missing transport limits");

  memset(resolved, 0, sizeof(*resolved));
  resolved->max_connections = value_or_default(
      configured->max_connections, TRANSPORT_DEFAULT_MAX_CONNECTIONS);
  resolved->max_subscriptions_per_connection =
      value_or_default(configured->max_subscriptions_per_connection,
                       TRANSPORT_DEFAULT_MAX_SUBSCRIPTIONS);
  resolved->max_assemblers_per_connection =
      value_or_default(configured->max_assemblers_per_connection,
                       TRANSPORT_DEFAULT_MAX_ASSEMBLERS);
  resolved->max_repair_requests_per_second =
      value_or_default(configured->max_repair_requests_per_second,
                       TRANSPORT_DEFAULT_MAX_REPAIR_REQUESTS_PER_SECOND);
  resolved->max_aggregate_repair_requests_per_second = value_or_default(
      configured->max_aggregate_repair_requests_per_second,
      TRANSPORT_DEFAULT_MAX_AGGREGATE_REPAIR_REQUESTS_PER_SECOND);
  resolved->max_egress_packets_per_socket =
      value_or_default(configured->max_egress_packets_per_socket,
                       TRANSPORT_DEFAULT_MAX_EGRESS_PACKETS);
  resolved->max_egress_bytes_per_socket =
      value_or_default(configured->max_egress_bytes_per_socket,
                       TRANSPORT_DEFAULT_MAX_EGRESS_BYTES);
  resolved->max_assembler_memory_bytes =
      value_or_default(configured->max_assembler_memory_bytes,
                       TRANSPORT_DEFAULT_ASSEMBLER_MEMORY_BUDGET);
  resolved->max_recovery_cache_bytes =
      value_or_default(configured->max_recovery_cache_bytes,
                       TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES);
  resolved->max_reliable_object_size = value_or_default(
      configured->max_reliable_object_size, TRANSPORT_MAX_RELIABLE_OBJECT_SIZE);
  resolved->max_fec_object_size = value_or_default(
      configured->max_fec_object_size, TRANSPORT_MAX_FEC_OBJECT_SIZE);
  resolved->max_udp_payload_size =
      value_or_default(configured->max_udp_payload_size, 1280U);
  resolved->max_packets_per_tick = value_or_default(
      configured->max_packets_per_tick, TRANSPORT_DEFAULT_MAX_PACKETS_PER_TICK);

  if (resolved->max_connections > TRANSPORT_HARD_MAX_CONNECTIONS)
    return fail(error, error_capacity, "max_connections exceeds hard limit");
  if (resolved->max_subscriptions_per_connection >
      TRANSPORT_HARD_MAX_SUBSCRIPTIONS)
    return fail(error, error_capacity,
                "max_subscriptions_per_connection exceeds alias space");
  if (resolved->max_assemblers_per_connection > TRANSPORT_HARD_MAX_ASSEMBLERS)
    return fail(error, error_capacity,
                "max_assemblers_per_connection exceeds hard limit");
  if (resolved->max_repair_requests_per_second > UINT16_MAX)
    return fail(error, error_capacity,
                "max_repair_requests_per_second exceeds hard limit");
  if (resolved->max_aggregate_repair_requests_per_second > UINT16_MAX)
    return fail(error, error_capacity,
                "max_aggregate_repair_requests_per_second exceeds hard limit");
  if (resolved->max_egress_packets_per_socket < QLINQ_MIN_EGRESS_PACKETS ||
      resolved->max_egress_packets_per_socket >
          TRANSPORT_HARD_MAX_EGRESS_PACKETS)
    return fail(error, error_capacity,
                "max_egress_packets_per_socket is outside supported range");
  if (resolved->max_egress_bytes_per_socket < QLINQ_MIN_EGRESS_BYTES)
    return fail(error, error_capacity,
                "max_egress_bytes_per_socket cannot hold one send batch");
  if (resolved->max_assembler_memory_bytes < 1024U * 1024U)
    return fail(error, error_capacity,
                "max_assembler_memory_bytes must be at least 1 MiB");
  if (resolved->max_reliable_object_size > TRANSPORT_MAX_RELIABLE_OBJECT_SIZE)
    return fail(error, error_capacity,
                "max_reliable_object_size exceeds wire implementation");
  if (resolved->max_fec_object_size > TRANSPORT_MAX_FEC_OBJECT_SIZE)
    return fail(error, error_capacity,
                "max_fec_object_size exceeds wire implementation");
  /* One active track must reach its rolling checkpoint before the cache
   * fills. Grouped records have a two-byte prefix and a 16-bit length. */
  size_t grouped_max =
      resolved->max_fec_object_size < TRANSPORT_MAX_FEC_RECORD_SIZE + 2U
          ? resolved->max_fec_object_size
          : TRANSPORT_MAX_FEC_RECORD_SIZE + 2U;
  size_t minimum_cache = TRANSPORT_RECOVERY_WINDOW_OBJECTS * grouped_max;
  if (minimum_cache < resolved->max_fec_object_size)
    minimum_cache = resolved->max_fec_object_size;
  if (resolved->max_recovery_cache_bytes < minimum_cache)
    return fail(error, error_capacity,
                "recovery cache must hold one recovery window");
  if (resolved->max_udp_payload_size < 1200U ||
      resolved->max_udp_payload_size > 1500U)
    return fail(error, error_capacity,
                "max_udp_payload_size is outside supported range");
  if (resolved->max_packets_per_tick > 65536U)
    return fail(error, error_capacity,
                "max_packets_per_tick exceeds hard limit");
  return true;
}
