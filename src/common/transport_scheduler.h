#ifndef QLINQ_TRANSPORT_SCHEDULER_H
#define QLINQ_TRANSPORT_SCHEDULER_H

#include "transport.h"

#include "pathflow.h"
#include "quicly.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  path_t paths[TRANSPORT_MAX_PATHS];
  size_t parity_symbols;
} transport_schedule_t;

bool transport_schedule_build(pathflow_context_t *context,
                              const path_state_t *states, size_t num_paths,
                              size_t data_symbols, size_t symbol_size,
                              bool fec_enabled, uint8_t priority,
                              size_t *round_robin,
                              transport_schedule_t *schedule);

#endif
