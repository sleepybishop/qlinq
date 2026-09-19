#include "transport_scheduler.h"
#include "transport_paths.h"

#include <string.h>

bool transport_schedule_build(pathflow_context_t *context,
                              const path_state_t *states, size_t num_paths,
                              size_t data_symbols, size_t symbol_size,
                              bool fec_enabled, uint8_t priority,
                              size_t *round_robin,
                              transport_schedule_t *schedule) {
  if (!context || !states || !round_robin || !schedule || num_paths == 0 ||
      num_paths > TRANSPORT_MAX_PATHS || data_symbols == 0 || symbol_size == 0)
    return false;
  memset(schedule, 0, sizeof(*schedule));

  path_t defaults = transport_path_estimate(NULL, 0, 0, symbol_size, 0);
  for (size_t i = 0; i < num_paths; i++) {
    schedule->paths[i].b = states[i].b_ewma > 0 ? states[i].b_ewma : defaults.b;
    schedule->paths[i].l =
        states[i].initialized ? states[i].l_ewma : defaults.l;
    schedule->paths[i].p =
        states[i].initialized ? states[i].p_ewma : defaults.p;
    schedule->paths[i].q = states[i].q_ewma;
  }

  if (!fec_enabled) {
    for (size_t symbol = 0; symbol < data_symbols; symbol++)
      schedule->paths[symbol % num_paths].x++;
    return true;
  }

  if (data_symbols == 1) {
    schedule->paths[*round_robin % num_paths].x = 1;
    (*round_robin)++;
    return true;
  }

  size_t target_reliability = priority == 0 ? 85 : (priority == 2 ? 99 : 95);
  context->offset = 0;
  if (pathflow_optimize(context, num_paths, data_symbols, schedule->paths,
                        FP_FROM_FLOAT(10.0f), target_reliability,
                        PATHFLOW_SOLVER_GREEDY) == PATHFLOW_ERROR)
    return false;

  for (size_t i = 0; i < num_paths; i++) {
    if (schedule->paths[i].x > schedule->paths[i].m)
      schedule->parity_symbols += schedule->paths[i].x - schedule->paths[i].m;
  }
  if (schedule->parity_symbols == 0) {
    /* Account for minimum parity on a data-carrying path. Do not resurrect a
     * path rejected for loss just because its latency is small. Choose the
     * earliest finish, including unsent work and existing symbols. */
    size_t chosen = SIZE_MAX;
    fp_t best = FP_MAX;
    for (size_t i = 0; i < num_paths; i++) {
      path_t *path = &schedule->paths[i];
      if (path->m == 0)
        continue;
      fp_t finish =
          FP_ADD(path->l,
                 FP_DIV(FP_ADD(FP_FROM_INT(path->q), FP_FROM_INT(path->x + 1)),
                        path->b));
      if (chosen == SIZE_MAX || finish < best) {
        chosen = i;
        best = finish;
      }
    }
    if (chosen == SIZE_MAX)
      return false;
    schedule->paths[chosen].x++;
    schedule->parity_symbols = 1;
  }
  return true;
}
