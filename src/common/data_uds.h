/* data_uds.h */

#ifndef DATA_UDS_H
#define DATA_UDS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "transport.h"

typedef struct data_uds_t data_uds_t;

typedef void (*data_uds_callback_t)(void *user_data,
                                    const moq_track_id_t *track_id,
                                    const uint8_t *buf, size_t size,
                                    uint8_t priority);

/* The extended callback can retain a complete input record under backpressure.
 * id and progress survive RETRY; progress is an application-owned bit field.
 * ACCEPTED consumes the record, RETRY retains it, FATAL disconnects the helper.
 * Payload and descriptor pointers remain callback-borrowed. */
typedef enum {
  DATA_UDS_ACCEPTED,
  DATA_UDS_RETRY,
  DATA_UDS_FATAL
} data_uds_result_t;

typedef struct {
  const moq_track_id_t *track_id;
  const uint8_t *data;
  size_t size;
  uint8_t priority;
  uint64_t id;
  uint64_t progress;
} data_uds_record_t;

typedef data_uds_result_t (*data_uds_record_callback_t)(
    void *user_data, data_uds_record_t *record);

typedef bool (*data_uds_is_ready_callback_t)(void *user_data,
                                             const moq_track_id_t *track_id);

/* create and destroy a UDS generic data socket listener */
data_uds_t *data_uds_create(const char *socket_name,
                            data_uds_callback_t callback,
                            data_uds_is_ready_callback_t is_ready_cb,
                            void *user_data);
data_uds_t *data_uds_create_ex(const char *socket_name,
                               data_uds_record_callback_t callback,
                               data_uds_is_ready_callback_t is_ready_cb,
                               void *user_data);
void data_uds_destroy(data_uds_t *d);

/* write a length-prefixed data block with priority to the connected UDS client
 * matching the track_id */
bool data_uds_send(data_uds_t *d, const moq_track_id_t *track_id,
                   const uint8_t *buf, size_t size, uint8_t priority);

/* process listener and client fds in a non-blocking manner */
void data_uds_tick(data_uds_t *d);

struct pollfd;

/* collect UDS file descriptors for polling */
size_t data_uds_get_poll_fds(data_uds_t *d, struct pollfd *fds, size_t max_fds);

#endif /* DATA_UDS_H */
