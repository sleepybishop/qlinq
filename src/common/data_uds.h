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

typedef bool (*data_uds_is_ready_callback_t)(void *user_data,
                                             const moq_track_id_t *track_id);

/* create and destroy a UDS generic data socket listener */
data_uds_t *data_uds_create(const char *socket_name,
                            data_uds_callback_t callback,
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
