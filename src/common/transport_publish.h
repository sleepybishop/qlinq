#ifndef QLINQ_TRANSPORT_PUBLISH_H
#define QLINQ_TRANSPORT_PUBLISH_H

#include "transport_internal.h"
#include "transport_wire.h"

bool transport_publish_recipient_eligible(const transport_t *t,
                                          const transport_conn_t *conn,
                                          const moq_track_id_t *track);

bool transport_publish_recovery_ready(transport_t *t,
                                      const moq_track_id_t *track_id);

bool transport_publish_flush_grouped(transport_t *t);
bool transport_publish_finish_grouped(transport_t *t,
                                      const moq_track_id_t *track_id,
                                      uint64_t *final_object_id,
                                      bool *has_objects);
void transport_publish_checkpoint_member_added(transport_t *t,
                                               transport_conn_t *conn,
                                               const moq_track_id_t *track_id,
                                               uint8_t alias);
void transport_publish_checkpoint_member_removed(transport_t *t,
                                                 transport_conn_t *conn,
                                                 const moq_track_id_t *track_id,
                                                 uint8_t alias);
void transport_publish_checkpoint_connection_removed(transport_t *t,
                                                     transport_conn_t *conn);
bool transport_publish_checkpoint_acked(
    transport_t *t, transport_conn_t *conn,
    const qlinq_wire_track_checkpoint_ack_t *ack,
    const moq_track_id_t *track_id);

#endif
