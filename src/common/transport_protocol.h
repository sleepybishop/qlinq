#ifndef QLINQ_TRANSPORT_PROTOCOL_H
#define QLINQ_TRANSPORT_PROTOCOL_H

#include "transport_internal.h"

bool transport_track_type_valid(uint8_t type);
void transport_protocol_setup(transport_t *t);
void transport_protocol_receive_datagram(transport_conn_t *conn,
                                         ptls_iovec_t payload,
                                         bool allow_telemetry);
bool transport_protocol_send_hello(transport_conn_t *conn);
void transport_protocol_maybe_emit_connected(transport_conn_t *conn);
void transport_protocol_poll_lifecycle(transport_t *t);
bool transport_protocol_send_nack(transport_conn_t *conn, uint8_t alias,
                                  uint64_t group_id, uint64_t object_id,
                                  const uint16_t *missing, uint16_t count,
                                  bool whole_object);

#endif
