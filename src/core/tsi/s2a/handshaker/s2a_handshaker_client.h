/*
 *
 * Copyright 2019 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef GRPC_CORE_TSI_S2A_HANDSHAKER_S2A_HANDSHAKER_CLIENT_H
#define GRPC_CORE_TSI_S2A_HANDSHAKER_S2A_HANDSHAKER_CLIENT_H

#include <grpc/byte_buffer.h>
#include <grpc/byte_buffer_reader.h>
#include <grpc/grpc.h>
#include "src/core/lib/iomgr/closure.h"
#include "src/core/lib/iomgr/pollset_set.h"
#include "src/core/tsi/transport_security_interface.h"

namespace grpc_core {
namespace experimental {

typedef struct s2a_tsi_handshaker s2a_tsi_handshaker;

/** The Secure Session Agent (S2A) handshaker client interface. It facilitates
 *  establishing a secure channel with the peer by interacting with the
 *  S2A's handshaker service. More precisely, it schedules
 *  a handshaker request that could be one of client_start, server_start,
 *  and next handshaker requests. The interface and all API's are
 *  thread-compatible. **/
typedef struct s2a_handshaker_client s2a_handshaker_client;

typedef struct grpc_s2a_credentials_options grpc_s2a_credentials_options;

/** A function that makes a gRPC call to the S2A. The default caller option
 *  is the grpc_call_start_batch_and_execute caller. **/
typedef grpc_call_error (*s2a_grpc_caller)(grpc_call* call, const grpc_op* ops,
                                           size_t nops, grpc_closure* tag);

/** The vtable for the S2A handshaker client operations. **/
typedef struct s2a_handshaker_client_vtable {
  tsi_result (*client_start)(s2a_handshaker_client* client);
  tsi_result (*server_start)(s2a_handshaker_client* client,
                             grpc_slice* bytes_received);
  tsi_result (*next)(s2a_handshaker_client* client, grpc_slice* bytes_received);
  void (*shutdown)(s2a_handshaker_client* client);
  void (*destruct)(s2a_handshaker_client* client);
} s2a_handshaker_client_vtable;

/** This method schedules a client_start handshaker request with the S2A's
 *  handshaker service.
 *  - client: an s2a_handshaker_client instance.
 *  It returns TSI_OK on success and an error code on failure. **/
tsi_result s2a_handshaker_client_start_client(
    const s2a_handshaker_client* client);

/** This method schedules a server_start handshaker request with the S2A's
 *  handshaker service.
 *  - client: an s2a_handshaker_client instance.
 *  - bytes_received: the bytes from the out_bytes field of the message received
 *    from the peer.
 *  It returns TSI_OK on success and an error code on failure. **/
tsi_result s2a_handshaker_client_start_server(
    const s2a_handshaker_client* client, grpc_slice* bytes_received);

/** This method schedules a next handshaker request with the S2A's
 *  handshaker service.
 *  - client: an s2a_handshaker_client instance.
 *  - bytes_received: the bytes from the out_bytes field of the SessionResp
 *    message that the client peer received from its S2A.
 *  It returns TSI_OK on success and an error code on failure. **/
tsi_result s2a_handshaker_client_next(const s2a_handshaker_client* client,
                                      grpc_slice* bytes_received);

/** This method cancels previously scheduled, but not yet executed, handshaker
 *  requests to the S2A's handshaker service. After this operation completes, no
 *  further handshaker requests will be scheduled with the S2A. **/
void s2a_handshaker_client_shutdown(const s2a_handshaker_client* client);

/** This method populates |client| with an instance of the
 *  s2a_handshaker_client, which is configured using the other arguments. The
 *  additional arguments are specified below.
 *  - handshaker: the s2a_tsi_handshaker that owns |client|.
 *  - channel: the gRPC channel used to connect with the S2A.
 *  - handshaker_service_url: the address of the S2A handshaker service; it
 *    follows the format "host:port".
 *  - interested_parties: the set of pollsets that are interested in this gRPC
 *    connection.
 *  - options: S2A-specific options used to configure the s2a_handshaker_client.
 *  - target_name: the name of the endpoint to which the channel connects; this
 *    data will be used for a secure naming check.
 *  - grpc_cb: a gRPC-provided callback function that is owned by |handshaker|.
 *  - cb: a callback function to be called when the tsi_handshaker_next API
 *    completes.
 *  - user_data: the argument passed to |cb|.
 *  - is_client: a boolean that is true if |client| is used at the client side,
 *    and false if |client| is used at the server side.
 *  - client: a pointer to the address of an s2a_handshaker_client instance,
 *    which will be populated by the method. It is legal (and expected) for
 *    |client| to point to a nullptr.
 *  - error_details: an error message for when the creation fails. It is legal
 *    (and expected) to have |error_details| point to a nullptr.
 *
 *  On success, this method returns TSI_OK. Otherwise, it returns an error code
 *  and populates |error_details| with further details; in this case, the memory
 *  allocated to |error_details| must be freed using gpr_free. **/
tsi_result s2a_handshaker_client_create(
    s2a_tsi_handshaker* handshaker, grpc_channel* channel,
    const char* handshaker_service_url, grpc_pollset_set* interested_parties,
    grpc_s2a_credentials_options* options, const grpc_slice& target_name,
    grpc_iomgr_cb_func grpc_cb, tsi_handshaker_on_next_done_cb cb,
    void* user_data, bool is_client, s2a_handshaker_client** client,
    char** error_details);

/** This method destroys an s2a_handshaker_client. The caller must call this
 *  method after any use of s2a_handshaker_client_create, even if it outputs a
 *  status other than TSI_OK.  **/
void s2a_handshaker_client_destroy(s2a_handshaker_client* client);

}  // namespace experimental
}  // namespace grpc_core

#endif  // GRPC_CORE_TSI_S2A_HANDSHAKER_S2A_HANDSHAKER_CLIENT_H
