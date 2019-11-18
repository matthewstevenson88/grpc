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

#ifndef GRPC_CORE_TSI_S2A_RECORD_PROTOCOL_S2A_CRYPTER_UTIL_H
#define GRPC_CORE_TSI_S2A_RECORD_PROTOCOL_S2A_CRYPTER_UTIL_H

#include <grpc/byte_buffer.h>
#include <grpc/byte_buffer_reader.h>
#include <grpc/grpc.h>
#include "src/core/lib/slice/slice_internal.h"
#include "src/proto/grpc/gcp/s2a.upb.h"

/** This method populates |session_state| with the s2a_SessionState instance
 *  extracted from |session_state_buffer|.
 *  - session_state_buffer: a buffer created from a s2a_SessionState instance;
 *    the caller must not pass in nullptr for this argument.
 *  - arena: an instance of upb_arena; the caller must not pass in nullptr for
 *    this argument, and otherwise there are no restrictions on the memory
 *    allocated to |arena|.
 *  - session_state: an instance populated by the method, which will be
 *    destroyed when |arena| is destroyed; it is legal (and expected) for
 *    |session_state| to point to a nullptr.
 *  - error_details: an instance populated by the method if an error occurs; it
 *    is legal (and expected) for |error_details| to point to a nullptr.
 *
 *  On success, the method populates |session_state| and returns GRPC_STATUS_OK.
 *  On failure, the method returns an error code and populates |error_details|
 *  with further details, and this must be freed using gpr_free.
 *
 *  Note: the implementation of this method is nearly identical to that of the
 *  alts_tsi_utils_deserialize_response() method from the alts_tsi_utils.cc
 *  file.
 *  **/
grpc_status_code s2a_deserialize_session_state(
    grpc_byte_buffer* session_state_buffer, upb_arena* arena,
    s2a_SessionState** session_state, char** error_details);

#endif  // GRPC_CORE_TSI_S2A_RECORD_PROTOCOL_S2A_CRYPTER_UTIL_H
