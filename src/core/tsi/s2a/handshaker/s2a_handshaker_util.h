/*
 *
 * Copyright 2021 gRPC authors.
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

#ifndef GRPC_CORE_TSI_S2A_HANDSHAKER_S2A_HANDSHAKER_UTIL_H_
#define GRPC_CORE_TSI_S2A_HANDSHAKER_S2A_HANDSHAKER_UTIL_H_

#include <cstddef>
#include <grpc/byte_buffer.h>
#include <grpc/byte_buffer_reader.h>

#include "s2a/include/s2a_options.h"
#include "s2a/src/proto/upb-generated/proto/common.upb.h"
#include "s2a/src/proto/upb-generated/proto/s2a.upb.h"
#include "s2a/src/proto/upb-generated/proto/s2a_context.upb.h"

namespace s2a {
namespace tsi {

/** Converts to the upb-generated TLS version enum. **/
s2a_proto_TLSVersion s2a_convert_tls_version_to_enum(
    s2a_options::S2AOptions::TlsVersion tls_version);

/** Converts to the upb-generated ciphersuite enum. **/
s2a_proto_Ciphersuite s2a_convert_ciphersuite_to_enum(
    s2a_options::S2AOptions::Ciphersuite ciphersuite);

/** This method serializes |request| into a buffer, and returns a newly created
 *  grpc_byte_buffer that holds this buffer. The caller must not pass in nullptr
 *  for |request| or |arena|. **/
grpc_byte_buffer* s2a_get_serialized_session_req(s2a_proto_SessionReq* request,
                                                 upb_arena* arena);

/** This method deserializes |buffer| and produces a SessionReq message that is
 *  valid within |arena|. The caller must not pass in nullptr for |arena| or
 *  |buffer|. **/
s2a_proto_SessionReq* s2a_deserialize_session_req(upb_arena* arena,
                                                  grpc_byte_buffer* buffer);

/** This method deserializes |buffer| and produces a SessionResp message that is
 *  valid within |arena|. The caller must not pass in nullptr for |arena| or
 *  |buffer|. **/
s2a_proto_SessionResp* s2a_deserialize_session_resp(upb_arena* arena,
                                                    grpc_byte_buffer* buffer);

/** This method deserializes |serialized_buffer| and produces a |S2AContext|
 *  message that is valid within |arena|. The caller must not pass in nullptr
 *  for |arena|. **/
s2a_proto_S2AContext* s2a_deserialize_context(upb_arena* arena,
                                              char* serialized_buffer,
                                              size_t serialized_buffer_size);

}  // namespace tsi
}  // namespace s2a

#endif  // GRPC_CORE_TSI_S2A_HANDSHAKER_S2A_HANDSHAKER_UTIL_H_
