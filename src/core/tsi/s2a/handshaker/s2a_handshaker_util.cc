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

#include "src/core/tsi/s2a/handshaker/s2a_handshaker_util.h"

#include <cstring>

#include "src/core/tsi/s2a/s2a_security.h"
#include "src/core/lib/slice/slice_internal.h"

namespace s2a {
namespace tsi {

s2a_proto_TLSVersion s2a_convert_tls_version_to_enum(
    s2a_options::S2AOptions::TlsVersion tls_version) {
  switch (tls_version) {
    case s2a_options::S2AOptions::TlsVersion::TLS1_2:
      return s2a_proto_TLS1_2;
    case s2a_options::S2AOptions::TlsVersion::TLS1_3:
      return s2a_proto_TLS1_3;
    default:
      GPR_ASSERT(0);
  }
}

s2a_proto_Ciphersuite s2a_convert_ciphersuite_to_enum(
    s2a_options::S2AOptions::Ciphersuite ciphersuite) {
  switch (ciphersuite) {
    case s2a_options::S2AOptions::Ciphersuite::AES_128_GCM_SHA256:
      return s2a_proto_AES_128_GCM_SHA256;
    case s2a_options::S2AOptions::Ciphersuite::AES_256_GCM_SHA384:
      return s2a_proto_AES_256_GCM_SHA384;
    case s2a_options::S2AOptions::Ciphersuite::CHACHA20_POLY1305_SHA256:
      return s2a_proto_CHACHA20_POLY1305_SHA256;
    default:
      GPR_ASSERT(0);
  }
}

grpc_byte_buffer* s2a_get_serialized_session_req(s2a_proto_SessionReq* request,
                                                 upb_arena* arena) {
  GPR_ASSERT(request != nullptr);
  GPR_ASSERT(arena != nullptr);
  size_t buffer_length;
  char* buffer = s2a_proto_SessionReq_serialize(request, arena, &buffer_length);
  if (buffer == nullptr) {
    return nullptr;
  }
  grpc_slice slice = grpc_slice_from_copied_buffer(buffer, buffer_length);
  grpc_byte_buffer* byte_buffer = grpc_raw_byte_buffer_create(&slice, 1);
  grpc_slice_unref_internal(slice);
  return byte_buffer;
}

s2a_proto_SessionReq* s2a_deserialize_session_req(upb_arena* arena,
                                                  grpc_byte_buffer* buffer) {
  GPR_ASSERT(arena != nullptr);
  GPR_ASSERT(buffer != nullptr);
  grpc_byte_buffer_reader reader;
  GPR_ASSERT(grpc_byte_buffer_reader_init(&reader, buffer));
  grpc_slice slice = grpc_byte_buffer_reader_readall(&reader);
  size_t buf_size = GPR_SLICE_LENGTH(slice);
  void* buf = upb_arena_malloc(arena, buf_size);
  memcpy(buf, reinterpret_cast<const char*>(GPR_SLICE_START_PTR(slice)),
         buf_size);
  s2a_proto_SessionReq* request =
      s2a_proto_SessionReq_parse(reinterpret_cast<char*>(buf), buf_size, arena);
  GPR_ASSERT(request != nullptr);
  grpc_slice_unref(slice);
  grpc_byte_buffer_reader_destroy(&reader);
  return request;
}

s2a_proto_SessionResp* s2a_deserialize_session_resp(upb_arena* arena,
                                                    grpc_byte_buffer* buffer) {
  GPR_ASSERT(arena != nullptr);
  GPR_ASSERT(buffer != nullptr);
  grpc_byte_buffer_reader reader;
  GPR_ASSERT(grpc_byte_buffer_reader_init(&reader, buffer));
  grpc_slice slice = grpc_byte_buffer_reader_readall(&reader);
  size_t buf_size = GPR_SLICE_LENGTH(slice);
  void* buf = upb_arena_malloc(arena, buf_size);
  memcpy(buf, reinterpret_cast<const char*>(GPR_SLICE_START_PTR(slice)),
         buf_size);
  s2a_proto_SessionResp* response = s2a_proto_SessionResp_parse(
      reinterpret_cast<char*>(buf), buf_size, arena);
  grpc_slice_unref(slice);
  grpc_byte_buffer_reader_destroy(&reader);
  return response;
}

s2a_proto_S2AContext* s2a_deserialize_context(upb_arena* arena,
                                              char* serialized_buffer,
                                              size_t serialized_buffer_size) {
  GPR_ASSERT(arena != nullptr);
  if (serialized_buffer == nullptr || serialized_buffer_size == 0) {
    return nullptr;
  }
  void* context_buffer = upb_arena_malloc(arena, serialized_buffer_size);
  memcpy(context_buffer, serialized_buffer, serialized_buffer_size);
  return s2a_proto_S2AContext_parse(reinterpret_cast<char*>(context_buffer),
                                    serialized_buffer_size, arena);
}

}  // namespace tsi
}  // namespace s2a

