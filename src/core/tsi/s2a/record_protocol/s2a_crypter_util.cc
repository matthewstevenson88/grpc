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

#include "src/core/tsi/s2a/record_protocol/s2a_crypter_util.h"
#include <grpc/support/alloc.h>
#include <grpc/support/log.h>
#include <grpc/support/string_util.h>

grpc_status_code s2a_deserialize_session_state(
    grpc_byte_buffer* session_state_buffer, upb_arena* arena,
    s2a_SessionState** session_state, char** error_details) {
  if (session_state_buffer == nullptr) {
    *error_details =
        gpr_strdup("The |session_state_buffer| argument is nullptr.");
    return GRPC_STATUS_FAILED_PRECONDITION;
  }
  if (arena == nullptr) {
    *error_details = gpr_strdup("The |arena| argument is nullptr.");
    return GRPC_STATUS_FAILED_PRECONDITION;
  }
  grpc_byte_buffer_reader bbr;
  grpc_byte_buffer_reader_init(&bbr, session_state_buffer);
  grpc_slice slice = grpc_byte_buffer_reader_readall(&bbr);
  size_t buf_size = GPR_SLICE_LENGTH(slice);
  void* buf = upb_arena_malloc(arena, buf_size);
  memcpy(buf, reinterpret_cast<const char*>(GPR_SLICE_START_PTR(slice)),
         buf_size);
  *session_state =
      s2a_SessionState_parse(reinterpret_cast<char*>(buf), buf_size, arena);
  grpc_slice_unref_internal(slice);
  grpc_byte_buffer_reader_destroy(&bbr);
  if (*session_state == nullptr) {
    *error_details = gpr_strdup("The s2a_SessionState_parse() method failed.");
    return GRPC_STATUS_INTERNAL;
  }
  return GRPC_STATUS_OK;
}

tsi_result s2a_util_convert_to_tsi_result(s2a_decrypt_status status) {
  switch (status) {
    case OK:
      return TSI_OK;
    default:
      // TODO(mattstev): add more specifics for other error codes once I decide
      // how they will be used by the S2A TSI handshaker.
      return TSI_UNIMPLEMENTED;
  }
}
