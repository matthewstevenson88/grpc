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

#include "src/core/tsi/s2a/handshaker/s2a_handshaker_util.h"
#include <grpc/support/port_platform.h>
#include "src/core/lib/slice/slice_internal.h"
#include "src/core/tsi/s2a/s2a_constants.h"

namespace grpc_core {
namespace experimental {

int32_t s2a_convert_ciphersuite_to_enum(uint16_t ciphersuite) {
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      return 0;
    case kTlsAes256GcmSha384:
      return 1;
    case kTlsChacha20Poly1305Sha256:
      return 2;
  }
}

grpc_byte_buffer* s2a_get_serialized_session_req(s2a_SessionReq* request,
                                                 upb_arena* arena) {
  size_t buffer_length;
  char* buffer = s2a_SessionReq_serialize(request, arena, &buffer_length);
  if (buffer == nullptr) {
    return nullptr;
  }
  grpc_slice slice = grpc_slice_from_copied_buffer(buffer, buffer_length);
  grpc_byte_buffer* byte_buffer = grpc_raw_byte_buffer_create(&slice, 1);
  grpc_slice_unref_internal(slice);
  return byte_buffer;
}

}  // namespace experimental
}  // namespace grpc_core
