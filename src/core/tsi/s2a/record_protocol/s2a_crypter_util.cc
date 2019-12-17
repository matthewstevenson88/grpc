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
#include "src/core/tsi/s2a/s2a_constants.h"

tsi_result s2a_util_convert_to_tsi_result(S2ADecryptStatus status) {
  switch (status) {
    case S2ADecryptStatus::OK:
      return TSI_OK;
    default:
      // TODO(mattstev): add more specifics for other error codes once I decide
      // how they will be used by the S2A TSI handshaker.
      return TSI_UNIMPLEMENTED;
  }
}

grpc_status_code s2a_ciphersuite_to_hash_function(
    uint16_t ciphersuite, GsecHashFunction* hash_function,
    char** error_details) {
  GPR_ASSERT(hash_function != nullptr);
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      *hash_function = GsecHashFunction::SHA256_hash_function;
      break;
    case kTlsAes256GcmSha384:
      *hash_function = GsecHashFunction::SHA384_hash_function;
      break;
    case kTlsChacha20Poly1305Sha256:
      *hash_function = GsecHashFunction::SHA256_hash_function;
      break;
    default:
      *error_details = gpr_strdup(kS2AUnsupportedCiphersuite);
      return GRPC_STATUS_FAILED_PRECONDITION;
  }
  return GRPC_STATUS_OK;
}
