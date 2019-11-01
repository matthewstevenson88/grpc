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

#include <grpc/support/string_util.h>
#include "src/core/tsi/alts/crypt/gsec.h"

grpc_status_code gsec_chacha_poly_aead_crypter_create(
    const uint8_t* key, size_t key_length, size_t nonce_length,
    size_t tag_length, gsec_aead_crypter** crypter, char** error_details) {
  *error_details =
      gpr_strdup("The CHACHA-POLY AEAD crypter is not yet implemented.");
  return GRPC_STATUS_UNIMPLEMENTED;
}
