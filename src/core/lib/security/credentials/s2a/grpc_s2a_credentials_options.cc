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

#include <grpc/support/port_platform.h>

#include "src/core/lib/security/credentials/s2a/grpc_s2a_credentials_options.h"

#include <grpc/support/alloc.h>
#include <grpc/support/log.h>

namespace experimental {

grpc_s2a_credentials_options* grpc_s2a_credentials_options_copy(
    const grpc_s2a_credentials_options* options) {
  if (options != nullptr && options->vtable != nullptr &&
      options->vtable->copy != nullptr) {
    return options->vtable->copy(options);
  }
  gpr_log(GPR_ERROR, "Invalid arguments to grpc_s2a_credentials_options_copy.");
  return nullptr;
}

void grpc_s2a_credentials_options_destroy(
    grpc_s2a_credentials_options* options) {
  if (options != nullptr) {
    if (options->vtable != nullptr && options->vtable->destruct != nullptr) {
      options->vtable->destruct(options);
    }
    gpr_free(options);
  }
}

void grpc_s2a_credentials_options_add_ciphersuite(
    grpc_s2a_credentials_options* options,
    s2a_supported_ciphersuite ciphersuite) {
  if (options == nullptr) {
    gpr_log(GPR_ERROR,
            "Invalid nullptr argument to "
            "grpc_s2a_credentials_options_add_ciphersuite.");
    return;
  }
  s2a_ciphersuite* node =
      static_cast<s2a_ciphersuite*>(gpr_zalloc(sizeof(s2a_ciphersuite)));
  node->cipher = ciphersuite;
  node->next = options->ciphersuite_head;
  options->ciphersuite_head = node;
}

}  // namespace experimental
