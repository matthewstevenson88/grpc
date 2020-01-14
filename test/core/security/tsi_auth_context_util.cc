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

#include "test/core/security/tsi_auth_context_util.h"

#include <grpc/grpc.h>
#include <grpc/support/alloc.h>
#include <grpc/support/log.h>

#include "src/core/lib/security/context/security_context.h"

bool check_identity_from_auth_context_for_testing(
    const grpc_auth_context* ctx, const char* expected_property_name,
    const char* expected_identity) {
  grpc_auth_property_iterator it;
  const grpc_auth_property* prop;
  GPR_ASSERT(grpc_auth_context_peer_is_authenticated(ctx));
  it = grpc_auth_context_peer_identity(ctx);
  prop = grpc_auth_property_iterator_next(&it);
  GPR_ASSERT(prop != nullptr);
  if (strcmp(prop->name, expected_property_name) != 0) {
    gpr_log(GPR_ERROR, "Expected peer identity property name %s and got %s.",
            expected_property_name, prop->name);
    return false;
  }
  if (strncmp(prop->value, expected_identity, prop->value_length) != 0) {
    gpr_log(GPR_ERROR, "Expected peer identity %s and got got %s.",
            expected_identity, prop->value);
    return false;
  }
  return true;
}
