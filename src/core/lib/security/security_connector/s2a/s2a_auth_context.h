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

#ifndef GRPC_CORE_LIB_SECURITY_SECURITY_CONNECTOR_S2A_S2A_AUTH_CONTEXT_H
#define GRPC_CORE_LIB_SECURITY_SECURITY_CONNECTOR_S2A_S2A_AUTH_CONTEXT_H

#include <grpc/support/port_platform.h>
#include "src/core/lib/security/context/security_context.h"

namespace experimental {
namespace internal {

/** This API is exposed only for testing. **/
grpc_core::RefCountedPtr<grpc_auth_context> grpc_s2a_auth_context_from_tsi_peer(
    const tsi_peer* peer);

}  // namespace internal
}  // namespace experimental

#endif  // GRPC_CORE_LIB_SECURITY_SECURITY_CONNECTOR_S2A_S2A_AUTH_CONTEXT_H
