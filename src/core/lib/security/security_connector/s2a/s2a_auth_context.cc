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

#include "src/core/lib/security/security_connector/s2a/s2a_auth_context.h"
#include "src/core/lib/transport/transport.h"
#include "src/core/tsi/s2a/s2a_constants.h"
#include "src/core/tsi/transport_security.h"

namespace experimental {
namespace internal {

grpc_core::RefCountedPtr<grpc_auth_context> grpc_s2a_auth_context_from_tsi_peer(
    const tsi_peer* peer) {
  if (peer == nullptr) {
    gpr_log(
        GPR_ERROR,
        "Invalid nullptr arguments to |grpc_s2a_auth_context_from_tsi_peer|.");
    return nullptr;
  }

  /** Validate certificate type. **/
  const tsi_peer_property* cert_type_prop =
      tsi_peer_get_property_by_name(peer, TSI_CERTIFICATE_TYPE_PEER_PROPERTY);
  if (cert_type_prop == nullptr ||
      strncmp(cert_type_prop->value.data, kTsiS2ACertificateType,
              cert_type_prop->value.length) != 0) {
    gpr_log(GPR_ERROR, "Invalid or missing certificate type property.");
    return nullptr;
  }

  /** Validate S2A Context. **/
  const tsi_peer_property* s2a_context_property =
      tsi_peer_get_property_by_name(peer, kTsiS2AContext);
  if (s2a_context_property == nullptr) {
    gpr_log(GPR_ERROR, "Missing S2A context property.");
    return nullptr;
  }

  /** Create auth context. **/
  auto ctx = grpc_core::MakeRefCounted<grpc_auth_context>(nullptr);
  grpc_auth_context_add_cstring_property(
      ctx.get(), GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME,
      kGrpcS2ATransportSecurityType);
  size_t i = 0;
  for (i = 0; i < peer->property_count; i++) {
    const tsi_peer_property* tsi_prop = &peer->properties[i];
    /** Add service account to auth context. **/
    if (strcmp(tsi_prop->name, kTsiS2AServiceAccountPeerProperty) == 0) {
      grpc_auth_context_add_property(
          ctx.get(), kTsiS2AServiceAccountPeerProperty, tsi_prop->value.data,
          tsi_prop->value.length);
      GPR_ASSERT(grpc_auth_context_set_peer_identity_property_name(
                     ctx.get(), kTsiS2AServiceAccountPeerProperty) == 1);
    }
    /** Add S2A context to auth context. **/
    if (strcmp(tsi_prop->name, kTsiS2AContext) == 0) {
      grpc_auth_context_add_property(ctx.get(), kTsiS2AContext,
                                     tsi_prop->value.data,
                                     tsi_prop->value.length);
    }
  }
  if (!grpc_auth_context_peer_is_authenticated(ctx.get())) {
    gpr_log(GPR_ERROR, "Invalid unauthenticated peer.");
    ctx.reset(DEBUG_LOCATION, "test");
    return nullptr;
  }
  return ctx;
}

}  // namespace internal
}  // namespace experimental
