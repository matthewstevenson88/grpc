/*
 *
 * Copyright 2018 gRPC authors.
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

#include <grpc/grpc.h>
#include <grpc/support/alloc.h>
#include <grpc/support/log.h>

#include "src/core/lib/security/security_connector/s2a/s2a_auth_context.h"
#include "src/core/lib/transport/transport.h"
#include "src/core/tsi/s2a/s2a_constants.h"
#include "src/core/tsi/transport_security.h"
#include "test/core/security/tsi_auth_context_util.h"

using experimental::internal::grpc_s2a_auth_context_from_tsi_peer;

static void s2a_auth_context_peer_is_nullptr() {
  grpc_core::RefCountedPtr<grpc_auth_context> ctx =
      grpc_s2a_auth_context_from_tsi_peer(nullptr);
  GPR_ASSERT(ctx == nullptr);
}

static void s2a_auth_context_empty_certificate() {
  tsi_peer peer;
  GPR_ASSERT(tsi_construct_peer(/* property_count=*/0, &peer) == TSI_OK);
  grpc_core::RefCountedPtr<grpc_auth_context> ctx =
      grpc_s2a_auth_context_from_tsi_peer(&peer);
  GPR_ASSERT(ctx == nullptr);
  tsi_peer_destruct(&peer);
}

static void s2a_auth_context_empty_peer() {
  tsi_peer peer;
  GPR_ASSERT(tsi_construct_peer(/* property_count=*/1, &peer) == TSI_OK);
  GPR_ASSERT(tsi_construct_string_peer_property_from_cstring(
                 TSI_CERTIFICATE_TYPE_PEER_PROPERTY, kTsiS2ACertificateType,
                 &peer.properties[0]) == TSI_OK);
  grpc_core::RefCountedPtr<grpc_auth_context> ctx =
      grpc_s2a_auth_context_from_tsi_peer(&peer);
  GPR_ASSERT(ctx == nullptr);
  tsi_peer_destruct(&peer);
}

static void s2a_auth_context_unknown_peer_property() {
  tsi_peer peer;
  GPR_ASSERT(tsi_construct_peer(kTsiS2ANumOfPeerProperties, &peer) == TSI_OK);
  GPR_ASSERT(tsi_construct_string_peer_property_from_cstring(
                 TSI_CERTIFICATE_TYPE_PEER_PROPERTY, kTsiS2ACertificateType,
                 &peer.properties[0]) == TSI_OK);
  GPR_ASSERT(tsi_construct_string_peer_property_from_cstring(
                 "unknown", "alice", &peer.properties[1]) == TSI_OK);
  grpc_core::RefCountedPtr<grpc_auth_context> ctx =
      grpc_s2a_auth_context_from_tsi_peer(&peer);
  GPR_ASSERT(ctx == nullptr);
  tsi_peer_destruct(&peer);
}

static void s2a_auth_context_success() {
  tsi_peer peer;
  GPR_ASSERT(tsi_construct_peer(kTsiS2ANumOfPeerProperties, &peer) == TSI_OK);
  GPR_ASSERT(tsi_construct_string_peer_property_from_cstring(
                 TSI_CERTIFICATE_TYPE_PEER_PROPERTY, kTsiS2ACertificateType,
                 &peer.properties[0]) == TSI_OK);
  GPR_ASSERT(tsi_construct_string_peer_property_from_cstring(
                 kTsiS2AServiceAccountPeerProperty, "alice",
                 &peer.properties[1]) == TSI_OK);
  char test_ctx[] = "s2a_test serialized context";
  grpc_slice serialized_s2a_ctx = grpc_slice_from_copied_string(test_ctx);
  GPR_ASSERT(
      tsi_construct_string_peer_property(
          kTsiS2AContext,
          reinterpret_cast<char*>(GRPC_SLICE_START_PTR(serialized_s2a_ctx)),
          GRPC_SLICE_LENGTH(serialized_s2a_ctx),
          &peer.properties[2]) == TSI_OK);
  grpc_core::RefCountedPtr<grpc_auth_context> ctx =
      grpc_s2a_auth_context_from_tsi_peer(&peer);
  GPR_ASSERT(ctx != nullptr);
  GPR_ASSERT(
      test_identity(ctx.get(), kTsiS2AServiceAccountPeerProperty, "alice"));
  ctx.reset(DEBUG_LOCATION, "test");
  grpc_slice_unref(serialized_s2a_ctx);
  tsi_peer_destruct(&peer);
}

int main(int /*argc*/, char** /*argv*/) {
  s2a_auth_context_peer_is_nullptr();
  s2a_auth_context_empty_certificate();
  s2a_auth_context_empty_peer();
  s2a_auth_context_unknown_peer_property();
  s2a_auth_context_success();
  return 0;
}
