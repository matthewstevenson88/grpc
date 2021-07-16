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

#include "src/core/tsi/s2a/s2a_tsi_handshaker.h"

#include <grpc/slice.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "s2a/src/handshaker/s2a_proxy_test_util.h"
#include "src/core/lib/iomgr/exec_ctx.h"
#include "src/core/tsi/s2a/s2a_security.h"
#include "src/core/tsi/transport_security_grpc.h"

namespace s2a {
namespace tsi {
namespace {

constexpr size_t kConsumedBytes = 2;
constexpr char kRecvBytes[] = "recv_bytes";
constexpr size_t kRecvBytesSize = 10;

std::string PeerPropertyToString(const tsi_peer_property* property) {
  ABSL_ASSERT(property != nullptr);
  return std::string(property->value.data, property->value.length);
}

TEST(S2ATsiHandshakerResultTest, CreateFailsBecauseNullptrArgument) {
  EXPECT_EQ(CreateS2ATsiHandshakerResult(/*proxy=*/nullptr).status().code(),
            absl::StatusCode::kInvalidArgument);
}

TEST(S2ATsiHandshakerResultTest, CreateFailsBecauseHandshakeIsNotFinished) {
  EXPECT_EQ(CreateS2ATsiHandshakerResult(
                s2a_proxy::CreateTestProxy(/*has_handshake_result=*/false,
                                           /*is_client=*/true))
                .status()
                .code(),
            absl::StatusCode::kFailedPrecondition);
}

TEST(S2ATsiHandshakerResultTest, SetAndGetUnusedBytes) {
  absl::StatusOr<tsi_handshaker_result*> handshake_result =
      CreateS2ATsiHandshakerResult(
          s2a_proxy::CreateTestProxy(/*has_handshake_result=*/true,
                                     /*is_client=*/true));
  EXPECT_TRUE(handshake_result.ok());
  EXPECT_NE(*handshake_result, nullptr);

  grpc_slice received_bytes = grpc_slice_from_static_string(kRecvBytes);
  SetUnusedBytes(*handshake_result, &received_bytes, kConsumedBytes);
  const uint8_t* unused_bytes = nullptr;
  size_t unused_bytes_size = 0;
  EXPECT_EQ(tsi_handshaker_result_get_unused_bytes(
                *handshake_result, &unused_bytes, &unused_bytes_size),
            TSI_OK);
  EXPECT_EQ(unused_bytes_size, kRecvBytesSize - kConsumedBytes);
  for (size_t i = 0; i < unused_bytes_size; i++) {
    EXPECT_EQ(unused_bytes[unused_bytes_size - i - 1],
              kRecvBytes[kRecvBytesSize - i - 1]);
  }

  tsi_handshaker_result_destroy(*handshake_result);
}

TEST(S2ATsiHandshakerResultTest, GetFrameProtector) {
  absl::StatusOr<tsi_handshaker_result*> handshake_result =
      CreateS2ATsiHandshakerResult(
          s2a_proxy::CreateTestProxy(/*has_handshake_result=*/true,
                                     /*is_client=*/true));
  EXPECT_TRUE(handshake_result.ok());
  EXPECT_NE(*handshake_result, nullptr);

  {
    grpc_core::ExecCtx exec_ctx;
    tsi_zero_copy_grpc_protector* protector = nullptr;
    size_t max_frame_size = 0;
    EXPECT_EQ(tsi_handshaker_result_create_zero_copy_grpc_protector(
                  *handshake_result, &max_frame_size, &protector),
              TSI_OK);
    EXPECT_NE(protector, nullptr);
    tsi_zero_copy_grpc_protector_destroy(protector);
  }

  tsi_handshaker_result_destroy(*handshake_result);
}

TEST(S2ATsiHandshakerResultTest, ExtractPeer) {
  absl::StatusOr<tsi_handshaker_result*> handshake_result =
      CreateS2ATsiHandshakerResult(
          s2a_proxy::CreateTestProxy(/*has_handshake_result=*/true,
                                     /*is_client=*/true));
  EXPECT_TRUE(handshake_result.ok());
  EXPECT_NE(*handshake_result, nullptr);

  tsi_peer peer;
  EXPECT_EQ(tsi_handshaker_result_extract_peer(*handshake_result, &peer),
            TSI_OK);

  const tsi_peer_property* certificate_type_property =
      tsi_peer_get_property_by_name(&peer, TSI_CERTIFICATE_TYPE_PEER_PROPERTY);
  EXPECT_NE(certificate_type_property, nullptr);
  EXPECT_EQ(PeerPropertyToString(certificate_type_property),
            kTsiS2ACertificateType);

  const tsi_peer_property* peer_identity_property =
      tsi_peer_get_property_by_name(&peer, kTsiS2APeerIdentityPeerProperty);
  EXPECT_NE(peer_identity_property, nullptr);
  EXPECT_EQ(PeerPropertyToString(peer_identity_property),
            s2a_proxy::CreateTestContext()->PeerIdentity().GetIdentityString());

  const tsi_peer_property* security_level_property =
      tsi_peer_get_property_by_name(&peer, TSI_SECURITY_LEVEL_PEER_PROPERTY);
  EXPECT_NE(security_level_property, nullptr);
  EXPECT_EQ(PeerPropertyToString(security_level_property),
            tsi_security_level_to_string(TSI_PRIVACY_AND_INTEGRITY));

  const tsi_peer_property* s2a_context_property =
      tsi_peer_get_property_by_name(&peer, kTsiS2AContext);
  EXPECT_NE(s2a_context_property, nullptr);

  tsi_peer_destruct(&peer);
  tsi_handshaker_result_destroy(*handshake_result);
}

}  // namespace
}  // namespace tsi
}  // namespace s2a

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  grpc_init();
  int ret = RUN_ALL_TESTS();
  grpc_shutdown();
  return ret;
}
