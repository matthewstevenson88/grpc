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

#include "src/core/tsi/s2a/grpc_s2a_credentials_options.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <vector>

#include "s2a/include/s2a_options.h"
#include "src/core/tsi/s2a/s2a_security.h"

namespace {

using Ciphersuite = ::s2a::s2a_options::S2AOptions::Ciphersuite;
using Identity = ::s2a::s2a_options::S2AOptions::Identity;
using IdentityType = ::s2a::s2a_options::S2AOptions::IdentityType;
using TlsVersion = ::s2a::s2a_options::S2AOptions::TlsVersion;

constexpr char kS2AAddress[] = "s2a_address";
constexpr char kLocalSpiffeId[] = "local spiffe id";
constexpr char kLocalHostname[] = "local hostname";
constexpr char kTargetSpiffeId[] = "target spiffe id";
constexpr char kTargetHostname[] = "target hostname";

static std::vector<Ciphersuite> GetCiphersuites() {
  return {Ciphersuite::AES_128_GCM_SHA256, Ciphersuite::AES_256_GCM_SHA384,
          Ciphersuite::CHACHA20_POLY1305_SHA256};
}

static absl::flat_hash_set<Identity> GetLocalIdentities() {
  absl::flat_hash_set<Identity> local_identities;
  local_identities.insert(Identity::FromSpiffeId(kLocalSpiffeId));
  local_identities.insert(Identity::FromHostname(kLocalHostname));
  return local_identities;
}

static absl::flat_hash_set<Identity> GetTargetIdentities() {
  absl::flat_hash_set<Identity> target_identities;
  target_identities.insert(Identity::FromSpiffeId(kTargetSpiffeId));
  target_identities.insert(Identity::FromHostname(kTargetHostname));
  return target_identities;
}

TEST(S2ACredentialsOptionsTest, CreateWithPublicApis) {
  grpc_s2a_credentials_options* options = grpc_s2a_credentials_options_create();
  grpc_s2a_credentials_options_set_s2a_address(options, kS2AAddress);
  grpc_s2a_credentials_options_add_supported_ciphersuite(options,
                                                         kTlsAes128GcmSha256);
  grpc_s2a_credentials_options_add_supported_ciphersuite(options,
                                                         kTlsAes256GcmSha384);
  grpc_s2a_credentials_options_add_supported_ciphersuite(
      options, kTlsChacha20Poly1305Sha256);
  grpc_s2a_credentials_options_add_local_spiffe_id(options, kLocalSpiffeId);
  grpc_s2a_credentials_options_add_local_hostname(options, kLocalHostname);
  grpc_s2a_credentials_options_add_target_spiffe_id(options, kTargetSpiffeId);
  grpc_s2a_credentials_options_add_target_hostname(options, kTargetHostname);

  EXPECT_EQ(options->s2a_options.s2a_address(), kS2AAddress);
  EXPECT_EQ(options->s2a_options.min_tls_version(), TlsVersion::TLS1_3);
  EXPECT_EQ(options->s2a_options.max_tls_version(), TlsVersion::TLS1_3);
  EXPECT_EQ(options->s2a_options.supported_ciphersuites(), GetCiphersuites());
  EXPECT_EQ(options->s2a_options.local_identities(), GetLocalIdentities());
  EXPECT_EQ(options->s2a_options.target_identities(), GetTargetIdentities());

  grpc_s2a_credentials_options_destroy(options);
}

TEST(S2ACredentialsOptionsTest, UnsupportedCiphersuite) {
  grpc_s2a_credentials_options* options = grpc_s2a_credentials_options_create();
  grpc_s2a_credentials_options_add_supported_ciphersuite(options,
                                                         /*ciphersuite=*/0);

  EXPECT_TRUE(options->s2a_options.supported_ciphersuites().empty());

  grpc_s2a_credentials_options_destroy(options);
}

}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  grpc_init();
  int ret = RUN_ALL_TESTS();
  grpc_shutdown();
  return ret;
}
