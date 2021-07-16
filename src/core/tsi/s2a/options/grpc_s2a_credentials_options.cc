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

#include <grpc/support/log.h>

#include "src/core/tsi/s2a/s2a_security.h"

namespace {

using Ciphersuite = ::s2a::s2a_options::S2AOptions::Ciphersuite;
using Identity = ::s2a::s2a_options::S2AOptions::Identity;
using IdentityType = ::s2a::s2a_options::S2AOptions::IdentityType;
using TlsVersion = ::s2a::s2a_options::S2AOptions::TlsVersion;

}  // namespace

grpc_s2a_credentials_options* grpc_s2a_credentials_options_create() {
  return new grpc_s2a_credentials_options();
}

void grpc_s2a_credentials_options_destroy(
    grpc_s2a_credentials_options* options) {
  if (options == nullptr) {
    return;
  }
  delete options;
  options = nullptr;
}

void grpc_s2a_credentials_options_set_s2a_address(
    grpc_s2a_credentials_options* options, const char* s2a_address) {
  GPR_ASSERT(options != nullptr && s2a_address != nullptr);
  options->s2a_options.set_s2a_address(s2a_address);
}

void grpc_s2a_credentials_options_add_supported_ciphersuite(
    grpc_s2a_credentials_options* options, int ciphersuite) {
  GPR_ASSERT(options != nullptr);
  Ciphersuite tls_ciphersuite;
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      tls_ciphersuite = Ciphersuite::AES_128_GCM_SHA256;
      break;
    case kTlsAes256GcmSha384:
      tls_ciphersuite = Ciphersuite::AES_256_GCM_SHA384;
      break;
    case kTlsChacha20Poly1305Sha256:
      tls_ciphersuite = Ciphersuite::CHACHA20_POLY1305_SHA256;
      break;
    default:
      gpr_log(GPR_INFO, "TLS ciphersuite %d is not supported.", ciphersuite);
      return;
  }
  options->s2a_options.add_supported_ciphersuite(tls_ciphersuite);
}

void grpc_s2a_credentials_options_add_local_spiffe_id(
    grpc_s2a_credentials_options* options, const char* spiffe_id) {
  GPR_ASSERT(options != nullptr && spiffe_id != nullptr);
  options->s2a_options.add_local_spiffe_id(spiffe_id);
}

void grpc_s2a_credentials_options_add_local_hostname(
    grpc_s2a_credentials_options* options, const char* hostname) {
  GPR_ASSERT(options != nullptr && hostname != nullptr);
  options->s2a_options.add_local_hostname(hostname);
}

void grpc_s2a_credentials_options_add_target_spiffe_id(
    grpc_s2a_credentials_options* options, const char* spiffe_id) {
  GPR_ASSERT(options != nullptr && spiffe_id != nullptr);
  options->s2a_options.add_target_spiffe_id(spiffe_id);
}

void grpc_s2a_credentials_options_add_target_hostname(
    grpc_s2a_credentials_options* options, const char* hostname) {
  GPR_ASSERT(options != nullptr && hostname != nullptr);
  options->s2a_options.add_target_hostname(hostname);
}
