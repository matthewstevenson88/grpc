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

#include <grpc/grpc.h>
#include <grpc/support/log.h>

#include <grpc/grpc_security.h>
#include "src/core/lib/security/credentials/s2a/grpc_s2a_credentials_options.h"
#include "src/core/tsi/s2a/s2a_constants.h"

namespace experimental {

static void s2a_test_create_and_copy_options() {
  std::string handshaker_service_url = "handshaker_service_url";
  std::vector<uint16_t> ciphersuites = {
      kTlsAes128GcmSha256, kTlsAes256GcmSha384, kTlsChacha20Poly1305Sha256};
  std::vector<std::string> target_service_account_list;
  std::string service_account_1 = "target_service_account_1";
  std::string service_account_2 = "target_service_account_2";
  target_service_account_list.push_back(service_account_1);
  target_service_account_list.push_back(service_account_2);

  grpc_s2a_credentials_options* options = grpc_s2a_credentials_options_create();
  options->SetHandshakerServiceUrl(handshaker_service_url);
  options->AddSupportedCiphersuite(kTlsAes128GcmSha256);
  options->AddSupportedCiphersuite(kTlsAes256GcmSha384);
  options->AddSupportedCiphersuite(kTlsChacha20Poly1305Sha256);
  options->AddTargetServiceAccount(service_account_1);
  options->AddTargetServiceAccount(service_account_2);
  grpc_s2a_credentials_options* copy_options = options->Copy();

  GPR_ASSERT(options->CheckFieldsForTesting(
      handshaker_service_url, ciphersuites, target_service_account_list));
  GPR_ASSERT(copy_options->CheckFieldsForTesting(
      handshaker_service_url, ciphersuites, target_service_account_list));

  grpc_s2a_credentials_options_destroy(options);
  grpc_s2a_credentials_options_destroy(copy_options);
}

}  // namespace experimental

int main(int argc, char** argv) {
  experimental::s2a_test_create_and_copy_options();
  return 0;
}
