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

#include "src/core/lib/security/credentials/s2a/s2a_credentials.h"
#include <grpc/support/port_platform.h>
#include "src/core/lib/security/security_connector/s2a/s2a_security_connector.h"

namespace experimental {

grpc_s2a_credentials::grpc_s2a_credentials(
    const grpc_s2a_credentials_options* options)
    : grpc_channel_credentials(kGrpcS2ACredentialsType) {
  // TODO(mattstev): implement.
}

grpc_s2a_credentials::~grpc_s2a_credentials() {
  // TODO(mattstev): implement.
  return;
}

grpc_core::RefCountedPtr<grpc_channel_security_connector>
grpc_s2a_credentials::create_security_connector(
    grpc_core::RefCountedPtr<grpc_call_credentials> call_creds,
    const char* target_name, const grpc_channel_args* args,
    grpc_channel_args** new_args) {
  return grpc_s2a_channel_security_connector_create(
      this->Ref(), std::move(call_creds), target_name);
}

grpc_s2a_server_credentials::grpc_s2a_server_credentials(
    const grpc_s2a_credentials_options* options)
    : grpc_server_credentials(kGrpcS2ACredentialsType) {
  // TODO(mattstev): implement.
}

grpc_s2a_server_credentials::~grpc_s2a_server_credentials() {
  // TODO(mattstev): implement.
  return;
}

grpc_core::RefCountedPtr<grpc_server_security_connector>
grpc_s2a_server_credentials::create_security_connector() {
  return grpc_s2a_server_security_connector_create(this->Ref());
}

}  // namespace experimental
