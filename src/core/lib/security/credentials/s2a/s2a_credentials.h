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

#ifndef GRPC_CORE_LIB_SECURITY_CREDENTIALS_S2A_S2A_CREDENTIALS_H
#define GRPC_CORE_LIB_SECURITY_CREDENTIALS_S2A_S2A_CREDENTIALS_H

#include <grpc/grpc_security.h>
#include <grpc/support/port_platform.h>
#include "src/core/lib/security/credentials/credentials.h"

namespace grpc_core {
namespace experimental {

typedef struct grpc_s2a_credentials_options grpc_s2a_credentials_options;

/** The main client-side struct for securing a gRPC connection using S2A. **/
class grpc_s2a_credentials final : public grpc_channel_credentials {
 public:
  grpc_s2a_credentials(const grpc_s2a_credentials_options* options,
                       const char* handshaker_service_url);
  ~grpc_s2a_credentials() override;

  grpc_core::RefCountedPtr<grpc_channel_security_connector>
  create_security_connector(
      grpc_core::RefCountedPtr<grpc_call_credentials> call_creds,
      const char* target_name, const grpc_channel_args* args,
      grpc_channel_args** new_args) override;

  const grpc_s2a_credentials_options* options() const { return options_; }
  grpc_s2a_credentials_options* mutable_options() { return options_; }
  const char* handshaker_service_url() const { return handshaker_service_url_; }

 private:
  grpc_s2a_credentials_options* options_;
  char* handshaker_service_url_;
};

/** The main server-side struct for securing a gRPC connection using S2A. **/
class grpc_s2a_server_credentials final : public grpc_server_credentials {
 public:
  grpc_s2a_server_credentials(const grpc_s2a_credentials_options* options,
                              const char* handshaker_service_url);
  ~grpc_s2a_server_credentials() override;

  grpc_core::RefCountedPtr<grpc_server_security_connector>
  create_security_connector() override;

  const grpc_s2a_credentials_options* options() const { return options_; }
  grpc_s2a_credentials_options* mutable_options() { return options_; }
  const char* handshaker_service_url() const { return handshaker_service_url_; }

 private:
  grpc_s2a_credentials_options* options_;
  char* handshaker_service_url_;
};

}  // namespace experimental
}  // namespace grpc_core

#endif  // GRPC_CORE_LIB_SECURITY_CREDENTIALS_S2A_S2A_CREDENTIALS_H
