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

#include <grpc/support/port_platform.h>

#include "src/core/lib/security/security_connector/s2a/s2a_security_connector.h"

#include <grpc/grpc.h>
#include <grpc/support/alloc.h>
#include <grpc/support/log.h>
#include <grpc/support/string_util.h>

#include "src/core/lib/gprpp/ref_counted_ptr.h"
#include "src/core/lib/security/credentials/s2a/s2a_credentials.h"
#include "src/core/lib/security/transport/security_handshaker.h"
#include "src/core/lib/slice/slice_internal.h"
#include "src/core/lib/transport/transport.h"
#include "src/core/tsi/transport_security.h"

namespace experimental {

namespace {

/** The S2A channel security connector. **/
class grpc_s2a_channel_security_connector final
    : public grpc_channel_security_connector {
 public:
  grpc_s2a_channel_security_connector(
      grpc_core::RefCountedPtr<grpc_channel_credentials> channel_creds,
      grpc_core::RefCountedPtr<grpc_call_credentials> request_metadata_creds,
      const char* target_name)
      : grpc_channel_security_connector(/** url_scheme= **/ nullptr,
                                        std::move(channel_creds),
                                        std::move(request_metadata_creds)),
        target_name_(gpr_strdup(target_name)) {
    // TODO(mattstev): implement.
  }

  ~grpc_s2a_channel_security_connector() override { gpr_free(target_name_); }

  void add_handshakers(
      const grpc_channel_args* args, grpc_pollset_set* interested_parties,
      grpc_core::HandshakeManager* handshake_manager) override {
    // TODO(mattstev): implement.
    return;
  }

  void check_peer(tsi_peer peer, grpc_endpoint* ep,
                  grpc_core::RefCountedPtr<grpc_auth_context>* auth_context,
                  grpc_closure* on_peer_checked) override {
    // TODO(mattstev): implement.
    return;
  }

  int cmp(const grpc_security_connector* other_sc) const override {
    // TODO(mattstev): implement.
    return 0;
  }

  bool check_call_host(grpc_core::StringView host,
                       grpc_auth_context* auth_context,
                       grpc_closure* on_call_host_checked,
                       grpc_error** error) override {
    // TODO(mattstev): implement.
    return false;
  }

  void cancel_check_call_host(grpc_closure* on_call_host_checked,
                              grpc_error* error) override {
    // TODO(mattstev): implement.
    return;
  }

 private:
  char* target_name_;
};

/** The S2A server security connector. **/
class grpc_s2a_server_security_connector final
    : public grpc_server_security_connector {
 public:
  grpc_s2a_server_security_connector(
      grpc_core::RefCountedPtr<grpc_server_credentials> server_creds)
      : grpc_server_security_connector(/** url_scheme= **/ nullptr,
                                       std::move(server_creds)) {
    // TODO(mattstev): implement.
  }
  ~grpc_s2a_server_security_connector() override = default;

  void add_handshakers(
      const grpc_channel_args* args, grpc_pollset_set* interested_parties,
      grpc_core::HandshakeManager* handshake_manager) override {
    // TODO(mattstev): implement.
    return;
  }

  void check_peer(tsi_peer peer, grpc_endpoint* ep,
                  grpc_core::RefCountedPtr<grpc_auth_context>* auth_context,
                  grpc_closure* on_peer_checked) override {
    // TODO(mattstev): implement.
    return;
  }

  int cmp(const grpc_security_connector* other) const override {
    // TODO(mattstev): implement.
    return 0;
  }
};
}  // namespace

grpc_core::RefCountedPtr<grpc_channel_security_connector>
grpc_s2a_channel_security_connector_create(
    grpc_core::RefCountedPtr<grpc_channel_credentials> channel_creds,
    grpc_core::RefCountedPtr<grpc_call_credentials> request_metadata_creds,
    const char* target_name) {
  if (channel_creds == nullptr || target_name == nullptr) {
    gpr_log(
        GPR_ERROR,
        "Invalid arguments to grpc_s2a_channel_security_connector_create()");
    return nullptr;
  }
  return grpc_core::MakeRefCounted<grpc_s2a_channel_security_connector>(
      std::move(channel_creds), std::move(request_metadata_creds), target_name);
}

grpc_core::RefCountedPtr<grpc_server_security_connector>
grpc_s2a_server_security_connector_create(
    grpc_core::RefCountedPtr<grpc_server_credentials> server_creds) {
  if (server_creds == nullptr) {
    gpr_log(GPR_ERROR,
            "Invalid arguments to grpc_s2a_server_security_connector_create()");
    return nullptr;
  }
  return grpc_core::MakeRefCounted<grpc_s2a_server_security_connector>(
      std::move(server_creds));
}

}  // namespace experimental
