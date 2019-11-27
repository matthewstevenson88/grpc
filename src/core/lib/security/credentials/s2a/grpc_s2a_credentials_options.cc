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

#include "src/core/lib/security/credentials/s2a/grpc_s2a_credentials_options.h"

#include <grpc/support/alloc.h>
#include <grpc/support/log.h>
#include <grpc/support/string_util.h>
#include <string.h>

#include <iostream>

namespace experimental {

grpc_s2a_credentials_options::~grpc_s2a_credentials_options() {
  if (handshaker_service_url_ != nullptr) {
    gpr_free(handshaker_service_url_);
  }
  for (auto service_account : target_service_account_list_) {
    gpr_free(service_account);
  }
}

void grpc_s2a_credentials_options::set_handshaker_service_url(
    const char* handshaker_service_url) {
  if (handshaker_service_url_ != nullptr) {
    gpr_free(handshaker_service_url_);
  }
  handshaker_service_url_ = gpr_strdup(handshaker_service_url);
}

void grpc_s2a_credentials_options::add_supported_ciphersuite(
    uint16_t ciphersuite) {
  supported_ciphersuites_.push_back(ciphersuite);
}

void grpc_s2a_credentials_options::add_target_service_account(
    const char* target_service_account) {
  char* service_account = gpr_strdup(target_service_account);
  target_service_account_list_.push_back(service_account);
}

grpc_s2a_credentials_options* grpc_s2a_credentials_options::copy() const {
  grpc_s2a_credentials_options* new_options =
      new grpc_s2a_credentials_options();
  if (handshaker_service_url_ != nullptr) {
    new_options->set_handshaker_service_url(handshaker_service_url_);
  }
  for (auto ciphersuite : supported_ciphersuites_) {
    new_options->add_supported_ciphersuite(ciphersuite);
  }
  for (auto service_account : target_service_account_list_) {
    new_options->add_target_service_account(service_account);
  }
  return new_options;
}

bool grpc_s2a_credentials_options::check_fields(
    const char* handshaker_service_url,
    const std::vector<uint16_t>& supported_ciphersuites,
    const std::vector<char*>& target_service_account_list) {
  if (strcmp(handshaker_service_url_, handshaker_service_url) != 0) {
    return false;
  }
  if (supported_ciphersuites != supported_ciphersuites_) {
    return false;
  }
  if (target_service_account_list.size() !=
      target_service_account_list_.size()) {
    return false;
  }
  for (size_t i = 0; i < target_service_account_list.size(); i++) {
    if (strcmp(target_service_account_list[i],
               target_service_account_list_[i]) != 0) {
      return false;
    }
  }
  return true;
}

grpc_s2a_credentials_options* grpc_s2a_credentials_options_create(void) {
  return new grpc_s2a_credentials_options();
}

void grpc_s2a_credentials_options_destroy(
    grpc_s2a_credentials_options* options) {
  if (options == nullptr) {
    return;
  }
  delete options;
}

}  // namespace experimental
