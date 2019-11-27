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

#ifndef GRPC_CORE_LIB_SECURITY_CREDENTIALS_S2A_GRPC_S2A_CREDENTIALS_OPTIONS_H
#define GRPC_CORE_LIB_SECURITY_CREDENTIALS_S2A_GRPC_S2A_CREDENTIALS_OPTIONS_H

#include <grpc/grpc_security.h>
#include <grpc/support/port_platform.h>
#include <vector>
#include "src/core/tsi/s2a/s2a_constants.h"

namespace experimental {

struct grpc_s2a_credentials_options {
 public:
  ~grpc_s2a_credentials_options();

  /** Setter methods. They do not take ownership of the arguments, nor do they
   * remove a duplicate ciphersuite or target service account from the
   * appropriate vector, if a duplicate exists. **/
  void set_handshaker_service_url(const char* handshaker_service_url);
  void add_supported_ciphersuite(uint16_t ciphersuite);
  /** This API should only be called at the client-side. Any target service
   *  accounts that are added on the server-side will be ignored. **/
  void add_target_service_account(const char* target_service_account);

  /** Create a deep copy of this grpc_s2a_credentials_options instance. **/
  grpc_s2a_credentials_options* copy() const;

  /** This method returns true if the fields of this
   *  grpc_s2a_credentials_options instance match the arguments; otherwise, it
   *  returns false. It is used only for testing purposes. **/
  bool check_fields(const char* handshaker_service_url,
                    const std::vector<uint16_t>& supported_ciphersuites,
                    const std::vector<char*>& target_service_account_list);

 private:
  char* handshaker_service_url_;
  std::vector<uint16_t> supported_ciphersuites_;
  std::vector<char*> target_service_account_list_;
};

}  // namespace experimental

#endif  // GRPC_CORE_LIB_SECURITY_CREDENTIALS_S2A_GRPC_S2A_CREDENTIALS_OPTIONS_H
