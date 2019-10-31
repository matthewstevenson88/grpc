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

namespace experimental {

enum s2a_supported_ciphersuite {
  AES_128_GCM_SHA256 = 0,
  AES_256_GCM_SHA384 = 1,
  CHACHA20_POLY1305_SHA256 = 2,
};

/** An ordered list of ciphersuites for use by the S2A. **/
typedef struct s2a_ciphersuite {
  struct s2a_ciphersuite* next;
  s2a_supported_ciphersuite cipher;
} s2a_ciphersuite;

/** The V-table for the grpc_s2a_credentials_options. **/
typedef struct grpc_s2a_credentials_options_vtable {
  grpc_s2a_credentials_options* (*copy)(
      const grpc_s2a_credentials_options* options);
  void (*destruct)(grpc_s2a_credentials_options* options);
} grpc_s2a_credentials_options_vtable;

/** The base struct for the S2A credentials options. The options contain an
 *  ordered list of S2A ciphersuites; if |ciphersuite_head| is nullptr, then the
 *  AES-128-GCM-SHA256 ciphersuite is selected by default. **/
struct grpc_s2a_credentials_options {
  const struct grpc_s2a_credentials_options_vtable* vtable;
  s2a_ciphersuite* ciphersuite_head;
};

/** An ordered list of target service accounts used for secure naming check. **/
typedef struct target_service_account {
  struct target_service_account* next;
  char* data;
} target_service_account;

/** The main struct for the S2A client credentials options. The options contain
 *  an ordered list of target service accounts (if specified) used for secure
 *  naming check. **/
typedef struct grpc_s2a_credentials_client_options {
  grpc_s2a_credentials_options base;
  target_service_account* target_account_list_head;
} grpc_s2a_credentials_client_options;

/** The main struct for the S2A server credentials options. The options
 *  currently do not contain any server-specific fields. **/
typedef struct grpc_s2a_credentials_server_options {
  grpc_s2a_credentials_options base;
} grpc_s2a_credentials_server_options;

/** This method performs a deep copy on the grpc_s2a_credentials_options
 *  instance.
 *  - options: a grpc_s2a_credentials_options instance to be copied.
 *
 *  On success, it returns a new grpc_s2a_credentials_options instance;
 *  otherwise, the method returns nullptr. **/
grpc_s2a_credentials_options* grpc_s2a_credentials_options_copy(
    const grpc_s2a_credentials_options* options);

/** This method adds a ciphersuite to the head of the ordered list of
 *  ciphersuites supported by the S2A credentials options instance.
 *  - options: a grpc_s2a_credentials_options instance.
 *  - ciphersuite: an s2a_supported_ciphersuite. **/
void grpc_s2a_credentials_options_add_ciphersuite(
    grpc_s2a_credentials_options* options,
    s2a_supported_ciphersuite ciphersuite);

}  // namespace experimental

#endif  // GRPC_CORE_LIB_SECURITY_CREDENTIALS_S2A_GRPC_S2A_CREDENTIALS_OPTIONS_H
