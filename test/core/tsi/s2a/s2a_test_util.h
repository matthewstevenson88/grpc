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

#ifndef GRPC_TEST_CORE_TSI_S2A_RECORD_PROTOCOL_S2A_TEST_UTIL_H
#define GRPC_TEST_CORE_TSI_S2A_RECORD_PROTOCOL_S2A_TEST_UTIL_H

#include <grpc/grpc.h>
#include <grpc/support/sync.h>
#include "src/core/tsi/s2a/record_protocol/s2a_crypter.h"

enum TLSCiphersuite {
  TLS_AES_128_GCM_SHA256_ciphersuite,
  TLS_AES_256_GCM_SHA384_ciphersuite,
  TLS_CHACHA20_POLY1305_SHA256_ciphersuite,
};

grpc_byte_buffer* create_example_session_state(bool admissible_tls_version,
                                               TLSCiphersuite ciphersuite,
                                               bool has_in_out_key,
                                               bool correct_key_size,
                                               bool has_in_out_sequence,
                                               bool has_in_out_fixed_nonce);

size_t expected_message_size(size_t plaintext_size);

#endif  //  GRPC_TEST_CORE_TSI_S2A_RECORD_PROTOCOL_S2A_TEST_UTIL_H
