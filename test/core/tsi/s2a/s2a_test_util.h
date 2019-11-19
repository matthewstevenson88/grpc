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

#ifndef GRPC_TEST_CORE_TSI_S2A_S2A_TEST_UTIL_H
#define GRPC_TEST_CORE_TSI_S2A_S2A_TEST_UTIL_H

#include <grpc/grpc.h>
#include <grpc/support/sync.h>
#include "src/core/tsi/s2a/record_protocol/s2a_crypter.h"

grpc_byte_buffer* create_example_session_state(bool admissible_tls_version,
                                               uint16_t ciphersuite,
                                               bool has_in_out_key,
                                               bool correct_key_size,
                                               bool has_in_out_sequence,
                                               bool has_in_out_fixed_nonce);

size_t expected_message_size(size_t plaintext_size);

/** This method verifies whether |record_*| and |record_*_size| match the TLS
 *  1.3 record obtained from a particular plaintext and using a crypter
 *  configured by the output of the |create_example_session_state| method. The
 *  three plaintexts are "123456", "789123456", and "7891". The return value of
 *  this method is determined as follows:
 *  - if |record_one| is not nullptr and |record_two| and |record_three| are
 *    nullptr, then the method returns true iff |record_one| matches the first
 *    TLS record;
 *  - if |record_one| and |record_two| are not nullptr and |record_three| is
 *    nullptr, then the method returns true iff |record_one| and |record_two|
 *    match the first two TLS records;
 *  - if all of |record_one|, |record_two|, and |record_three| are not nullptr,
 *    then the method returns true iff they match the first three TLS records;
 *  - in any other case, the method returns false and possibly populates
 *    |error_details|. **/
bool check_encrypt_record(uint16_t ciphersuite, uint8_t* record_one,
                          size_t record_one_size, uint8_t* record_two,
                          size_t record_two_size, uint8_t* record_three,
                          size_t record_three_size, char** error_details);

/** This method returns true if |record| and |record_size| match the TLS 1.3
 *  record obtained from an empty plaintext and using a crypter configured by
 *  the output of the |create_example_session_state| method. Otherwise, this
 *  method returns false. **/
bool check_record_empty_plaintext(uint16_t ciphersuite, uint8_t* record,
                                  size_t record_size, char** error_details);

#endif  //  GRPC_TEST_CORE_TSI_S2A_S2A_TEST_UTIL_H
