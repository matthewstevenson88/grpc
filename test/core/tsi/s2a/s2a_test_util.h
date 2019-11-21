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
#include <vector>
#include "src/core/tsi/s2a/record_protocol/s2a_crypter.h"

/** This method verifies that the in and out half connections of |crypter| are
 *  what is expected from an s2a_crypter instance with ciphersuite |ciphersuite|
 *  and whose in and out traffic secret is |expected_traffic_secret|. **/
void verify_half_connections(uint16_t ciphersuite, s2a_crypter* crypter,
                             std::vector<uint8_t>& expected_traffic_secret);

/** This method returns the size of a TLS 1.3 record created by encrypting a
 *  plaintext of size |plaintext_size|. **/
size_t expected_message_size(size_t plaintext_size);

/** This method populates the |bytes| buffer with |length| randomly-generated
 *  bytes. The |bytes| buffer is owned by the caller. **/
void random_array(uint8_t* bytes, size_t length);

/** This method encrypts |plaintext| using |crypter|, writes the resulting TLs
 *  1.3 record to |record|, and verifies that the TLS 1.3 record has the
 *  expected size. **/
void encrypt_plaintext_and_verify_size(s2a_crypter* crypter,
                                       std::vector<uint8_t>& plaintext,
                                       std::vector<uint8_t>& record,
                                       size_t* record_size,
                                       char** error_details);

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
 *  - in any other case, the method returns false. **/
bool check_encrypt_record(uint16_t ciphersuite,
                          std::vector<uint8_t>& record_one,
                          std::vector<uint8_t>& record_two,
                          std::vector<uint8_t>& record_three);

/** This method returns true if |record| and |record_size| match the TLS 1.3
 *  record obtained from an empty plaintext and using a crypter configured by
 *  the output of the |create_example_session_state| method. Otherwise, this
 *  method returns false. **/
bool check_record_empty_plaintext(uint16_t ciphersuite,
                                  std::vector<uint8_t>& record);

/** This method generates a random message of size |message_size|, encrypts this
 *  message using |out_crypter|, decrypts this message using |in_crypter|, and
 *  then verifies that the decrypted message coincides with the original. **/
void send_random_message(size_t message_size, s2a_crypter* out_crypter,
                         s2a_crypter* in_crypter);

/** This method populates |crypter_one| and |crypter_two| with compatible,
 *  random crypters that use |ciphersuite|. **/
grpc_status_code create_random_crypter_pair(uint16_t ciphersuite,
                                            s2a_crypter** crypter_one,
                                            s2a_crypter** crypter_two,
                                            grpc_channel* channel);

#endif  //  GRPC_TEST_CORE_TSI_S2A_S2A_TEST_UTIL_H
