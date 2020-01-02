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

#include "test/core/tsi/s2a/s2a_test_util.h"
#include <grpc/support/log.h>
#include <grpc/support/string_util.h>
#include <openssl/ssl3.h>
#include <stdlib.h>
#include "src/core/tsi/s2a/record_protocol/s2a_crypter.h"
#include "src/core/tsi/s2a/record_protocol/s2a_crypter_util.h"
#include "src/core/tsi/s2a/s2a_constants.h"
#include "test/core/tsi/s2a/s2a_test_data.h"

void verify_half_connections(uint16_t ciphersuite, s2a_crypter* crypter,
                             std::vector<uint8_t>& expected_traffic_secret) {
  GPR_ASSERT(crypter != nullptr);
  uint8_t* expected_nonce = nullptr;
  size_t expected_nonce_size;
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      expected_nonce = s2a_test_data::aes_128_gcm_nonce_bytes.data();
      expected_nonce_size = s2a_test_data::aes_128_gcm_nonce_bytes.size();
      break;
    case kTlsAes256GcmSha384:
      expected_nonce = s2a_test_data::aes_256_gcm_nonce_bytes.data();
      expected_nonce_size = s2a_test_data::aes_256_gcm_nonce_bytes.size();
      break;
    case kTlsChacha20Poly1305Sha256:
      expected_nonce = s2a_test_data::chacha_poly_nonce_bytes.data();
      expected_nonce_size = s2a_test_data::chacha_poly_nonce_bytes.size();
      break;
    default:
      gpr_log(GPR_ERROR, kS2AUnsupportedCiphersuite);
      abort();
  }
  check_half_connection_for_testing(crypter, /* in_half_connection=*/true,
                                    /* expected_sequence=*/0,
                                    expected_traffic_secret.size(),
                                    expected_traffic_secret.data(),
                                    /* verify_nonce=*/true, expected_nonce_size,
                                    expected_nonce, SSL3_RT_HEADER_LENGTH);
  check_half_connection_for_testing(crypter, /* in_half_connection=*/true,
                                    /* expected_sequence=*/0,
                                    expected_traffic_secret.size(),
                                    expected_traffic_secret.data(),
                                    /* verify_nonce=*/true, expected_nonce_size,
                                    expected_nonce, SSL3_RT_HEADER_LENGTH);
}

size_t expected_message_size(size_t plaintext_size) {
  /** This is the expected size of any TLS 1.3 record. It is independent of the
   *  TLS ciphersuite that is used. **/
  return 5u /* header */ + plaintext_size + 16u /* tag */ +
         1u /* record type */;
}

void encrypt_plaintext_and_verify_size(s2a_crypter* crypter,
                                       std::vector<uint8_t>& plaintext,
                                       std::vector<uint8_t>& record,
                                       size_t* record_size,
                                       char** error_details) {
  grpc_status_code status =
      s2a_encrypt(crypter, plaintext.data(), plaintext.size(), record.data(),
                  record.size(), record_size, error_details);
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(*record_size == expected_message_size(plaintext.size()));
  GPR_ASSERT(*error_details == nullptr);
}

bool check_encrypt_record(uint16_t ciphersuite,
                          std::vector<uint8_t>& record_one,
                          std::vector<uint8_t>& record_two,
                          std::vector<uint8_t>& record_three) {
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      GPR_ASSERT(record_one == s2a_test_data::aes_128_gcm_record_one_bytes);
      break;
    case kTlsAes256GcmSha384:
      GPR_ASSERT(record_one == s2a_test_data::aes_256_gcm_record_one_bytes);
      break;
    case kTlsChacha20Poly1305Sha256:
      GPR_ASSERT(record_one == s2a_test_data::chacha_poly_record_one_bytes);
      break;
  }
  if (record_two.empty() && record_three.empty()) {
    return true;
  }
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      GPR_ASSERT(record_two == s2a_test_data::aes_128_gcm_record_two_bytes);
      break;
    case kTlsAes256GcmSha384:
      GPR_ASSERT(record_two == s2a_test_data::aes_256_gcm_record_two_bytes);
      break;
    case kTlsChacha20Poly1305Sha256:
      GPR_ASSERT(record_two == s2a_test_data::chacha_poly_record_two_bytes);
      break;
  }
  if (record_three.empty()) {
    return true;
  }
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      GPR_ASSERT(record_three == s2a_test_data::aes_128_gcm_record_three_bytes);
      break;
    case kTlsAes256GcmSha384:
      GPR_ASSERT(record_three == s2a_test_data::aes_256_gcm_record_three_bytes);
      break;
    case kTlsChacha20Poly1305Sha256:
      GPR_ASSERT(record_three == s2a_test_data::chacha_poly_record_three_bytes);
      break;
  }
  return true;
}

bool check_record_empty_plaintext(uint16_t ciphersuite,
                                  std::vector<uint8_t>& record) {
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      GPR_ASSERT(record == s2a_test_data::aes_128_gcm_empty_record_bytes);
      break;
    case kTlsAes256GcmSha384:
      GPR_ASSERT(record == s2a_test_data::aes_256_gcm_empty_record_bytes);
      break;
    case kTlsChacha20Poly1305Sha256:
      GPR_ASSERT(record == s2a_test_data::chacha_poly_empty_record_bytes);
      break;
  }
  return true;
}

void send_message(std::vector<uint8_t>& message, s2a_crypter* out_crypter,
                  s2a_crypter* in_crypter) {
  GPR_ASSERT(out_crypter != nullptr && in_crypter != nullptr);
  GPR_ASSERT(out_crypter != in_crypter);
  size_t max_record_overhead;
  char* error_details = nullptr;
  grpc_status_code max_overhead_status = s2a_max_record_overhead(
      *out_crypter, &max_record_overhead, &error_details);
  if (max_overhead_status != GRPC_STATUS_OK) {
    gpr_log(GPR_ERROR, "%s", error_details);
    gpr_free(error_details);
  }
  GPR_ASSERT(max_overhead_status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);
  GPR_ASSERT(message.size() <= SSL3_RT_MAX_PLAIN_LENGTH + max_record_overhead);

  size_t record_allocated_size = message.size() + max_record_overhead;
  std::vector<uint8_t> record(record_allocated_size, 0);
  size_t record_size;

  grpc_status_code encrypt_status =
      s2a_encrypt(out_crypter, message.data(), message.size(), record.data(),
                  record.size(), &record_size, &error_details);
  GPR_ASSERT(encrypt_status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);
  GPR_ASSERT(record_size == expected_message_size(message.size()));

  size_t plaintext_allocated_size;
  grpc_status_code plaintext_status = s2a_max_plaintext_size(
      *in_crypter, record_size, &plaintext_allocated_size, &error_details);
  if (plaintext_status != GRPC_STATUS_OK) {
    gpr_log(GPR_ERROR, "%s", error_details);
    gpr_free(error_details);
  }
  GPR_ASSERT(plaintext_status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);
  std::vector<uint8_t> plaintext(plaintext_allocated_size, 0);
  size_t plaintext_size;
  S2ADecryptStatus decrypt_status =
      s2a_decrypt(in_crypter, record.data(), record_size, plaintext.data(),
                  plaintext.size(), &plaintext_size, &error_details);
  GPR_ASSERT(decrypt_status == S2ADecryptStatus::OK);
  GPR_ASSERT(error_details == nullptr);

  GPR_ASSERT(plaintext_size == message.size());
  plaintext.resize(plaintext_size);
  GPR_ASSERT(plaintext == message);
}
