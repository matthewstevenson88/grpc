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

#include <grpc/support/alloc.h>
#include <grpc/support/log.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <vector>
#include "src/core/lib/surface/channel.h"
#include "src/core/tsi/s2a/record_protocol/s2a_crypter.h"
#include "src/core/tsi/s2a/record_protocol/s2a_crypter_util.h"
#include "src/core/tsi/s2a/s2a_constants.h"
#include "test/core/tsi/s2a/s2a_test_data.h"
#include "test/core/tsi/s2a/s2a_test_util.h"

/** The following buffers are obtained by encrypting |decrypt_plaintext_one|
 *  using the crypter constructed in |create_example_session_state| and the
 *  sequence number 0. **/
std::vector<uint8_t> decrypt_plaintext_1 = {'1', '2', '3', '4', '5', '6'};
std::vector<uint8_t> aes_128_gcm_decrypt_record_1 = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0xf2, 0xe4, 0xe4, 0x11, 0xac,
    0x67, 0x60, 0xe4, 0xe3, 0xf0, 0x74, 0xa3, 0x65, 0x74, 0xc4,
    0x5e, 0xe4, 0xc1, 0x90, 0x61, 0x03, 0xdb, 0x0d};
std::vector<uint8_t> aes_256_gcm_decrypt_record_1 = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0x24, 0xef, 0xee, 0x5a, 0xf1,
    0xa6, 0x21, 0x70, 0xad, 0x5a, 0x95, 0xf8, 0x99, 0xd0, 0x38,
    0xb9, 0x65, 0x38, 0x6a, 0x1a, 0x7d, 0xae, 0xd9};
std::vector<uint8_t> chacha_poly_decrypt_record_1 = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0xc9, 0x47, 0xff, 0xa4, 0x70,
    0x30, 0x43, 0x70, 0x33, 0x8b, 0xb0, 0x7c, 0xe4, 0x68, 0xe6,
    0xb8, 0xa0, 0x94, 0x4a, 0x33, 0x8b, 0xa4, 0x02};

/** The following buffers are obtained by encrypting the alert message
 *  {SSL3_AL_WARNING, SSL3_AD_CLOSE_NOTIFY} using the crypter constructed in
 *  |create_example_session_state| and the sequence number 0. **/
std::vector<uint8_t> aes_128_gcm_decrypt_close_notify = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0xc2, 0xd6, 0xc2, 0x45, 0xfb, 0x80, 0x96,
    0x9d, 0xe1, 0xdd, 0x9d, 0x14, 0x49, 0x92, 0x61, 0xb6, 0x77, 0x35, 0xb0};
std::vector<uint8_t> aes_256_gcm_decrypt_close_notify = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0x14, 0xdd, 0xc8, 0xf3, 0xb3, 0x85, 0x66,
    0x60, 0xbb, 0x5a, 0xc8, 0x15, 0x33, 0xc1, 0x57, 0x58, 0x2f, 0x8b, 0x4c};
std::vector<uint8_t> chacha_poly_decrypt_close_notify = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0xf9, 0x75, 0xd9, 0xcb, 0x2f, 0x11, 0x6d,
    0x85, 0xd4, 0xe3, 0x85, 0x9f, 0x52, 0x88, 0xa9, 0xb0, 0x13, 0xd7, 0x78};

/** The following buffers are obtained by encrypting the alert message
 *  {SSL3_AL_WARNING, SSL3_AD_CERTIFICATE_REVOKED} using the crypter
 *  constructed in |create_example_session_state| and the sequence
 *  number 0. **/
std::vector<uint8_t> aes_128_gcm_decrypt_alert_other = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0xc2, 0xfa, 0xc2, 0x3f, 0x99, 0x5c, 0xbe,
    0x79, 0xa8, 0xd1, 0xe4, 0xc8, 0xf0, 0x35, 0x3a, 0xfe, 0xfe, 0xaa, 0xc9};
std::vector<uint8_t> aes_256_gcm_decrypt_alert_other = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0x14, 0xf1, 0xc8, 0x0a, 0xdd, 0x85, 0x19,
    0x3c, 0x95, 0x98, 0x21, 0x9a, 0xe9, 0xdc, 0x26, 0xf2, 0x47, 0x9c, 0xcf};
std::vector<uint8_t> chacha_poly_decrypt_alert_other = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0xf9, 0x59, 0xd9, 0x6f, 0xed, 0x92, 0xbd,
    0xc7, 0xe8, 0x5e, 0x04, 0xe8, 0x6c, 0x19, 0xea, 0xf1, 0x54, 0xb0, 0x52};

/** The following buffers are obtained by encrypting the alert message
 *  {SSL3_AL_WARNING} using the crypter constructed in
 *  |create_example_session_state| and the sequence number 0. **/
std::vector<uint8_t> aes_128_gcm_decrypt_alert_small = {
    0x17, 0x03, 0x03, 0x00, 0x12, 0xc2, 0xc3, 0x51, 0xfc, 0x48, 0xd9, 0xac,
    0x84, 0xfa, 0x16, 0x5a, 0xdc, 0xc9, 0xa2, 0x6f, 0xfb, 0xc3, 0xc7};
std::vector<uint8_t> aes_256_gcm_decrypt_alert_small = {
    0x17, 0x03, 0x03, 0x00, 0x12, 0x14, 0xc8, 0x47, 0x61, 0x02, 0xa4, 0x60,
    0xb5, 0xcf, 0x9e, 0x9b, 0xa5, 0x9e, 0x17, 0x26, 0x21, 0x5c, 0xa9};
std::vector<uint8_t> chacha_poly_decrypt_alert_small = {
    0x17, 0x03, 0x03, 0x00, 0x12, 0xf9, 0x60, 0x6a, 0x83, 0xac, 0x17, 0xb1,
    0x65, 0xa5, 0x1f, 0x3f, 0xe7, 0x64, 0xda, 0x85, 0x60, 0xc7, 0x06};

/** The following vectors are the traffic secret "kkkk...k", with the length
 *  determined by the ciphersuite. **/
std::vector<uint8_t> aes_128_gcm_traffic_secret = {
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b};
std::vector<uint8_t> aes_256_gcm_traffic_secret = {
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b};
std::vector<uint8_t> chacha_poly_traffic_secret = {
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b};

/** The following vectors are the new traffic secret obtaing from "kkkk...k"
 *  after advancing once. **/
std::vector<uint8_t> aes_128_gcm_advanced_traffic_secret = {
    243, 139, 148, 85,  234, 88, 113, 35, 90,  105, 252, 55, 97,  12, 108, 161,
    33,  87,  121, 230, 107, 69, 160, 71, 215, 57,  1,   17, 224, 0,  129, 196};
std::vector<uint8_t> aes_256_gcm_advanced_traffic_secret = {
    1,   108, 131, 93,  182, 100, 190, 181, 82,  106, 155, 179,
    217, 164, 251, 166, 62,  103, 37,  93,  207, 164, 96,  161,
    20,  217, 241, 239, 154, 154, 31,  104, 90,  81,  135, 57,
    245, 87,  208, 230, 111, 219, 137, 189, 175, 162, 98,  87};
std::vector<uint8_t> chacha_poly_advanced_traffic_secret = {
    243, 139, 148, 85,  234, 88, 113, 35, 90,  105, 252, 55, 97,  12, 108, 161,
    33,  87,  121, 230, 107, 69, 160, 71, 215, 57,  1,   17, 224, 0,  129, 196};

static grpc_status_code setup_crypter(uint16_t ciphersuite,
                                      grpc_channel* channel,
                                      s2a_crypter** crypter,
                                      char** error_details) {
  uint8_t* traffic_secret;
  size_t traffic_secret_size;
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      traffic_secret = s2a_test_data::aes_128_gcm_traffic_secret.data();
      traffic_secret_size = s2a_test_data::aes_128_gcm_traffic_secret.size();
      break;
    case kTlsAes256GcmSha384:
      traffic_secret = s2a_test_data::aes_256_gcm_traffic_secret.data();
      traffic_secret_size = s2a_test_data::aes_256_gcm_traffic_secret.size();
      break;
    case kTlsChacha20Poly1305Sha256:
      traffic_secret = s2a_test_data::chacha_poly_traffic_secret.data();
      traffic_secret_size = s2a_test_data::chacha_poly_traffic_secret.size();
      break;
    default:
      gpr_log(GPR_ERROR, kS2AUnsupportedCiphersuite);
      abort();
  }
  return s2a_crypter_create(
      /** tls_version **/ 0, ciphersuite, traffic_secret, traffic_secret_size,
      traffic_secret, traffic_secret_size, channel, crypter, error_details);
}

static void s2a_test_incorrect_tls_version() {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = new grpc_channel();
  char* error_details = nullptr;
  uint8_t in_traffic_secret[32] = "in_traffic_secret";
  uint8_t out_traffic_secret[32] = "out_traffic_secret";
  grpc_status_code status = s2a_crypter_create(
      /** TLS 1.2 **/ 1, kTlsAes128GcmSha256, in_traffic_secret,
      kSha256DigestLength, out_traffic_secret, kSha256DigestLength, channel,
      &crypter, &error_details);
  GPR_ASSERT(status == GRPC_STATUS_FAILED_PRECONDITION);
  GPR_ASSERT(strcmp(error_details, kS2AUnsupportedTlsVersion) == 0);

  // Cleanup.
  gpr_free(error_details);
  delete channel;
}

static void s2a_test_incorrect_key_size() {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = new grpc_channel();
  char* error_details = nullptr;
  std::vector<uint8_t> in_traffic_secret(kSha256DigestLength - 1, 0);
  std::vector<uint8_t> out_traffic_secret(kSha256DigestLength + 1, 0);
  grpc_status_code status = s2a_crypter_create(
      /** TLS 1.3 **/ 0, kTlsAes128GcmSha256, in_traffic_secret.data(),
      in_traffic_secret.size(), out_traffic_secret.data(),
      out_traffic_secret.size(), channel, &crypter, &error_details);
  GPR_ASSERT(status == GRPC_STATUS_FAILED_PRECONDITION);
  GPR_ASSERT(strcmp(error_details, kS2ATrafficSecretSizeMismatch) == 0);

  // Cleanup.
  s2a_crypter_destroy(crypter);
  gpr_free(error_details);
  delete channel;
}

static void s2a_test_create_crypter_success(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = new grpc_channel();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    delete channel;
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  gsec_aead_crypter* in_crypter = s2a_in_aead_crypter_for_testing(crypter);
  gsec_aead_crypter* out_crypter = s2a_out_aead_crypter_for_testing(crypter);
  GPR_ASSERT(in_crypter != nullptr);
  GPR_ASSERT(out_crypter != nullptr);

  size_t in_nonce_size;
  size_t out_nonce_size;
  size_t in_key_size;
  size_t out_key_size;
  size_t in_tag_size;
  size_t out_tag_size;
  size_t correct_key_size = 0;
  size_t correct_nonce_size = 0;
  size_t correct_tag_size = 0;
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      correct_key_size = kTlsAes128GcmSha256KeySize;
      correct_nonce_size = kTlsAes128GcmSha256NonceSize;
      correct_tag_size = kEvpAeadAesGcmTagLength;
      break;
    case kTlsAes256GcmSha384:
      correct_key_size = kTlsAes256GcmSha384KeySize;
      correct_nonce_size = kTlsAes256GcmSha384NonceSize;
      correct_tag_size = kEvpAeadAesGcmTagLength;
      break;
    case kTlsChacha20Poly1305Sha256:
      correct_key_size = kTlsChacha20Poly1305Sha256KeySize;
      correct_nonce_size = kTlsChacha20Poly1305Sha256NonceSize;
      correct_tag_size = kPoly1305TagLength;
      break;
    default:
      gpr_log(GPR_ERROR, kS2AUnsupportedCiphersuite);
      abort();
      break;
  }

  gsec_aead_crypter_nonce_length(in_crypter, &in_nonce_size,
                                 /** error details **/ nullptr);
  GPR_ASSERT(in_nonce_size == correct_nonce_size);
  gsec_aead_crypter_nonce_length(out_crypter, &out_nonce_size,
                                 /** error details **/ nullptr);
  GPR_ASSERT(out_nonce_size == correct_nonce_size);

  gsec_aead_crypter_key_length(in_crypter, &in_key_size,
                               /** error details **/ nullptr);
  gsec_aead_crypter_key_length(out_crypter, &out_key_size,
                               /** error details **/ nullptr);
  GPR_ASSERT(in_key_size == correct_key_size);
  GPR_ASSERT(out_key_size == correct_key_size);

  gsec_aead_crypter_tag_length(in_crypter, &in_tag_size,
                               /** error details **/ nullptr);
  GPR_ASSERT(in_tag_size == correct_tag_size);
  gsec_aead_crypter_tag_length(out_crypter, &out_tag_size,
                               /** error details **/ nullptr);
  GPR_ASSERT(out_tag_size == correct_tag_size);

  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      verify_half_connections(ciphersuite, crypter,
                              s2a_test_data::aes_128_gcm_traffic_secret);
      break;
    case kTlsAes256GcmSha384:
      verify_half_connections(ciphersuite, crypter,
                              s2a_test_data::aes_256_gcm_traffic_secret);
      break;
    case kTlsChacha20Poly1305Sha256:
      verify_half_connections(ciphersuite, crypter,
                              s2a_test_data::chacha_poly_traffic_secret);
      break;
    default:
      gpr_log(GPR_ERROR, kS2AUnsupportedCiphersuite);
      abort();
  }

  // Cleanup.
  s2a_crypter_destroy(crypter);
  delete channel;
}

static void s2a_test_encrypt_record_bad_size(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = new grpc_channel();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    delete channel;
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  /** Test the case when the memory allocated for the record is insufficient.**/
  std::vector<uint8_t> test_plaintext = {'1', '2', '3', '4', '5', '6'};
  size_t max_record_overhead;
  grpc_status_code overhead_status =
      s2a_max_record_overhead(*crypter, &max_record_overhead, &error_details);
  GPR_ASSERT(overhead_status == GRPC_STATUS_OK);
  size_t record_allocated_size =
      test_plaintext.size() - 2 + max_record_overhead;
  std::vector<uint8_t> record(record_allocated_size, 0);
  size_t record_size;
  grpc_status_code insufficient_memory_status = s2a_encrypt(
      crypter, test_plaintext.data(), test_plaintext.size(), record.data(),
      record_allocated_size, &record_size, &error_details);
  GPR_ASSERT(insufficient_memory_status == GRPC_STATUS_FAILED_PRECONDITION);
  GPR_ASSERT(strcmp(error_details, kS2APlaintextInsufficientRecordSize) == 0);
  gpr_free(error_details);
  error_details = nullptr;

  /** Test the case when the size of the plaintext is larger than the TLS 1.3
   *  RFC allows; see https://tools.ietf.org/html/rfc8446#section-5.1 . **/
  std::vector<uint8_t> oversized_plaintext(SSL3_RT_MAX_PLAIN_LENGTH + 1, 0);
  record_allocated_size = oversized_plaintext.size() + max_record_overhead;
  record.resize(record_allocated_size, 0);
  grpc_status_code oversized_plaintext_status = s2a_encrypt(
      crypter, oversized_plaintext.data(), oversized_plaintext.size(),
      record.data(), record_allocated_size, &record_size, &error_details);
  GPR_ASSERT(oversized_plaintext_status == GRPC_STATUS_FAILED_PRECONDITION);
  GPR_ASSERT(strcmp(error_details, kS2APlaintextExceedMaxSize) == 0);

  // Cleanup.
  s2a_crypter_destroy(crypter);
  delete channel;
  gpr_free(error_details);
}

static void s2a_test_encrypt_record_success(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = new grpc_channel();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    delete channel;
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  size_t max_record_overhead;
  grpc_status_code overhead_status =
      s2a_max_record_overhead(*crypter, &max_record_overhead, &error_details);
  GPR_ASSERT(overhead_status == GRPC_STATUS_OK);

  std::vector<uint8_t> test_plaintext = {'1', '2', '3', '4', '5', '6'};
  size_t record_allocated_size = test_plaintext.size() + max_record_overhead;
  std::vector<uint8_t> record(record_allocated_size, 0);
  size_t record_size;
  grpc_status_code encrypt_status = s2a_encrypt(
      crypter, test_plaintext.data(), test_plaintext.size(), record.data(),
      record_allocated_size, &record_size, &error_details);
  GPR_ASSERT(encrypt_status == GRPC_STATUS_OK);
  GPR_ASSERT(record_size == expected_message_size(test_plaintext.size()));

  std::vector<uint8_t> record_2(0, 0);
  std::vector<uint8_t> record_3(0, 0);
  bool correct_encrypted_record =
      check_encrypt_record(ciphersuite, record, record_2, record_3);
  GPR_ASSERT(correct_encrypted_record);
  GPR_ASSERT(error_details == nullptr);

  // Cleanup.
  s2a_crypter_destroy(crypter);
  delete channel;
}

static void s2a_test_encrypt_three_records(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = new grpc_channel();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    delete channel;
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  size_t max_record_overhead;
  grpc_status_code overhead_status =
      s2a_max_record_overhead(*crypter, &max_record_overhead, &error_details);
  GPR_ASSERT(overhead_status == GRPC_STATUS_OK);

  std::vector<uint8_t> test_plaintext_1 = {'1', '2', '3', '4', '5', '6'};
  size_t record_1_allocated_size =
      test_plaintext_1.size() + max_record_overhead;
  std::vector<uint8_t> record_1(record_1_allocated_size, 0);
  size_t record_1_size;
  encrypt_plaintext_and_verify_size(crypter, test_plaintext_1, record_1,
                                    &record_1_size, &error_details);

  std::vector<uint8_t> test_plaintext_2 = {'7', '8', '9', '1', '2',
                                           '3', '4', '5', '6'};
  size_t record_2_allocated_size =
      test_plaintext_2.size() + max_record_overhead;
  std::vector<uint8_t> record_2(record_2_allocated_size, 0);
  size_t record_2_size;
  encrypt_plaintext_and_verify_size(crypter, test_plaintext_2, record_2,
                                    &record_2_size, &error_details);

  std::vector<uint8_t> test_plaintext_3 = {'7', '8', '9', '1'};
  size_t record_3_allocated_size =
      test_plaintext_3.size() + max_record_overhead;
  std::vector<uint8_t> record_3(record_3_allocated_size, 0);
  size_t record_3_size;
  encrypt_plaintext_and_verify_size(crypter, test_plaintext_3, record_3,
                                    &record_3_size, &error_details);

  bool correct_encrypted_record =
      check_encrypt_record(ciphersuite, record_1, record_2, record_3);
  GPR_ASSERT(correct_encrypted_record);
  GPR_ASSERT(error_details == nullptr);

  // Cleanup.
  s2a_crypter_destroy(crypter);
  delete channel;
}

static void s2a_test_encrypt_empty_plaintext(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = new grpc_channel();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    delete channel;
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  size_t max_record_overhead;
  grpc_status_code overhead_status =
      s2a_max_record_overhead(*crypter, &max_record_overhead, &error_details);
  GPR_ASSERT(overhead_status == GRPC_STATUS_OK);

  std::vector<uint8_t> test_plaintext = {};
  size_t record_allocated_size = test_plaintext.size() + max_record_overhead;
  std::vector<uint8_t> record(record_allocated_size, 0);
  size_t record_size;

  /** Encrypt empty plaintext with incorrect plaintext size. **/
  grpc_status_code bad_encrypt_status =
      s2a_encrypt(crypter, test_plaintext.data(), /** plaintext size **/ 1,
                  record.data(), record.size(), &record_size, &error_details);
  GPR_ASSERT(bad_encrypt_status == GRPC_STATUS_INVALID_ARGUMENT);
  GPR_ASSERT(strcmp(error_details, kS2APlaintextNullptr) == 0);
  gpr_free(error_details);
  error_details = nullptr;

  /** Encrypt empty plaintext with correct plaintext size. **/
  grpc_status_code encrypt_status =
      s2a_encrypt(crypter, test_plaintext.data(), test_plaintext.size(),
                  record.data(), record.size(), &record_size, &error_details);
  GPR_ASSERT(encrypt_status == GRPC_STATUS_OK);
  GPR_ASSERT(record_size == expected_message_size(test_plaintext.size()));
  GPR_ASSERT(check_record_empty_plaintext(ciphersuite, record));

  // Cleanup.
  s2a_crypter_destroy(crypter);
  delete channel;
}

static void s2a_test_decrypt_record_success(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = new grpc_channel();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    delete channel;
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  std::vector<uint8_t> record;
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      record = s2a_test_data::aes_128_gcm_decrypt_record_1;
      break;
    case kTlsAes256GcmSha384:
      record = s2a_test_data::aes_256_gcm_decrypt_record_1;
      break;
    case kTlsChacha20Poly1305Sha256:
      record = s2a_test_data::chacha_poly_decrypt_record_1;
      break;
  }

  size_t plaintext_allocated_size;
  grpc_status_code plaintext_status = s2a_max_plaintext_size(
      *crypter, record.size(), &plaintext_allocated_size, &error_details);
  if (plaintext_status != GRPC_STATUS_OK) {
    gpr_log(GPR_ERROR, "%s", error_details);
    gpr_free(error_details);
  }
  GPR_ASSERT(plaintext_status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);
  size_t plaintext_size;
  std::vector<uint8_t> plaintext(plaintext_allocated_size, 0);
  S2ADecryptStatus decrypt_status =
      s2a_decrypt(crypter, record.data(), record.size(), plaintext.data(),
                  plaintext.size(), &plaintext_size, &error_details);
  GPR_ASSERT(decrypt_status == S2ADecryptStatus::OK);
  GPR_ASSERT(error_details == nullptr);
  GPR_ASSERT(plaintext_size == 6);
  plaintext.resize(plaintext_size);
  GPR_ASSERT(plaintext == s2a_test_data::decrypt_plaintext_1);

  // Cleanup.
  s2a_crypter_destroy(crypter);
  delete channel;
}

static void s2a_test_decrypt_record_with_padding(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = new grpc_channel();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    delete channel;
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  std::vector<uint8_t> record;
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      record = s2a_test_data::aes_128_gcm_padded_zeros_record;
      break;
    case kTlsAes256GcmSha384:
      record = s2a_test_data::aes_256_gcm_padded_zeros_record;
      break;
    case kTlsChacha20Poly1305Sha256:
      record = s2a_test_data::chacha_poly_padded_zeros_record;
      break;
  }

  size_t plaintext_allocated_size;
  grpc_status_code plaintext_status = s2a_max_plaintext_size(
      *crypter, record.size(), &plaintext_allocated_size, &error_details);
  if (plaintext_status != GRPC_STATUS_OK) {
    gpr_log(GPR_ERROR, "%s", error_details);
    gpr_free(error_details);
  }
  GPR_ASSERT(plaintext_status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);
  size_t plaintext_size;
  std::vector<uint8_t> plaintext(plaintext_allocated_size, 0);
  S2ADecryptStatus decrypt_status =
      s2a_decrypt(crypter, record.data(), record.size(), plaintext.data(),
                  plaintext.size(), &plaintext_size, &error_details);
  GPR_ASSERT(decrypt_status == S2ADecryptStatus::OK);
  GPR_ASSERT(error_details == nullptr);
  GPR_ASSERT(plaintext_size == 6);
  plaintext.resize(plaintext_size);
  GPR_ASSERT(plaintext == s2a_test_data::message_encrypted_with_padded_zeros);

  // Cleanup.
  s2a_crypter_destroy(crypter);
  delete channel;
}

static void s2a_test_decrypt_large_record(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = new grpc_channel();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    delete channel;
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  /** Construct a TLS record whose plaintext is larger than is allowed. **/
  size_t tag_size;
  gsec_aead_crypter_tag_length(s2a_in_aead_crypter_for_testing(crypter),
                               &tag_size, &error_details);
  size_t oversize_payload_size = /* ciphertext=*/SSL3_RT_MAX_PLAIN_LENGTH +
                                 /* extra=*/15 + /* record type=*/1 + tag_size;
  size_t oversize_record_size = SSL3_RT_HEADER_LENGTH + oversize_payload_size;
  std::vector<uint8_t> oversize_record(oversize_record_size, 0);
  oversize_record[0] = SSL3_RT_APPLICATION_DATA;
  const uint16_t wire_version = static_cast<uint16_t>(TLS1_2_VERSION);
  oversize_record[1] = wire_version >> 8;
  oversize_record[2] = wire_version & 0xff;
  oversize_record[3] = oversize_payload_size >> 8;
  oversize_record[4] = oversize_payload_size & 0xff;

  /** Attempt to decrypt the TLS record with oversized plaintext. **/
  size_t plaintext_allocated_size;
  grpc_status_code plaintext_status =
      s2a_max_plaintext_size(*crypter, oversize_record.size(),
                             &plaintext_allocated_size, &error_details);
  if (plaintext_status != GRPC_STATUS_OK) {
    gpr_log(GPR_ERROR, "%s", error_details);
    gpr_free(error_details);
  }
  GPR_ASSERT(plaintext_status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);
  std::vector<uint8_t> plaintext(plaintext_allocated_size, 0);
  size_t plaintext_size;
  S2ADecryptStatus decrypt_status = s2a_decrypt(
      crypter, oversize_record.data(), oversize_record.size(), plaintext.data(),
      plaintext.size(), &plaintext_size, &error_details);
  GPR_ASSERT(decrypt_status == S2ADecryptStatus::ALERT_RECORD_OVERFLOW);
  GPR_ASSERT(strcmp(error_details, kS2ARecordExceedMaxSize) == 0);

  // Cleanup.
  gpr_free(error_details);
  s2a_crypter_destroy(crypter);
  delete channel;
}

enum class TlsAlertType {
  close_notify,  // A close notify alert.
  other,         // Another valid alert.
  small,         // An improperly formatted alert whose plaintext is too small.
};

static void s2a_test_decrypt_alert(uint16_t ciphersuite,
                                   TlsAlertType alert_type) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = new grpc_channel();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    delete channel;
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  std::vector<uint8_t> record;
  switch (ciphersuite) {
    case kTlsAes128GcmSha256: {
      switch (alert_type) {
        case TlsAlertType::close_notify:
          record = s2a_test_data::aes_128_gcm_decrypt_close_notify;
          break;
        case TlsAlertType::other:
          record = s2a_test_data::aes_128_gcm_decrypt_alert_other;
          break;
        case TlsAlertType::small:
          record = s2a_test_data::aes_128_gcm_decrypt_alert_small;
          break;
      }
    } break;
    case kTlsAes256GcmSha384: {
      switch (alert_type) {
        case TlsAlertType::close_notify:
          record = s2a_test_data::aes_256_gcm_decrypt_close_notify;
          break;
        case TlsAlertType::other:
          record = s2a_test_data::aes_256_gcm_decrypt_alert_other;
          break;
        case TlsAlertType::small:
          record = s2a_test_data::aes_256_gcm_decrypt_alert_small;
          break;
      }
    } break;
    case kTlsChacha20Poly1305Sha256: {
      switch (alert_type) {
        case TlsAlertType::close_notify:
          record = s2a_test_data::chacha_poly_decrypt_close_notify;
          break;
        case TlsAlertType::other:
          record = s2a_test_data::chacha_poly_decrypt_alert_other;
          break;
        case TlsAlertType::small:
          record = s2a_test_data::chacha_poly_decrypt_alert_small;
          break;
      }
    } break;
  }

  size_t plaintext_allocated_size;
  grpc_status_code plaintext_status = s2a_max_plaintext_size(
      *crypter, record.size(), &plaintext_allocated_size, &error_details);
  if (plaintext_status != GRPC_STATUS_OK) {
    gpr_log(GPR_ERROR, "%s", error_details);
    gpr_free(error_details);
  }
  GPR_ASSERT(plaintext_status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);
  size_t plaintext_size;
  std::vector<uint8_t> plaintext(plaintext_allocated_size, 0);
  S2ADecryptStatus decrypt_status =
      s2a_decrypt(crypter, record.data(), record.size(), plaintext.data(),
                  plaintext.size(), &plaintext_size, &error_details);
  switch (alert_type) {
    case TlsAlertType::close_notify:
      GPR_ASSERT(decrypt_status == S2ADecryptStatus::ALERT_CLOSE_NOTIFY);
      break;
    case TlsAlertType::other:
      GPR_ASSERT(decrypt_status == S2ADecryptStatus::ALERT_OTHER);
      break;
    case TlsAlertType::small:
      GPR_ASSERT(decrypt_status == S2ADecryptStatus::INVALID_RECORD);
      GPR_ASSERT(strcmp(error_details, kS2ARecordSmallAlert) == 0);
      gpr_free(error_details);
      break;
  }

  // Cleanup.
  s2a_crypter_destroy(crypter);
  delete channel;
}

static void s2a_test_roundtrips(uint16_t ciphersuite) {
  s2a_crypter* in_crypter = nullptr;
  s2a_crypter* out_crypter = nullptr;
  grpc_channel* channel = new grpc_channel();
  char* error_details = nullptr;
  grpc_status_code in_status =
      setup_crypter(ciphersuite, channel, &in_crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(in_status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(in_crypter);
    gpr_free(error_details);
    delete channel;
    return;
  }
  grpc_status_code out_status =
      setup_crypter(ciphersuite, channel, &out_crypter, &error_details);
  GPR_ASSERT(out_status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  send_message(s2a_test_data::test_message_1, in_crypter, out_crypter);
  send_message(s2a_test_data::test_message_2, out_crypter, in_crypter);
  send_message(s2a_test_data::test_message_3, out_crypter, in_crypter);
  send_message(s2a_test_data::test_message_4, in_crypter, out_crypter);
  send_message(s2a_test_data::test_message_5, out_crypter, in_crypter);

  // Cleanup.
  s2a_crypter_destroy(in_crypter);
  s2a_crypter_destroy(out_crypter);
  delete channel;
}

static void s2a_test_key_update(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = new grpc_channel();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    delete channel;
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  /** Setup for encryption of key update message. **/
  iovec plaintext_vec = {
      reinterpret_cast<void*>(s2a_test_data::key_update_message.data()),
      s2a_test_data::key_update_message.size()};

  size_t max_record_overhead;
  grpc_status_code overhead_status =
      s2a_max_record_overhead(*crypter, &max_record_overhead, &error_details);
  GPR_ASSERT(overhead_status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);
  size_t record_allocated_size =
      s2a_test_data::key_update_message.size() + max_record_overhead;
  std::vector<uint8_t> record(record_allocated_size, 0);
  iovec record_vec = {(void*)record.data(), record.size()};
  size_t record_bytes_written;

  /** Encrypt key update message. **/
  grpc_status_code write_key_update_status = s2a_write_tls13_record(
      crypter, SSL3_RT_HANDSHAKE, &plaintext_vec, /* plaintext_vec length=*/1,
      record_vec, &record_bytes_written, &error_details);
  GPR_ASSERT(write_key_update_status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);
  GPR_ASSERT(record_bytes_written ==
             expected_message_size(s2a_test_data::key_update_message.size()));

  /** Setup for decryption of key update message. **/
  iovec record_header_vec = {record_vec.iov_base, SSL3_RT_HEADER_LENGTH};
  iovec protected_vec = {
      reinterpret_cast<uint8_t*>(record_vec.iov_base) + SSL3_RT_HEADER_LENGTH,
      record.size() - SSL3_RT_HEADER_LENGTH};
  size_t plaintext_size;
  grpc_status_code plaintext_status = s2a_max_plaintext_size(
      *crypter, record_bytes_written, &plaintext_size, &error_details);
  GPR_ASSERT(plaintext_status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);
  std::vector<uint8_t> plaintext(plaintext_size, 0);
  iovec unprotected_vec = {(void*)plaintext.data(), plaintext.size()};
  size_t unprotected_bytes_written;

  /** Decrypt key update message. **/
  S2ADecryptStatus read_key_update_status = s2a_decrypt_record(
      crypter, record_header_vec, &protected_vec, /* protected_vec length=*/1,
      unprotected_vec, &unprotected_bytes_written, &error_details);
  GPR_ASSERT(read_key_update_status == S2ADecryptStatus::OK);
  GPR_ASSERT(error_details == nullptr);
  GPR_ASSERT(unprotected_bytes_written ==
             s2a_test_data::key_update_message.size());

  /** Verify correctness. **/
  uint8_t* expected_traffic_secret;
  size_t expected_traffic_secret_size;
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      expected_traffic_secret = aes_128_gcm_advanced_traffic_secret.data();
      expected_traffic_secret_size = aes_128_gcm_advanced_traffic_secret.size();
      break;
    case kTlsAes256GcmSha384:
      expected_traffic_secret = aes_256_gcm_advanced_traffic_secret.data();
      expected_traffic_secret_size = aes_256_gcm_advanced_traffic_secret.size();
      break;
    case kTlsChacha20Poly1305Sha256:
      expected_traffic_secret = chacha_poly_advanced_traffic_secret.data();
      expected_traffic_secret_size = chacha_poly_advanced_traffic_secret.size();
      break;
  }
  check_half_connection_for_testing(
      crypter, /* in=*/true, /* expected sequence=*/0,
      expected_traffic_secret_size, expected_traffic_secret,
      /* verify_nonce=*/false, /* expected_nonce_size=*/0,
      /* expected_nonce=*/nullptr, SSL3_RT_HEADER_LENGTH);
  plaintext.resize(unprotected_bytes_written);
  GPR_ASSERT(plaintext == s2a_test_data::key_update_message);

  /** Cleanup. **/
  s2a_crypter_destroy(crypter);
  delete channel;
}

int main(int argc, char** argv) {
  s2a_test_incorrect_tls_version();
  s2a_test_incorrect_key_size();
  const size_t number_ciphersuites = 3;
  uint16_t ciphersuite[number_ciphersuites] = {
      kTlsAes128GcmSha256, kTlsAes256GcmSha384, kTlsChacha20Poly1305Sha256};
  const size_t number_alert_types = 3;
  TlsAlertType alert[number_alert_types] = {
      TlsAlertType::close_notify, TlsAlertType::other, TlsAlertType::small};
  for (size_t i = 0; i < number_ciphersuites; i++) {
    s2a_test_create_crypter_success(ciphersuite[i]);
    s2a_test_encrypt_record_bad_size(ciphersuite[i]);
    s2a_test_encrypt_record_success(ciphersuite[i]);
    s2a_test_encrypt_three_records(ciphersuite[i]);
    s2a_test_encrypt_empty_plaintext(ciphersuite[i]);
    s2a_test_decrypt_record_success(ciphersuite[i]);
    s2a_test_decrypt_record_with_padding(ciphersuite[i]);
    s2a_test_decrypt_large_record(ciphersuite[i]);
    for (size_t j = 0; j < number_alert_types; j++) {
      s2a_test_decrypt_alert(ciphersuite[i], alert[j]);
    }
    s2a_test_key_update(ciphersuite[i]);
    s2a_test_roundtrips(ciphersuite[i]);
  }
  return 0;
}
