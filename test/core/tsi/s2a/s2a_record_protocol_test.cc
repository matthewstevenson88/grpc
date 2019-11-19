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
#include <openssl/ssl3.h>
#include <vector>
#include "src/core/lib/surface/channel.h"
#include "src/core/tsi/s2a/record_protocol/s2a_crypter.h"
#include "src/core/tsi/s2a/record_protocol/s2a_crypter_util.h"
#include "src/core/tsi/s2a/s2a_constants.h"
#include "test/core/tsi/s2a/s2a_test_util.h"

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

static grpc_status_code setup_crypter(uint16_t ciphersuite,
                                      grpc_channel* channel,
                                      s2a_crypter** crypter,
                                      char** error_details) {
  uint8_t* traffic_secret;
  size_t traffic_secret_size;
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      traffic_secret = aes_128_gcm_traffic_secret.data();
      traffic_secret_size = aes_128_gcm_traffic_secret.size();
      break;
    case kTlsAes256GcmSha384:
      traffic_secret = aes_256_gcm_traffic_secret.data();
      traffic_secret_size = aes_256_gcm_traffic_secret.size();
      break;
    case kTlsChacha20Poly1305Sha256:
      traffic_secret = chacha_poly_traffic_secret.data();
      traffic_secret_size = chacha_poly_traffic_secret.size();
      break;
    default:
      gpr_log(GPR_ERROR, kS2AUnsupportedCiphersuite);
      abort();
  }
  return s2a_crypter_create(
      /** tls_version **/ 0, ciphersuite, traffic_secret, traffic_secret_size,
      traffic_secret, traffic_secret_size, channel, crypter, error_details);
}

static void test_incorrect_tls_version() {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  uint8_t in_traffic_secret[32] = "in_traffic_secret";
  uint8_t out_traffic_secret[32] = "out_traffic_secret";
  grpc_status_code status = s2a_crypter_create(
      /** TLS 1.2 **/ 1, kTlsAes128GcmSha256, in_traffic_secret,
      kSha256DigestLength, out_traffic_secret, kSha256DigestLength, channel,
      &crypter, &error_details);
  GPR_ASSERT(status == GRPC_STATUS_FAILED_PRECONDITION);
  int correct_error_message = strcmp(error_details, kS2AUnsupportedTlsVersion);
  GPR_ASSERT(correct_error_message == 0);

  // Cleanup.
  gpr_free(error_details);
  grpc_core::Delete<grpc_channel>(channel);
}

static void test_incorrect_key_size() {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  std::vector<uint8_t> in_traffic_secret(kSha256DigestLength - 1, 0);
  std::vector<uint8_t> out_traffic_secret(kSha256DigestLength + 1, 0);
  grpc_status_code status = s2a_crypter_create(
      /** TLS 1.3 **/ 0, kTlsAes128GcmSha256, in_traffic_secret.data(),
      in_traffic_secret.size(), out_traffic_secret.data(),
      out_traffic_secret.size(), channel, &crypter, &error_details);
  GPR_ASSERT(status == GRPC_STATUS_FAILED_PRECONDITION);
  int correct_error_message =
      strcmp(error_details, kS2ATrafficSecretSizeMismatch);
  GPR_ASSERT(correct_error_message == 0);

  // Cleanup.
  s2a_crypter_destroy(crypter);
  gpr_free(error_details);
  grpc_core::Delete<grpc_channel>(channel);
}

static void test_deserialize_byte_buffer() {
  upb::Arena arena;
  s2a_SessionState* session_state = s2a_SessionState_new(arena.ptr());
  s2a_SessionState_set_in_key(session_state,
                              upb_strview_make("kkkkkkkkkkkkkkkk", 17));
  size_t buf_size;
  char* buf = s2a_SessionState_serialize(session_state, arena.ptr(), &buf_size);
  grpc_slice slice = grpc_slice_from_copied_buffer(buf, buf_size);

  /** Valid serialization. **/
  upb::Arena arena2;
  grpc_byte_buffer* buffer =
      grpc_raw_byte_buffer_create(&slice, /** number of slices **/ 1);
  s2a_SessionState* decoded_session_state = nullptr;
  char* error_details = nullptr;
  grpc_status_code deserialize_status = s2a_deserialize_session_state(
      buffer, arena2.ptr(), &decoded_session_state, &error_details);
  GPR_ASSERT(deserialize_status == GRPC_STATUS_OK);
  int correct_in_key = strcmp(
      s2a_SessionState_in_key(decoded_session_state).data, "kkkkkkkkkkkkkkkk");
  GPR_ASSERT(correct_in_key == 0);
  grpc_byte_buffer_destroy(buffer);

  /** Invalid serialization. **/
  grpc_slice bad_slice =
      grpc_slice_split_head(&slice, GRPC_SLICE_LENGTH(slice) - 1);
  buffer = grpc_raw_byte_buffer_create(&bad_slice, /** number of slices **/ 1);
  s2a_SessionState* bad_session_state = nullptr;
  deserialize_status = s2a_deserialize_session_state(
      buffer, arena2.ptr(), &bad_session_state, &error_details);
  GPR_ASSERT(deserialize_status == GRPC_STATUS_INTERNAL);
  int correct_error_message =
      strcmp(error_details, "The |s2a_SessionState_parse| method failed.");
  GPR_ASSERT(correct_error_message == 0);

  /** Clean up. **/
  gpr_free(error_details);
  grpc_slice_unref(slice);
  grpc_slice_unref(bad_slice);
  grpc_byte_buffer_destroy(buffer);
}

static void test_create_crypter_success(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message =
        strcmp(error_details, kS2AChachaPolyUnimplemented);
    GPR_ASSERT(correct_error_message == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  gsec_aead_crypter* in_crypter = s2a_in_aead_crypter(crypter);
  gsec_aead_crypter* out_crypter = s2a_out_aead_crypter(crypter);
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
      verify_half_connections(ciphersuite, crypter, aes_128_gcm_traffic_secret);
      break;
    case kTlsAes256GcmSha384:
      verify_half_connections(ciphersuite, crypter, aes_256_gcm_traffic_secret);
      break;
    case kTlsChacha20Poly1305Sha256:
      verify_half_connections(ciphersuite, crypter, chacha_poly_traffic_secret);
      break;
    default:
      gpr_log(GPR_ERROR, kS2AUnsupportedCiphersuite);
      abort();
  }

  // Cleanup.
  s2a_crypter_destroy(crypter);
  grpc_core::Delete<grpc_channel>(channel);
}

static void test_encrypt_record_bad_size(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message =
        strcmp(error_details, kS2AChachaPolyUnimplemented);
    GPR_ASSERT(correct_error_message == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  /** Test the case when the memory allocated for the record is insufficient.**/
  std::vector<uint8_t> test_plaintext = {'1', '2', '3', '4', '5', '6'};
  size_t record_allocated_size =
      test_plaintext.size() - 2 + s2a_max_record_overhead(crypter);
  std::vector<uint8_t> record(record_allocated_size, 0);
  size_t record_size;
  grpc_status_code insufficient_memory_status = s2a_encrypt(
      crypter, test_plaintext.data(), test_plaintext.size(), record.data(),
      record_allocated_size, &record_size, &error_details);
  GPR_ASSERT(insufficient_memory_status == GRPC_STATUS_FAILED_PRECONDITION);
  int correct_error_message =
      strcmp(error_details, kS2APlaintextInsufficientRecordSize);
  GPR_ASSERT(correct_error_message == 0);
  gpr_free(error_details);
  error_details = nullptr;

  /** Test the case when the size of the plaintext is larger than the TLS 1.3
   *  RFC allows; see https://tools.ietf.org/html/rfc8446#section-5.1 . **/
  std::vector<uint8_t> oversized_plaintext(SSL3_RT_MAX_PLAIN_LENGTH + 1, 0);
  record_allocated_size =
      oversized_plaintext.size() + s2a_max_record_overhead(crypter);
  record.resize(record_allocated_size, 0);
  grpc_status_code oversized_plaintext_status = s2a_encrypt(
      crypter, oversized_plaintext.data(), oversized_plaintext.size(),
      record.data(), record_allocated_size, &record_size, &error_details);
  GPR_ASSERT(oversized_plaintext_status == GRPC_STATUS_FAILED_PRECONDITION);
  correct_error_message = strcmp(error_details, kS2APlaintextExceedMaxSize);
  GPR_ASSERT(correct_error_message == 0);

  // Cleanup.
  s2a_crypter_destroy(crypter);
  grpc_core::Delete<grpc_channel>(channel);
  gpr_free(error_details);
}

static void test_encrypt_record_success(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message =
        strcmp(error_details, kS2AChachaPolyUnimplemented);
    GPR_ASSERT(correct_error_message == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  std::vector<uint8_t> test_plaintext = {'1', '2', '3', '4', '5', '6'};
  size_t record_allocated_size =
      test_plaintext.size() + s2a_max_record_overhead(crypter);
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
  grpc_core::Delete<grpc_channel>(channel);
}

static void test_encrypt_three_records(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message =
        strcmp(error_details, kS2AChachaPolyUnimplemented);
    GPR_ASSERT(correct_error_message == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  std::vector<uint8_t> test_plaintext_1 = {'1', '2', '3', '4', '5', '6'};
  size_t record_1_allocated_size =
      test_plaintext_1.size() + s2a_max_record_overhead(crypter);
  std::vector<uint8_t> record_1(record_1_allocated_size, 0);
  size_t record_1_size;
  encrypt_plaintext_and_verify_size(crypter, test_plaintext_1, record_1,
                                    &record_1_size, &error_details);

  std::vector<uint8_t> test_plaintext_2 = {'7', '8', '9', '1', '2',
                                           '3', '4', '5', '6'};
  size_t record_2_allocated_size =
      test_plaintext_2.size() + s2a_max_record_overhead(crypter);
  std::vector<uint8_t> record_2(record_2_allocated_size, 0);
  size_t record_2_size;
  encrypt_plaintext_and_verify_size(crypter, test_plaintext_2, record_2,
                                    &record_2_size, &error_details);

  std::vector<uint8_t> test_plaintext_3 = {'7', '8', '9', '1'};
  size_t record_3_allocated_size =
      test_plaintext_3.size() + s2a_max_record_overhead(crypter);
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
  grpc_core::Delete<grpc_channel>(channel);
}

static void test_encrypt_empty_plaintext(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message =
        strcmp(error_details, kS2AChachaPolyUnimplemented);
    GPR_ASSERT(correct_error_message == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  std::vector<uint8_t> test_plaintext = {};
  size_t record_allocated_size =
      test_plaintext.size() + s2a_max_record_overhead(crypter);
  std::vector<uint8_t> record(record_allocated_size, 0);
  size_t record_size;

  /** Encrypt empty plaintext with incorrect plaintext size. **/
  grpc_status_code bad_encrypt_status =
      s2a_encrypt(crypter, test_plaintext.data(), /** plaintext size **/ 1,
                  record.data(), record.size(), &record_size, &error_details);
  GPR_ASSERT(bad_encrypt_status == GRPC_STATUS_INVALID_ARGUMENT);
  int correct_error_message = strcmp(error_details, kS2APlaintextNullptr);
  GPR_ASSERT(correct_error_message == 0);
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
  grpc_core::Delete<grpc_channel>(channel);
}

int main(int argc, char** argv) {
  test_incorrect_tls_version();
  test_incorrect_key_size();
  test_deserialize_byte_buffer();
  const size_t number_ciphersuites = 3;
  uint16_t ciphersuite[number_ciphersuites] = {
      kTlsAes128GcmSha256, kTlsAes256GcmSha384, kTlsChacha20Poly1305Sha256};
  for (size_t i = 0; i < number_ciphersuites; i++) {
    test_create_crypter_success(ciphersuite[i]);
    test_encrypt_record_bad_size(ciphersuite[i]);
    test_encrypt_record_success(ciphersuite[i]);
    test_encrypt_three_records(ciphersuite[i]);
    test_encrypt_empty_plaintext(ciphersuite[i]);
  }
  return 0;
}
