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
  grpc_channel* channel = grpc_core::New<grpc_channel>();
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
  grpc_core::Delete<grpc_channel>(channel);
}

static void s2a_test_incorrect_key_size() {
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
  GPR_ASSERT(strcmp(error_details, kS2ATrafficSecretSizeMismatch) == 0);

  // Cleanup.
  s2a_crypter_destroy(crypter);
  gpr_free(error_details);
  grpc_core::Delete<grpc_channel>(channel);
}

static void s2a_test_create_crypter_success(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
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
  grpc_core::Delete<grpc_channel>(channel);
}

static void s2a_test_encrypt_record_bad_size(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

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
  grpc_core::Delete<grpc_channel>(channel);
  gpr_free(error_details);
}

static void s2a_test_encrypt_record_success(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
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
  grpc_core::Delete<grpc_channel>(channel);
}

static void s2a_test_encrypt_three_records(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
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
  grpc_core::Delete<grpc_channel>(channel);
}

static void s2a_test_encrypt_empty_plaintext(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
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
  grpc_core::Delete<grpc_channel>(channel);
}

static void s2a_test_decrypt_record_success(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
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
  grpc_core::Delete<grpc_channel>(channel);
}

static void s2a_test_decrypt_large_record(uint16_t ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
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
  grpc_core::Delete<grpc_channel>(channel);
}

enum class TlsAlertType {
  close_notify,  // A close notify alert.
  other,         // Another valid alert.
  small,         // An improperly formatted alert whose plaintext is too small.
};

static void s2a_test_decrypt_alert(uint16_t ciphersuite,
                                   TlsAlertType alert_type) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
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
  grpc_core::Delete<grpc_channel>(channel);
}

static void s2a_test_roundtrips(uint16_t ciphersuite) {
  s2a_crypter* in_crypter = nullptr;
  s2a_crypter* out_crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code in_status =
      setup_crypter(ciphersuite, channel, &in_crypter, &error_details);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(in_status == GRPC_STATUS_UNIMPLEMENTED);
    GPR_ASSERT(strcmp(error_details, kS2AChachaPolyUnimplemented) == 0);

    // Cleanup.
    s2a_crypter_destroy(in_crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
    return;
  }
  grpc_status_code out_status =
      setup_crypter(ciphersuite, channel, &out_crypter, &error_details);
  GPR_ASSERT(out_status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  send_message(s2a_test_data::test_message_1, in_crypter, out_crypter);
  send_message(s2a_test_data::test_message_2, out_crypter, in_crypter);
  send_message(s2a_test_data::test_message_3, out_crypter, in_crypter);

  // Cleanup.
  s2a_crypter_destroy(in_crypter);
  s2a_crypter_destroy(out_crypter);
  grpc_core::Delete<grpc_channel>(channel);
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
    s2a_test_decrypt_large_record(ciphersuite[i]);
    for (size_t j = 0; j < number_alert_types; j++) {
      s2a_test_decrypt_alert(ciphersuite[i], alert[j]);
    }
    s2a_test_roundtrips(ciphersuite[i]);
  }
  return 0;
}
