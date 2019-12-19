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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
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

namespace testing {

enum class TlsAlertType {
  close_notify,  // A close notify alert.
  other,         // Another valid alert.
  small,         // An improperly formatted alert whose plaintext is too small.
};

class S2ACrypterTest : public TestWithParam<uint16_t> {
 protected:
  S2ACrypterTest() {}

  void SetUp() override {
    channel_ = new grpc_channel();
  }

  void TearDown() override {
    if (error_details_ != nullptr) {
      gpr_free(error_details_);
      error_details_ = nullptr;
    }
    if (crypter_ != nullptr) {
      s2a_crypter_destroy(crypter_);
      crypter_ = nullptr;
    }
    delete channel_;
  }

  bool InitializeCrypterFromPointer(s2a_crypter** crypter) {
    uint8_t* traffic_secret;
    size_t traffic_secret_size;
    switch (GetParam()) {
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
    bool is_chacha_poly = (GetParam() == kTlsChacha20Poly1305Sha256);
    grpc_status_code expected_status = is_chacha_poly ? GRPC_STATUS_UNIMPLEMENTED : GRPC_STATUS_OK;
    const char* expected_error_details = is_chacha_poly ? kS2AChachaPolyUnimplemented : nullptr;
    EXPECT_EQ(s2a_crypter_create(
      /*TLS 1.3=*/ 0, GetParam(), traffic_secret, traffic_secret_size,
      traffic_secret, traffic_secret_size, channel_, crypter, &error_details_), expected_status);
    if (is_chacha_poly) {
      EXPECT_EQ(strcmp(error_details_, expected_error_details), 0);
      return false;
    }
    EXPECT_EQ(error_details_, nullptr);
    return true;
  }

  bool InitializeCrypter() {
    return InitializeCrypterFromPointer(&crypter_);
  }

  grpc_channel* channel_ = nullptr;
  char* error_details_ = nullptr;
  s2a_crypter* crypter_ = nullptr;
};

INSTANTIATE_TEST_SUITE_P(S2ACrypterTest, S2ACrypterTest, Values(kTlsAes128GcmSha256, kTlsAes256GcmSha384, kTlsChacha20Poly1305Sha256));

TEST_P(S2ACrypterTest, IncorrectTLSVersion) {
  uint8_t in_traffic_secret[32] = "in_traffic_secret";
  uint8_t out_traffic_secret[32] = "out_traffic_secret";
  grpc_status_code status = s2a_crypter_create(
      /*TLS 1.2=*/ 1, kTlsAes128GcmSha256, in_traffic_secret,
      kSha256DigestLength, out_traffic_secret, kSha256DigestLength, channel_,
      &crypter_, &error_details_);
  EXPECT_EQ(status, GRPC_STATUS_FAILED_PRECONDITION);
  EXPECT_EQ(strcmp(error_details_, kS2AUnsupportedTlsVersion), 0);
  EXPECT_EQ(status, GRPC_STATUS_FAILED_PRECONDITION);
  EXPECT_EQ(strcmp(error_details_, kS2AUnsupportedTlsVersion), 0);
}

TEST_P(S2ACrypterTest, IncorrectKeySize) {
  std::vector<uint8_t> in_traffic_secret(kSha256DigestLength - 1, 0);
  std::vector<uint8_t> out_traffic_secret(kSha256DigestLength + 1, 0);
  grpc_status_code status = s2a_crypter_create(
      /** TLS 1.3 **/ 0, kTlsAes128GcmSha256, in_traffic_secret.data(),
      in_traffic_secret.size(), out_traffic_secret.data(),
      out_traffic_secret.size(), channel_, &crypter_, &error_details_);
  EXPECT_EQ(status, GRPC_STATUS_FAILED_PRECONDITION);
  EXPECT_EQ(strcmp(error_details_, kS2ATrafficSecretSizeMismatch), 0);
}

TEST_P(S2ACrypterTest, CreateSuccess) {
  if (!InitializeCrypter()) { return; }

  gsec_aead_crypter* in_crypter = s2a_in_aead_crypter_for_testing(crypter_);
  gsec_aead_crypter* out_crypter = s2a_out_aead_crypter_for_testing(crypter_);
  EXPECT_NE(in_crypter, nullptr);
  EXPECT_NE(out_crypter, nullptr);

  size_t in_nonce_size;
  size_t out_nonce_size;
  size_t in_key_size;
  size_t out_key_size;
  size_t in_tag_size;
  size_t out_tag_size;
  size_t correct_key_size = 0;
  size_t correct_nonce_size = 0;
  size_t correct_tag_size = 0;
  switch (GetParam()) {
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
  gsec_aead_crypter_nonce_length(in_crypter, &in_nonce_size, &error_details_);
  EXPECT_EQ(in_nonce_size, correct_nonce_size);
  gsec_aead_crypter_nonce_length(out_crypter, &out_nonce_size, &error_details_);
  EXPECT_EQ(out_nonce_size, correct_nonce_size);

  gsec_aead_crypter_key_length(in_crypter, &in_key_size, &error_details_);
  gsec_aead_crypter_key_length(out_crypter, &out_key_size, &error_details_);
  EXPECT_EQ(in_key_size, correct_key_size);
  EXPECT_EQ(out_key_size, correct_key_size);

  gsec_aead_crypter_tag_length(in_crypter, &in_tag_size, &error_details_);
  EXPECT_EQ(in_tag_size, correct_tag_size);
  gsec_aead_crypter_tag_length(out_crypter, &out_tag_size, &error_details_);
  EXPECT_EQ(out_tag_size, correct_tag_size);

  switch (GetParam()) {
    case kTlsAes128GcmSha256:
      verify_half_connections(kTlsAes128GcmSha256, crypter_,
                              s2a_test_data::aes_128_gcm_traffic_secret);
      break;
    case kTlsAes256GcmSha384:
      verify_half_connections(kTlsAes256GcmSha384, crypter_,
                              s2a_test_data::aes_256_gcm_traffic_secret);
      break;
    case kTlsChacha20Poly1305Sha256:
      verify_half_connections(kTlsChacha20Poly1305Sha256, crypter_,
                              s2a_test_data::chacha_poly_traffic_secret);
      break;
    default:
      gpr_log(GPR_ERROR, kS2AUnsupportedCiphersuite);
      abort();
  }
}

TEST_P(S2ACrypterTest, EncryptRecordBadSize) {
  if (!InitializeCrypter()) { return; }

  /** Test the case when the memory allocated for the record is insufficient.**/
  std::vector<uint8_t> test_plaintext = {'1', '2', '3', '4', '5', '6'};
  size_t max_record_overhead;
  grpc_status_code overhead_status =
      s2a_max_record_overhead(*crypter_, &max_record_overhead, &error_details_);
  EXPECT_EQ(overhead_status, GRPC_STATUS_OK);
  size_t record_allocated_size =
      test_plaintext.size() - 2 + max_record_overhead;
  std::vector<uint8_t> record(record_allocated_size, 0);
  size_t record_size;
  grpc_status_code insufficient_memory_status = s2a_encrypt(
      crypter_, test_plaintext.data(), test_plaintext.size(), record.data(),
      record_allocated_size, &record_size, &error_details_);
  EXPECT_EQ(insufficient_memory_status, GRPC_STATUS_FAILED_PRECONDITION);
  EXPECT_EQ(strcmp(error_details_, kS2APlaintextInsufficientRecordSize), 0);
  gpr_free(error_details_);
  error_details_ = nullptr;

  /** Test the case when the size of the plaintext is larger than the TLS 1.3
   *  RFC allows; see https://tools.ietf.org/html/rfc8446#section-5.1 . **/
  std::vector<uint8_t> oversized_plaintext(SSL3_RT_MAX_PLAIN_LENGTH + 1, 0);
  record_allocated_size = oversized_plaintext.size() + max_record_overhead;
  record.resize(record_allocated_size, 0);
  grpc_status_code oversized_plaintext_status = s2a_encrypt(
      crypter_, oversized_plaintext.data(), oversized_plaintext.size(),
      record.data(), record_allocated_size, &record_size, &error_details_);
  EXPECT_EQ(oversized_plaintext_status, GRPC_STATUS_FAILED_PRECONDITION);
  EXPECT_EQ(strcmp(error_details_, kS2APlaintextExceedMaxSize), 0);
}

TEST_P(S2ACrypterTest, EncryptRecordSuccess) {
  if (!InitializeCrypter()) { return; }

  size_t max_record_overhead;
  grpc_status_code overhead_status =
      s2a_max_record_overhead(*crypter_, &max_record_overhead, &error_details_);
  EXPECT_EQ(overhead_status, GRPC_STATUS_OK);

  std::vector<uint8_t> test_plaintext = {'1', '2', '3', '4', '5', '6'};
  size_t record_allocated_size = test_plaintext.size() + max_record_overhead;
  std::vector<uint8_t> record(record_allocated_size, 0);
  size_t record_size;
  grpc_status_code encrypt_status = s2a_encrypt(
      crypter_, test_plaintext.data(), test_plaintext.size(), record.data(),
      record_allocated_size, &record_size, &error_details_);
  EXPECT_EQ(encrypt_status, GRPC_STATUS_OK);
  EXPECT_EQ(record_size, expected_message_size(test_plaintext.size()));

  std::vector<uint8_t> record_2(0, 0);
  std::vector<uint8_t> record_3(0, 0);
  bool correct_encrypted_record =
      check_encrypt_record(GetParam(), record, record_2, record_3);
  EXPECT_TRUE(correct_encrypted_record);
  EXPECT_EQ(error_details_, nullptr);
}

TEST_P(S2ACrypterTest, EncryptThreeRecords) {
  if (!InitializeCrypter()) { return; }

  size_t max_record_overhead;
  grpc_status_code overhead_status =
      s2a_max_record_overhead(*crypter_, &max_record_overhead, &error_details_);
  EXPECT_EQ(overhead_status, GRPC_STATUS_OK);

  std::vector<uint8_t> test_plaintext_1 = {'1', '2', '3', '4', '5', '6'};
  size_t record_1_allocated_size =
      test_plaintext_1.size() + max_record_overhead;
  std::vector<uint8_t> record_1(record_1_allocated_size, 0);
  size_t record_1_size;
  encrypt_plaintext_and_verify_size(crypter_, test_plaintext_1, record_1,
                                    &record_1_size, &error_details_);

  std::vector<uint8_t> test_plaintext_2 = {'7', '8', '9', '1', '2',
                                           '3', '4', '5', '6'};
  size_t record_2_allocated_size =
      test_plaintext_2.size() + max_record_overhead;
  std::vector<uint8_t> record_2(record_2_allocated_size, 0);
  size_t record_2_size;
  encrypt_plaintext_and_verify_size(crypter_, test_plaintext_2, record_2,
                                    &record_2_size, &error_details_);

  std::vector<uint8_t> test_plaintext_3 = {'7', '8', '9', '1'};
  size_t record_3_allocated_size =
      test_plaintext_3.size() + max_record_overhead;
  std::vector<uint8_t> record_3(record_3_allocated_size, 0);
  size_t record_3_size;
  encrypt_plaintext_and_verify_size(crypter_, test_plaintext_3, record_3,
                                    &record_3_size, &error_details_);

  bool correct_encrypted_record =
      check_encrypt_record(GetParam(), record_1, record_2, record_3);
  EXPECT_TRUE(correct_encrypted_record);
  EXPECT_EQ(error_details_, nullptr);
}

TEST_P(S2ACrypterTest, EncryptEmptyPlaintext) {
  if (!InitializeCrypter()) { return; }

  size_t max_record_overhead;
  grpc_status_code overhead_status =
      s2a_max_record_overhead(*crypter_, &max_record_overhead, &error_details_);
  EXPECT_EQ(overhead_status, GRPC_STATUS_OK);

  std::vector<uint8_t> test_plaintext = {};
  size_t record_allocated_size = test_plaintext.size() + max_record_overhead;
  std::vector<uint8_t> record(record_allocated_size, 0);
  size_t record_size;

  /** Encrypt empty plaintext with incorrect plaintext size. **/
  grpc_status_code bad_encrypt_status =
      s2a_encrypt(crypter_, test_plaintext.data(), /** plaintext size **/ 1,
                  record.data(), record.size(), &record_size, &error_details_);
  EXPECT_EQ(bad_encrypt_status, GRPC_STATUS_INVALID_ARGUMENT);
  EXPECT_EQ(strcmp(error_details_, kS2APlaintextNullptr), 0);
  gpr_free(error_details_);
  error_details_ = nullptr;

  /** Encrypt empty plaintext with correct plaintext size. **/
  grpc_status_code encrypt_status =
      s2a_encrypt(crypter_, test_plaintext.data(), test_plaintext.size(),
                  record.data(), record.size(), &record_size, &error_details_);
  EXPECT_EQ(encrypt_status, GRPC_STATUS_OK);
  EXPECT_EQ(record_size, expected_message_size(test_plaintext.size()));
  EXPECT_TRUE(check_record_empty_plaintext(GetParam(), record));
}

TEST_P(S2ACrypterTest, DecryptRecordSuccess) {
  if (!InitializeCrypter()) { return; }

  std::vector<uint8_t> record;
  switch (GetParam()) {
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
      *crypter_, record.size(), &plaintext_allocated_size, &error_details_);
  EXPECT_EQ(plaintext_status, GRPC_STATUS_OK);
  EXPECT_EQ(error_details_, nullptr);

  size_t plaintext_size;
  std::vector<uint8_t> plaintext(plaintext_allocated_size, 0);
  S2ADecryptStatus decrypt_status =
      s2a_decrypt(crypter_, record.data(), record.size(), plaintext.data(),
                  plaintext.size(), &plaintext_size, &error_details_);
  EXPECT_EQ(decrypt_status, S2ADecryptStatus::OK);
  EXPECT_EQ(error_details_, nullptr);
  EXPECT_EQ(plaintext_size, 6);
  plaintext.resize(plaintext_size);
  EXPECT_EQ(plaintext, s2a_test_data::decrypt_plaintext_1);
}

TEST_P(S2ACrypterTest, DecryptRecordWithPadding) {
  if (!InitializeCrypter()) { return; }

  std::vector<uint8_t> record;
  switch (GetParam()) {
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
      *crypter_, record.size(), &plaintext_allocated_size, &error_details_);
  EXPECT_EQ(plaintext_status, GRPC_STATUS_OK);
  EXPECT_EQ(error_details_, nullptr);

  size_t plaintext_size;
  std::vector<uint8_t> plaintext(plaintext_allocated_size, 0);
  S2ADecryptStatus decrypt_status =
      s2a_decrypt(crypter_, record.data(), record.size(), plaintext.data(),
                  plaintext.size(), &plaintext_size, &error_details_);
  EXPECT_EQ(decrypt_status, S2ADecryptStatus::OK);
  EXPECT_EQ(error_details_, nullptr);
  EXPECT_EQ(plaintext_size, 6);
  plaintext.resize(plaintext_size);
  EXPECT_EQ(plaintext, s2a_test_data::message_encrypted_with_padded_zeros);
}

TEST_P(S2ACrypterTest, DecryptLargeRecord) {
  if (!InitializeCrypter()) { return; }

  /** Construct a TLS record whose plaintext is larger than is allowed. **/
  size_t tag_size;
  gsec_aead_crypter_tag_length(s2a_in_aead_crypter_for_testing(crypter_),
                               &tag_size, &error_details_);
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
      s2a_max_plaintext_size(*crypter_, oversize_record.size(),
                             &plaintext_allocated_size, &error_details_);
  EXPECT_EQ(plaintext_status, GRPC_STATUS_OK);
  EXPECT_EQ(error_details_, nullptr);
  std::vector<uint8_t> plaintext(plaintext_allocated_size, 0);
  size_t plaintext_size;
  S2ADecryptStatus decrypt_status = s2a_decrypt(
      crypter_, oversize_record.data(), oversize_record.size(), plaintext.data(),
      plaintext.size(), &plaintext_size, &error_details_);
  EXPECT_EQ(decrypt_status, S2ADecryptStatus::ALERT_RECORD_OVERFLOW);
  EXPECT_EQ(strcmp(error_details_, kS2ARecordExceedMaxSize), 0);
}

TEST_P(S2ACrypterTest, DecryptAlertCloseNotify) {
  if (!InitializeCrypter()) { return; }

  std::vector<uint8_t> record;
  switch (GetParam()) {
    case kTlsAes128GcmSha256:
      record = s2a_test_data::aes_128_gcm_decrypt_close_notify;
      break;
    case kTlsAes256GcmSha384:
      record = s2a_test_data::aes_256_gcm_decrypt_close_notify;
      break;
    case kTlsChacha20Poly1305Sha256:
      record = s2a_test_data::chacha_poly_decrypt_close_notify;
      break;
  }

  size_t plaintext_allocated_size;
  grpc_status_code plaintext_status = s2a_max_plaintext_size(
      *crypter_, record.size(), &plaintext_allocated_size, &error_details_);
  EXPECT_EQ(plaintext_status, GRPC_STATUS_OK);
  EXPECT_EQ(error_details_, nullptr);
  size_t plaintext_size;
  std::vector<uint8_t> plaintext(plaintext_allocated_size, 0);
  S2ADecryptStatus decrypt_status =
      s2a_decrypt(crypter_, record.data(), record.size(), plaintext.data(),
                  plaintext.size(), &plaintext_size, &error_details_);
  EXPECT_EQ(decrypt_status, S2ADecryptStatus::ALERT_CLOSE_NOTIFY);
}

TEST_P(S2ACrypterTest, DecryptAlertOther) {
  if (!InitializeCrypter()) { return; }

  std::vector<uint8_t> record;
  switch (GetParam()) {
    case kTlsAes128GcmSha256:
      record = s2a_test_data::aes_128_gcm_decrypt_alert_other;
      break;
    case kTlsAes256GcmSha384:
      record = s2a_test_data::aes_256_gcm_decrypt_alert_other;
      break;
    case kTlsChacha20Poly1305Sha256:
      record = s2a_test_data::chacha_poly_decrypt_alert_other;
      break;
  }

  size_t plaintext_allocated_size;
  grpc_status_code plaintext_status = s2a_max_plaintext_size(
      *crypter_, record.size(), &plaintext_allocated_size, &error_details_);
  EXPECT_EQ(plaintext_status, GRPC_STATUS_OK);
  EXPECT_EQ(error_details_, nullptr);
  size_t plaintext_size;
  std::vector<uint8_t> plaintext(plaintext_allocated_size, 0);
  S2ADecryptStatus decrypt_status =
      s2a_decrypt(crypter_, record.data(), record.size(), plaintext.data(),
                  plaintext.size(), &plaintext_size, &error_details_);
  EXPECT_EQ(decrypt_status, S2ADecryptStatus::ALERT_OTHER);
}

TEST_P(S2ACrypterTest, DecryptAlertSmall) {
  if (!InitializeCrypter()) { return; }

  std::vector<uint8_t> record;
  switch (GetParam()) {
    case kTlsAes128GcmSha256:
      record = s2a_test_data::aes_128_gcm_decrypt_alert_small;
      break;
    case kTlsAes256GcmSha384:
      record = s2a_test_data::aes_256_gcm_decrypt_alert_small;
      break;
    case kTlsChacha20Poly1305Sha256:
      record = s2a_test_data::chacha_poly_decrypt_alert_small;
      break;
  }

  size_t plaintext_allocated_size;
  grpc_status_code plaintext_status = s2a_max_plaintext_size(
      *crypter_, record.size(), &plaintext_allocated_size, &error_details_);
  EXPECT_EQ(plaintext_status, GRPC_STATUS_OK);
  EXPECT_EQ(error_details_, nullptr);
  size_t plaintext_size;
  std::vector<uint8_t> plaintext(plaintext_allocated_size, 0);
  S2ADecryptStatus decrypt_status =
      s2a_decrypt(crypter_, record.data(), record.size(), plaintext.data(),
                  plaintext.size(), &plaintext_size, &error_details_);
  EXPECT_EQ(decrypt_status, S2ADecryptStatus::INVALID_RECORD);
  EXPECT_EQ(strcmp(error_details_, kS2ARecordSmallAlert), 0);
}

TEST_P(S2ACrypterTest, Roundtrips) {
  if (!InitializeCrypter()) { return; }

  s2a_crypter* peer_crypter = nullptr;
  InitializeCrypterFromPointer(&peer_crypter);

  send_message(s2a_test_data::test_message_1, crypter_, peer_crypter);
  send_message(s2a_test_data::test_message_2, peer_crypter, crypter_);
  send_message(s2a_test_data::test_message_3, peer_crypter, crypter_);
  send_message(s2a_test_data::test_message_4, crypter_, peer_crypter);
  send_message(s2a_test_data::test_message_5, peer_crypter, crypter_);

  // Cleanup.
  s2a_crypter_destroy(peer_crypter);
}

TEST_P(S2ACrypterTest, KeyUpdate) {
  if (!InitializeCrypter()) { return; }

  /** Setup for encryption of key update message. **/
  iovec plaintext_vec = {
      reinterpret_cast<void*>(s2a_test_data::key_update_message.data()),
      s2a_test_data::key_update_message.size()};

  size_t max_record_overhead;
  grpc_status_code overhead_status =
      s2a_max_record_overhead(*crypter_, &max_record_overhead, &error_details_);
  EXPECT_EQ(overhead_status, GRPC_STATUS_OK);
  EXPECT_EQ(error_details_, nullptr);
  size_t record_allocated_size =
      s2a_test_data::key_update_message.size() + max_record_overhead;
  std::vector<uint8_t> record(record_allocated_size, 0);
  iovec record_vec = {(void*)record.data(), record.size()};
  size_t record_bytes_written;

  /** Encrypt key update message. **/
  grpc_status_code write_key_update_status = s2a_write_tls13_record(
      crypter_, SSL3_RT_HANDSHAKE, &plaintext_vec, /* plaintext_vec length=*/1,
      record_vec, &record_bytes_written, &error_details_);
  EXPECT_EQ(write_key_update_status, GRPC_STATUS_OK);
  EXPECT_EQ(error_details_, nullptr);
  EXPECT_EQ(record_bytes_written, expected_message_size(s2a_test_data::key_update_message.size()));

  /** Setup for decryption of key update message. **/
  iovec record_header_vec = {record_vec.iov_base, SSL3_RT_HEADER_LENGTH};
  iovec protected_vec = {
      reinterpret_cast<uint8_t*>(record_vec.iov_base) + SSL3_RT_HEADER_LENGTH,
      record.size() - SSL3_RT_HEADER_LENGTH};
  size_t plaintext_size;
  grpc_status_code plaintext_status = s2a_max_plaintext_size(
      *crypter_, record_bytes_written, &plaintext_size, &error_details_);
  EXPECT_EQ(plaintext_status, GRPC_STATUS_OK);
  EXPECT_EQ(error_details_, nullptr);
  std::vector<uint8_t> plaintext(plaintext_size, 0);
  iovec unprotected_vec = {(void*)plaintext.data(), plaintext.size()};
  size_t unprotected_bytes_written;

  /** Decrypt key update message. **/
  S2ADecryptStatus read_key_update_status = s2a_decrypt_record(
      crypter_, record_header_vec, &protected_vec, /* protected_vec length=*/1,
      unprotected_vec, &unprotected_bytes_written, &error_details_);
  EXPECT_EQ(read_key_update_status, S2ADecryptStatus::OK);
  EXPECT_EQ(error_details_, nullptr);
  EXPECT_EQ(unprotected_bytes_written, s2a_test_data::key_update_message.size());

  /** Verify correctness. **/
  uint8_t* expected_traffic_secret;
  size_t expected_traffic_secret_size;
  switch (GetParam()) {
    case kTlsAes128GcmSha256:
      expected_traffic_secret = s2a_test_data::aes_128_gcm_advanced_traffic_secret.data();
      expected_traffic_secret_size = s2a_test_data::aes_128_gcm_advanced_traffic_secret.size();
      break;
    case kTlsAes256GcmSha384:
      expected_traffic_secret = s2a_test_data::aes_256_gcm_advanced_traffic_secret.data();
      expected_traffic_secret_size = s2a_test_data::aes_256_gcm_advanced_traffic_secret.size();
      break;
    case kTlsChacha20Poly1305Sha256:
      expected_traffic_secret = s2a_test_data::chacha_poly_advanced_traffic_secret.data();
      expected_traffic_secret_size = s2a_test_data::chacha_poly_advanced_traffic_secret.size();
      break;
  }
  check_half_connection_for_testing(
      crypter_, /* in=*/true, /* expected sequence=*/0,
      expected_traffic_secret_size, expected_traffic_secret,
      /* verify_nonce=*/false, /* expected_nonce_size=*/0,
      /* expected_nonce=*/nullptr, SSL3_RT_HEADER_LENGTH);
  plaintext.resize(unprotected_bytes_written);
  EXPECT_EQ(plaintext, s2a_test_data::key_update_message);
}

} // namespace testing

int main(int argc, char** argv) {
  grpc_init();
  ::testing::InitGoogleTest(&argc, argv);
  int ret = RUN_ALL_TESTS();
  grpc_shutdown();
  return ret;
}
