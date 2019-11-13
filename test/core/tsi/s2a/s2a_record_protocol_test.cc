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
#include "src/core/lib/surface/channel.h"
#include "src/core/tsi/s2a/record_protocol/s2a_crypter.h"
#include "src/core/tsi/s2a/record_protocol/s2a_crypter_util.h"
#include "src/core/tsi/s2a/s2a_constants.h"
#include "test/core/tsi/s2a/s2a_test_util.h"

/** Certain tests in this library use randomly-generated initial data. This
 *  parameter determines the number of times such a test runs. **/
#define S2A_ITERATIONS 1000

uint8_t decrypt_plaintext_one[7] = "123456";
const size_t decrypt_record_one_size = 28;
uint8_t aes_128_gcm_decrypt_record_one[decrypt_record_one_size] = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0xf2, 0xe4, 0xe4, 0x11, 0xac,
    0x67, 0x60, 0xe4, 0xe3, 0xf0, 0x74, 0xa3, 0x65, 0x74, 0xc4,
    0x5e, 0xe4, 0xc1, 0x90, 0x61, 0x03, 0xdb, 0x0d};
uint8_t aes_256_gcm_decrypt_record_one[decrypt_record_one_size] = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0x24, 0xef, 0xee, 0x5a, 0xf1,
    0xa6, 0x21, 0x70, 0xad, 0x5a, 0x95, 0xf8, 0x99, 0xd0, 0x38,
    0xb9, 0x65, 0x38, 0x6a, 0x1a, 0x7d, 0xae, 0xd9};
uint8_t chacha_poly_decrypt_record_one[decrypt_record_one_size] = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0xc9, 0x47, 0xff, 0xa4, 0x70,
    0x30, 0x43, 0x70, 0x33, 0x8b, 0xb0, 0x7c, 0xe4, 0x68, 0xe6,
    0xb8, 0xa0, 0x94, 0x4a, 0x33, 0x8b, 0xa4, 0x02};

const size_t decrypt_close_notify_size = 24;
uint8_t aes_128_gcm_decrypt_close_notify[decrypt_close_notify_size] = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0xc2, 0xd6, 0xc2, 0x45, 0xfb,
    0x80, 0x96, 0x9d, 0xe1, 0xdd, 0x9d, 0x14, 0x49, 0x92, 0x61,
    0xb6, 0x77, 0x35, 0xb0};
uint8_t aes_256_gcm_decrypt_close_notify[decrypt_close_notify_size] = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0x14, 0xdd, 0xc8, 0xf3, 0xb3,
    0x85, 0x66, 0x60, 0xbb, 0x5a, 0xc8, 0x15, 0x33, 0xc1, 0x57,
    0x58, 0x2f, 0x8b, 0x4c};
uint8_t chacha_poly_decrypt_close_notify[decrypt_close_notify_size] = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0xf9, 0x75, 0xd9, 0xcb, 0x2f,
    0x11, 0x6d, 0x85, 0xd4, 0xe3, 0x85, 0x9f, 0x52, 0x88, 0xa9,
    0xb0, 0x13, 0xd7, 0x78};

static grpc_status_code setup_crypter(TLSCiphersuite ciphersuite,
                                      grpc_channel* channel,
                                      s2a_crypter** crypter,
                                      char** error_details) {
  grpc_byte_buffer* session_state_buffer = create_example_session_state(
      /** admissible_tls_version **/ true, ciphersuite,
      /** has_in_out_key **/ true,
      /** correct_key_size **/ true,
      /** has_in_out_sequence **/ true,
      /** has_in_out_fixed_nonce **/ true);
  upb::Arena arena;
  s2a_SessionState* session_state = nullptr;
  grpc_status_code deserialize_status = s2a_deserialize_session_state(
      session_state_buffer, arena.ptr(), &session_state, error_details);
  if (deserialize_status != GRPC_STATUS_OK) {
    return deserialize_status;
  }
  GPR_ASSERT(session_state != nullptr);
  grpc_byte_buffer_destroy(session_state_buffer);

  upb_strview in_key = s2a_SessionState_in_key(session_state);
  upb_strview out_key = s2a_SessionState_out_key(session_state);
  size_t key_size;
  if (in_key.size != out_key.size) {
    return GRPC_STATUS_INTERNAL;
  } else {
    key_size = in_key.size;
  }
  upb_strview in_nonce = s2a_SessionState_in_fixed_nonce(session_state);
  upb_strview out_nonce = s2a_SessionState_out_fixed_nonce(session_state);
  size_t nonce_size;
  if (in_nonce.size != out_nonce.size) {
    return GRPC_STATUS_INTERNAL;
  } else {
    nonce_size = in_nonce.size;
  }

  return s2a_crypter_create(
      s2a_SessionState_tls_version(session_state),
      s2a_SessionState_tls_ciphersuite(session_state), (uint8_t*)in_key.data,
      (uint8_t*)out_key.data, key_size, (uint8_t*)in_nonce.data,
      (uint8_t*)out_nonce.data, nonce_size, channel, crypter, error_details);
}

static void s2a_test_incorrect_tls_version() {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status = s2a_crypter_create(
      /** TLS 1.2 **/ 1, TLS_AES_128_GCM_SHA256, /** in key **/ nullptr,
      /** out key **/ nullptr, TLS_AES_128_GCM_SHA256_KEY_SIZE,
      /** in nonce **/ nullptr, /** out nonce **/ nullptr,
      TLS_AES_128_GCM_SHA256_NONCE_SIZE, channel, &crypter, &error_details);
  GPR_ASSERT(status == GRPC_STATUS_FAILED_PRECONDITION);
  int correct_error_message =
      strcmp(error_details, S2A_UNSUPPORTED_TLS_VERSION);
  GPR_ASSERT(correct_error_message == 0);

  // Cleanup.
  gpr_free(error_details);
  grpc_core::Delete<grpc_channel>(channel);
}

static void s2a_test_incorrect_key_size() {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  uint8_t derived_in_key[32] = "derived_in_key";
  uint8_t derived_out_key[32] = "derived_out_key";
  uint8_t derived_in_nonce[24] = "derived_in_nonce";
  uint8_t derived_out_nonce[24] = "derived_out_nonce";
  grpc_status_code status = s2a_crypter_create(
      /** TLS 1.3 **/ 0, TLS_AES_128_GCM_SHA256, derived_in_key,
      derived_out_key, TLS_AES_128_GCM_SHA256_KEY_SIZE - 1, derived_in_nonce,
      derived_out_nonce, TLS_AES_128_GCM_SHA256_NONCE_SIZE, channel, &crypter,
      &error_details);
  GPR_ASSERT(status == GRPC_STATUS_FAILED_PRECONDITION);
  int correct_error_message = strcmp(error_details, S2A_KEY_SIZE_MISMATCH);
  GPR_ASSERT(correct_error_message == 0);

  // Cleanup.
  s2a_crypter_destroy(crypter);
  gpr_free(error_details);
  grpc_core::Delete<grpc_channel>(channel);
}

static void s2a_test_deserialize_byte_buffer() {
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
      strcmp(error_details, "The s2a_SessionState_parse() method failed.");
  GPR_ASSERT(correct_error_message == 0);

  /** Clean up. **/
  gpr_free(error_details);
  grpc_slice_unref(slice);
  grpc_slice_unref(bad_slice);
  grpc_byte_buffer_destroy(buffer);
}

static void s2a_test_create_crypter_success(TLSCiphersuite ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == TLS_CHACHA20_POLY1305_SHA256_ciphersuite) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message =
        strcmp(error_details, S2A_CHACHA_POLY_UNIMPLEMENTED);
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
    case TLS_AES_128_GCM_SHA256_ciphersuite:
      correct_key_size = TLS_AES_128_GCM_SHA256_KEY_SIZE;
      correct_nonce_size = TLS_AES_128_GCM_SHA256_NONCE_SIZE;
      correct_tag_size = EVP_AEAD_AES_GCM_TAG_LEN;
      break;
    case TLS_AES_256_GCM_SHA384_ciphersuite:
      correct_key_size = TLS_AES_256_GCM_SHA384_KEY_SIZE;
      correct_nonce_size = TLS_AES_256_GCM_SHA384_NONCE_SIZE;
      correct_tag_size = EVP_AEAD_AES_GCM_TAG_LEN;
      break;
    case TLS_CHACHA20_POLY1305_SHA256_ciphersuite:
      correct_key_size = TLS_CHACHA20_POLY1305_SHA256_KEY_SIZE;
      correct_nonce_size = TLS_CHACHA20_POLY1305_SHA256_NONCE_SIZE;
      correct_tag_size = POLY1305_TAG_LEN;
      break;
    default:
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

  if (ciphersuite == TLS_AES_128_GCM_SHA256_ciphersuite) {
    uint8_t nonce_bytes[13] = {0xb5, 0x80, 0x3d, 0x82, 0xad, 0x88, 0x54,
                               0xd2, 0xe5, 0x98, 0x18, 0x7f, 0x00};
    check_half_connection(crypter, true, 0, 12, nonce_bytes,
                          SSL3_RT_HEADER_LENGTH);
    check_half_connection(crypter, false, 0, 12, nonce_bytes,
                          SSL3_RT_HEADER_LENGTH);
  }

  // Cleanup.
  s2a_crypter_destroy(crypter);
  grpc_core::Delete<grpc_channel>(channel);
}

static void s2a_test_encrypt_record_bad_size(TLSCiphersuite ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == TLS_CHACHA20_POLY1305_SHA256_ciphersuite) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message =
        strcmp(error_details, S2A_CHACHA_POLY_UNIMPLEMENTED);
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
  const size_t test_plaintext_size = 7;
  uint8_t test_plaintext[test_plaintext_size] = "123456";
  size_t record_allocated_size =
      test_plaintext_size - 2 + s2a_max_record_overhead(crypter);
  uint8_t* record =
      (uint8_t*)gpr_malloc(record_allocated_size * sizeof(uint8_t));
  size_t record_size;
  grpc_status_code insufficient_memory_status =
      s2a_encrypt(crypter, test_plaintext, test_plaintext_size - 1, record,
                  record_allocated_size, &record_size, &error_details);
  GPR_ASSERT(insufficient_memory_status == GRPC_STATUS_FAILED_PRECONDITION);
  int correct_error_message =
      strcmp(error_details, S2A_PLAINTEXT_INSUFFICIENT_RECORD_SIZE);
  GPR_ASSERT(correct_error_message == 0);
  gpr_free(error_details);
  error_details = nullptr;
  gpr_free(record);
  record = nullptr;

  /** Test the case when the size of the plaintext is larger than the TLS 1.3
   *  RFC allows; see https://tools.ietf.org/html/rfc8446#section-5.1 . **/
  size_t oversized_plaintext_size = SSL3_RT_MAX_PLAIN_LENGTH + 1;
  uint8_t oversized_plaintext[oversized_plaintext_size];
  record_allocated_size =
      oversized_plaintext_size + s2a_max_record_overhead(crypter);
  record = (uint8_t*)gpr_malloc(record_allocated_size * sizeof(uint8_t));
  grpc_status_code oversized_plaintext_status =
      s2a_encrypt(crypter, oversized_plaintext, oversized_plaintext_size,
                  record, record_allocated_size, &record_size, &error_details);
  GPR_ASSERT(oversized_plaintext_status == GRPC_STATUS_FAILED_PRECONDITION);
  correct_error_message = strcmp(error_details, S2A_PLAINTEXT_EXCEED_MAX_SIZE);
  GPR_ASSERT(correct_error_message == 0);

  // Cleanup.
  s2a_crypter_destroy(crypter);
  grpc_core::Delete<grpc_channel>(channel);
  gpr_free(record);
  gpr_free(error_details);
}

static void s2a_test_encrypt_record_success(TLSCiphersuite ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == TLS_CHACHA20_POLY1305_SHA256_ciphersuite) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message =
        strcmp(error_details, S2A_CHACHA_POLY_UNIMPLEMENTED);
    GPR_ASSERT(correct_error_message == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  const size_t test_plaintext_size = 7;
  uint8_t test_plaintext[test_plaintext_size] = "123456";
  size_t record_allocated_size =
      test_plaintext_size + s2a_max_record_overhead(crypter);
  uint8_t* record =
      (uint8_t*)gpr_malloc(record_allocated_size * sizeof(uint8_t));
  size_t record_size;
  grpc_status_code encrypt_status =
      s2a_encrypt(crypter, test_plaintext, test_plaintext_size - 1, record,
                  record_allocated_size, &record_size, &error_details);
  GPR_ASSERT(encrypt_status == GRPC_STATUS_OK);
  GPR_ASSERT(record_size == expected_message_size(test_plaintext_size - 1));

  bool correct_encrypted_record = check_encrypt_record(
      ciphersuite, record, record_size, nullptr, 0, nullptr, 0, &error_details);
  GPR_ASSERT(correct_encrypted_record);
  GPR_ASSERT(error_details == nullptr);

  // Cleanup.
  s2a_crypter_destroy(crypter);
  grpc_core::Delete<grpc_channel>(channel);
  gpr_free(record);
}

static void encrypt_and_verify(s2a_crypter* crypter, uint8_t* plaintext,
                               size_t plaintext_size, uint8_t* record,
                               size_t record_allocated_size,
                               size_t* record_size, char** error_details) {
  grpc_status_code status =
      s2a_encrypt(crypter, plaintext, plaintext_size, record,
                  record_allocated_size, record_size, error_details);
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(*record_size == expected_message_size(plaintext_size));
  GPR_ASSERT(*error_details == nullptr);
}

static void test_encrypt_three_records(TLSCiphersuite ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == TLS_CHACHA20_POLY1305_SHA256_ciphersuite) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message =
        strcmp(error_details, S2A_CHACHA_POLY_UNIMPLEMENTED);
    GPR_ASSERT(correct_error_message == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  const size_t test_plaintext_one_size = 7;
  uint8_t test_plaintext_one[test_plaintext_one_size] = "123456";
  size_t record_one_allocated_size =
      test_plaintext_one_size + s2a_max_record_overhead(crypter);
  uint8_t* record_one =
      (uint8_t*)gpr_malloc(record_one_allocated_size * sizeof(uint8_t));
  size_t record_one_size;
  encrypt_and_verify(crypter, test_plaintext_one, test_plaintext_one_size - 1,
                     record_one, record_one_allocated_size, &record_one_size,
                     &error_details);

  const size_t test_plaintext_two_size = 10;
  uint8_t test_plaintext_two[test_plaintext_two_size] = "789123456";
  size_t record_two_allocated_size =
      test_plaintext_two_size + s2a_max_record_overhead(crypter);
  uint8_t* record_two =
      (uint8_t*)gpr_malloc(record_two_allocated_size * sizeof(uint8_t));
  size_t record_two_size;
  encrypt_and_verify(crypter, test_plaintext_two, test_plaintext_two_size - 1,
                     record_two, record_two_allocated_size, &record_two_size,
                     &error_details);

  const size_t test_plaintext_three_size = 5;
  uint8_t test_plaintext_three[test_plaintext_three_size] = "7891";
  size_t record_three_allocated_size =
      test_plaintext_three_size + s2a_max_record_overhead(crypter);
  uint8_t* record_three =
      (uint8_t*)gpr_malloc(record_three_allocated_size * sizeof(uint8_t));
  size_t record_three_size;
  encrypt_and_verify(crypter, test_plaintext_three,
                     test_plaintext_three_size - 1, record_three,
                     record_three_allocated_size, &record_three_size,
                     &error_details);

  bool correct_encrypted_record = check_encrypt_record(
      ciphersuite, record_one, record_one_size, record_two, record_two_size,
      record_three, record_three_size, &error_details);
  GPR_ASSERT(correct_encrypted_record);
  GPR_ASSERT(error_details == nullptr);

  // Cleanup.
  s2a_crypter_destroy(crypter);
  grpc_core::Delete<grpc_channel>(channel);
  gpr_free(record_one);
  gpr_free(record_two);
  gpr_free(record_three);
}

static void s2a_test_encrypt_empty_plaintext(TLSCiphersuite ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == TLS_CHACHA20_POLY1305_SHA256_ciphersuite) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message =
        strcmp(error_details, S2A_CHACHA_POLY_UNIMPLEMENTED);
    GPR_ASSERT(correct_error_message == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  size_t test_plaintext_size = 0;
  size_t incorrect_plaintext_size = 1;
  uint8_t* test_plaintext = nullptr;
  size_t record_allocated_size =
      test_plaintext_size + s2a_max_record_overhead(crypter);
  uint8_t* record =
      (uint8_t*)gpr_malloc(record_allocated_size * sizeof(uint8_t));
  size_t record_size;

  /** Encrypt empty plaintext with incorrect plaintext size. **/
  grpc_status_code bad_encrypt_status =
      s2a_encrypt(crypter, test_plaintext, incorrect_plaintext_size, record,
                  record_allocated_size, &record_size, &error_details);
  GPR_ASSERT(bad_encrypt_status == GRPC_STATUS_INVALID_ARGUMENT);
  int correct_error_message = strcmp(error_details, S2A_PLAINTEXT_NULLPTR);
  GPR_ASSERT(correct_error_message == 0);
  gpr_free(error_details);
  error_details = nullptr;

  /** Encrypt empty plaintext with correct plaintext size. **/
  grpc_status_code encrypt_status =
      s2a_encrypt(crypter, test_plaintext, test_plaintext_size, record,
                  record_allocated_size, &record_size, &error_details);
  GPR_ASSERT(encrypt_status == GRPC_STATUS_OK);
  GPR_ASSERT(record_size == expected_message_size(test_plaintext_size));
  GPR_ASSERT(check_record_empty_plaintext(ciphersuite, record, record_size,
                                          &error_details));

  // Cleanup.
  s2a_crypter_destroy(crypter);
  grpc_core::Delete<grpc_channel>(channel);
  gpr_free(record);
}

static void s2a_test_decrypt_record_success(TLSCiphersuite ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == TLS_CHACHA20_POLY1305_SHA256_ciphersuite) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message =
        strcmp(error_details, S2A_CHACHA_POLY_UNIMPLEMENTED);
    GPR_ASSERT(correct_error_message == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  uint8_t* record = nullptr;
  switch (ciphersuite) {
    case TLS_AES_128_GCM_SHA256_ciphersuite:
      record = aes_128_gcm_decrypt_record_one;
      break;
    case TLS_AES_256_GCM_SHA384_ciphersuite:
      record = aes_256_gcm_decrypt_record_one;
      break;
    case TLS_CHACHA20_POLY1305_SHA256_ciphersuite:
      record = chacha_poly_decrypt_record_one;
      break;
  }
  GPR_ASSERT(record != nullptr);

  size_t plaintext_allocated_size =
      s2a_max_plaintext_size(crypter, decrypt_record_one_size);
  uint8_t* plaintext =
      (uint8_t*)gpr_malloc(plaintext_allocated_size * sizeof(uint8_t));
  size_t plaintext_size;
  s2a_decrypt_status decrypt_status =
      s2a_decrypt(crypter, record, decrypt_record_one_size, plaintext,
                  plaintext_allocated_size, &plaintext_size, &error_details);
  GPR_ASSERT(decrypt_status == OK);
  GPR_ASSERT(error_details == nullptr);
  GPR_ASSERT(plaintext_size == 6);
  GPR_ASSERT(memcmp(decrypt_plaintext_one, plaintext, plaintext_size) == 0);

  // Cleanup.
  s2a_crypter_destroy(crypter);
  grpc_core::Delete<grpc_channel>(channel);
  gpr_free(plaintext);
}

static void s2a_test_alert_close_notify(TLSCiphersuite ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == TLS_CHACHA20_POLY1305_SHA256_ciphersuite) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message =
        strcmp(error_details, S2A_CHACHA_POLY_UNIMPLEMENTED);
    GPR_ASSERT(correct_error_message == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  uint8_t* record = nullptr;
  switch (ciphersuite) {
    case TLS_AES_128_GCM_SHA256_ciphersuite:
      record = aes_128_gcm_decrypt_close_notify;
      break;
    case TLS_AES_256_GCM_SHA384_ciphersuite:
      record = aes_256_gcm_decrypt_close_notify;
      break;
    case TLS_CHACHA20_POLY1305_SHA256_ciphersuite:
      record = chacha_poly_decrypt_close_notify;
      break;
  }
  GPR_ASSERT(record != nullptr);

  size_t plaintext_allocated_size = s2a_max_plaintext_size(crypter, decrypt_close_notify_size);
  uint8_t* plaintext = (uint8_t*)gpr_malloc(plaintext_allocated_size * sizeof(uint8_t));
  size_t plaintext_size;
  s2a_decrypt_status decrypt_status =
      s2a_decrypt(crypter, record, decrypt_close_notify_size, plaintext,
                  plaintext_allocated_size, &plaintext_size, &error_details);
  GPR_ASSERT(decrypt_status == ALERT_CLOSE_NOTIFY);

  // Cleanup.
  s2a_crypter_destroy(crypter);
  grpc_core::Delete<grpc_channel>(channel);
  gpr_free(plaintext);
}

static void s2a_test_roundtrip_success(TLSCiphersuite ciphersuite,
                                       size_t iterations) {
  s2a_crypter* in_crypter = nullptr;
  s2a_crypter* out_crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code in_status =
      setup_crypter(ciphersuite, channel, &in_crypter, &error_details);
  if (ciphersuite == TLS_CHACHA20_POLY1305_SHA256_ciphersuite) {
    GPR_ASSERT(in_status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message =
        strcmp(error_details, S2A_CHACHA_POLY_UNIMPLEMENTED);
    GPR_ASSERT(correct_error_message == 0);

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

  for (size_t i = 0; i < iterations; i++) {
    send_random_message(i, out_crypter, in_crypter);
    send_random_message(i, in_crypter, out_crypter);
  }
  send_random_message(0, in_crypter, out_crypter);

  // Cleanup.
  s2a_crypter_destroy(in_crypter);
  s2a_crypter_destroy(out_crypter);
  grpc_core::Delete<grpc_channel>(channel);
}

// TODO(mattstev): implement a uniform ramdom sample without using C++11 std
// libraries.
static void s2a_test_random_roundtrips(TLSCiphersuite ciphersuite, size_t iterations) {
  s2a_crypter* crypter_one = nullptr;
  s2a_crypter* crypter_two = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  grpc_status_code setup_status = create_random_crypter_pair(ciphersuite,
                                                             &crypter_one,
                                                             &crypter_two,
                                                             channel);
  if (setup_status == GRPC_STATUS_UNIMPLEMENTED) {
    grpc_core::Delete<grpc_channel>(channel);
    return;
  }
  GPR_ASSERT(setup_status == GRPC_STATUS_OK);

  for (size_t i = 0; i < iterations; i++) {
    size_t random_size = rand() % SSL3_RT_MAX_PLAIN_LENGTH;
    bool one_is_sender = ((rand() % 2) == 0);
    if (one_is_sender) {
      send_random_message(random_size, crypter_one, crypter_two);
    } else {
      send_random_message(random_size, crypter_two, crypter_one);
    }
  }

  // Cleanup.
  s2a_crypter_destroy(crypter_one);
  s2a_crypter_destroy(crypter_two);
  grpc_core::Delete<grpc_channel>(channel);
}

int main(int argc, char** argv) {
  s2a_test_incorrect_tls_version();
  s2a_test_incorrect_key_size();
  s2a_test_deserialize_byte_buffer();
  const size_t number_ciphersuites = 3;
  TLSCiphersuite ciphersuite[number_ciphersuites] = {
      TLS_AES_128_GCM_SHA256_ciphersuite, TLS_AES_256_GCM_SHA384_ciphersuite,
      TLS_CHACHA20_POLY1305_SHA256_ciphersuite};
  for (size_t i = 0; i < number_ciphersuites; i++) {
    s2a_test_create_crypter_success(ciphersuite[i]);
    s2a_test_encrypt_record_bad_size(ciphersuite[i]);
    s2a_test_encrypt_record_success(ciphersuite[i]);
    s2a_test_encrypt_three_records(ciphersuite[i]);
    s2a_test_encrypt_empty_plaintext(ciphersuite[i]);
    s2a_test_decrypt_record_success(ciphersuite[i]);
    s2a_test_alert_close_notify(ciphersuite[i]);
    s2a_test_roundtrip_success(ciphersuite[i], S2A_ITERATIONS);
    s2a_test_random_roundtrips(ciphersuite[i], S2A_ITERATIONS);
  }
  return 0;
}
