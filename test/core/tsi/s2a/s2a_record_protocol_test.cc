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

static void test_incorrect_tls_version() {
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
      strcmp(error_details, "S2A does not support the desired TLS version.");
  GPR_ASSERT(correct_error_message == 0);

  // Cleanup.
  gpr_free(error_details);
  grpc_core::Delete<grpc_channel>(channel);
}

static void test_incorrect_key_size() {
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
  int correct_error_message = strcmp(error_details,
                                     "The size of the provisioned keys does "
                                     "not match the ciphersuite key size.");
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
      strcmp(error_details, "The s2a_SessionState_parse() method failed.");
  GPR_ASSERT(correct_error_message == 0);

  /** Clean up. **/
  gpr_free(error_details);
  grpc_slice_unref(slice);
  grpc_slice_unref(bad_slice);
  grpc_byte_buffer_destroy(buffer);
}

static void test_create_crypter_success(TLSCiphersuite ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == TLS_CHACHA20_POLY1305_SHA256_ciphersuite) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message = strcmp(
        error_details, "The CHACHA-POLY AEAD crypter is not yet implemented.");
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

static void test_encrypt_record_bad_size(TLSCiphersuite ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == TLS_CHACHA20_POLY1305_SHA256_ciphersuite) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message = strcmp(
        error_details, "The CHACHA-POLY AEAD crypter is not yet implemented.");
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
  size_t test_plaintext_size = 7;
  uint8_t test_plaintext[7] = "123456";
  uint8_t* test_plaintext_pointer = test_plaintext;
  size_t record_allocated_size =
      test_plaintext_size - 2 + s2a_max_record_overhead(crypter);
  uint8_t* record =
      (uint8_t*)gpr_malloc(record_allocated_size * sizeof(uint8_t));
  size_t record_size;
  grpc_status_code insufficient_memory_status =
      s2a_encrypt(crypter, test_plaintext_pointer, test_plaintext_size, record,
                  record_allocated_size, &record_size, &error_details);
  GPR_ASSERT(insufficient_memory_status == GRPC_STATUS_FAILED_PRECONDITION);
  int correct_error_message = strcmp(error_details,
                                     "The plaintext size is too large to fit "
                                     "in the allocated TLS 1.3 record.");
  GPR_ASSERT(correct_error_message == 0);
  gpr_free(error_details);
  error_details = nullptr;
  gpr_free(record);
  record = nullptr;

  /** Test the case when the size of the plaintext is larger than the TLS 1.3
   *  RFC allows; see https://tools.ietf.org/html/rfc8446#section-5.1 . **/
  size_t oversized_plaintext_size = SSL3_RT_MAX_PLAIN_LENGTH + 1;
  uint8_t oversized_plaintext[oversized_plaintext_size];
  uint8_t* oversized_plaintext_pointer = oversized_plaintext;
  record_allocated_size =
      oversized_plaintext_size + s2a_max_record_overhead(crypter);
  record = (uint8_t*)gpr_malloc(record_allocated_size * sizeof(uint8_t));
  grpc_status_code oversized_plaintext_status = s2a_encrypt(
      crypter, oversized_plaintext_pointer, oversized_plaintext_size, record,
      record_allocated_size, &record_size, &error_details);
  GPR_ASSERT(oversized_plaintext_status == GRPC_STATUS_FAILED_PRECONDITION);
  correct_error_message = strcmp(error_details,
                                 "The plaintext size exceeds the maximum "
                                 "plaintext size for a single TLS 1.3 record.");
  GPR_ASSERT(correct_error_message == 0);

  // Cleanup.
  s2a_crypter_destroy(crypter);
  grpc_core::Delete<grpc_channel>(channel);
  gpr_free(record);
  gpr_free(error_details);
}

static void test_encrypt_record_success(TLSCiphersuite ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == TLS_CHACHA20_POLY1305_SHA256_ciphersuite) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message = strcmp(
        error_details, "The CHACHA-POLY AEAD crypter is not yet implemented.");
    GPR_ASSERT(correct_error_message == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  size_t test_plaintext_size = 7 - 1;
  uint8_t test_plaintext[7] = "123456";
  uint8_t* test_plaintext_pointer = test_plaintext;
  size_t record_allocated_size =
      test_plaintext_size + s2a_max_record_overhead(crypter);
  uint8_t* record =
      (uint8_t*)gpr_malloc(record_allocated_size * sizeof(uint8_t));
  size_t record_size;
  grpc_status_code encrypt_status =
      s2a_encrypt(crypter, test_plaintext_pointer, test_plaintext_size, record,
                  record_allocated_size, &record_size, &error_details);
  GPR_ASSERT(encrypt_status == GRPC_STATUS_OK);
  GPR_ASSERT(record_size == expected_message_size(test_plaintext_size));

  bool correct_encrypted_record = check_encrypt_record(
      ciphersuite, record, record_size, nullptr, 0, nullptr, 0, &error_details);
  GPR_ASSERT(correct_encrypted_record);
  GPR_ASSERT(error_details == nullptr);

  // Cleanup.
  s2a_crypter_destroy(crypter);
  grpc_core::Delete<grpc_channel>(channel);
  gpr_free(record);
}

static void test_encrypt_three_records(TLSCiphersuite ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == TLS_CHACHA20_POLY1305_SHA256_ciphersuite) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message = strcmp(
        error_details, "The CHACHA-POLY AEAD crypter is not yet implemented.");
    GPR_ASSERT(correct_error_message == 0);

    // Cleanup.
    s2a_crypter_destroy(crypter);
    gpr_free(error_details);
    grpc_core::Delete<grpc_channel>(channel);
    return;
  }
  GPR_ASSERT(status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);

  size_t test_plaintext_one_size = 7 - 1;
  uint8_t test_plaintext_one[7] = "123456";
  uint8_t* test_plaintext_one_pointer = test_plaintext_one;
  size_t record_one_allocated_size =
      test_plaintext_one_size + s2a_max_record_overhead(crypter);
  uint8_t* record_one =
      (uint8_t*)gpr_malloc(record_one_allocated_size * sizeof(uint8_t));
  size_t record_one_size;
  grpc_status_code encrypt_one_status = s2a_encrypt(
      crypter, test_plaintext_one_pointer, test_plaintext_one_size, record_one,
      record_one_allocated_size, &record_one_size, &error_details);
  GPR_ASSERT(encrypt_one_status == GRPC_STATUS_OK);
  GPR_ASSERT(record_one_size == expected_message_size(test_plaintext_one_size));

  size_t test_plaintext_two_size = 10 - 1;
  uint8_t test_plaintext_two[10] = "789123456";
  uint8_t* test_plaintext_two_pointer = test_plaintext_two;
  size_t record_two_allocated_size =
      test_plaintext_two_size + s2a_max_record_overhead(crypter);
  uint8_t* record_two =
      (uint8_t*)gpr_malloc(record_two_allocated_size * sizeof(uint8_t));
  size_t record_two_size;
  grpc_status_code encrypt_two_status = s2a_encrypt(
      crypter, test_plaintext_two_pointer, test_plaintext_two_size, record_two,
      record_two_allocated_size, &record_two_size, &error_details);
  GPR_ASSERT(encrypt_two_status == GRPC_STATUS_OK);
  GPR_ASSERT(record_two_size == expected_message_size(test_plaintext_two_size));

  size_t test_plaintext_three_size = 5 - 1;
  uint8_t test_plaintext_three[5] = "7891";
  uint8_t* test_plaintext_three_pointer = test_plaintext_three;
  size_t record_three_allocated_size =
      test_plaintext_three_size + s2a_max_record_overhead(crypter);
  uint8_t* record_three =
      (uint8_t*)gpr_malloc(record_three_allocated_size * sizeof(uint8_t));
  size_t record_three_size;
  grpc_status_code encrypt_three_status = s2a_encrypt(
      crypter, test_plaintext_three_pointer, test_plaintext_three_size,
      record_three, record_three_allocated_size, &record_three_size,
      &error_details);
  GPR_ASSERT(encrypt_three_status == GRPC_STATUS_OK);
  GPR_ASSERT(record_three_size ==
             expected_message_size(test_plaintext_three_size));
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

static void test_encrypt_empty_plaintext(TLSCiphersuite ciphersuite) {
  s2a_crypter* crypter = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  char* error_details = nullptr;
  grpc_status_code status =
      setup_crypter(ciphersuite, channel, &crypter, &error_details);
  if (ciphersuite == TLS_CHACHA20_POLY1305_SHA256_ciphersuite) {
    GPR_ASSERT(status == GRPC_STATUS_UNIMPLEMENTED);
    int correct_error_message = strcmp(
        error_details, "The CHACHA-POLY AEAD crypter is not yet implemented.");
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
  uint8_t* test_plaintext_pointer = nullptr;
  size_t record_allocated_size =
      test_plaintext_size + s2a_max_record_overhead(crypter);
  uint8_t* record =
      (uint8_t*)gpr_malloc(record_allocated_size * sizeof(uint8_t));
  size_t record_size;

  /** Encrypt empty plaintext with incorrect plaintext size. **/
  grpc_status_code bad_encrypt_status =
      s2a_encrypt(crypter, test_plaintext_pointer, incorrect_plaintext_size,
                  record, record_allocated_size, &record_size, &error_details);
  GPR_ASSERT(bad_encrypt_status == GRPC_STATUS_INVALID_ARGUMENT);
  int correct_error_message = strcmp(
      error_details,
      "If |plaintext| is nullptr, then |plaintext_size| must be set to zero.");
  GPR_ASSERT(correct_error_message == 0);
  gpr_free(error_details);
  error_details = nullptr;

  /** Encrypt empty plaintext with correct plaintext size. **/
  grpc_status_code encrypt_status =
      s2a_encrypt(crypter, test_plaintext_pointer, test_plaintext_size, record,
                  record_allocated_size, &record_size, &error_details);
  GPR_ASSERT(encrypt_status == GRPC_STATUS_OK);
  GPR_ASSERT(record_size == expected_message_size(test_plaintext_size));
  GPR_ASSERT(check_record_empty_plaintext(ciphersuite, record,
                                          record_size, &error_details));

  // Cleanup.
  s2a_crypter_destroy(crypter);
  grpc_core::Delete<grpc_channel>(channel);
  gpr_free(record);
}

int main(int argc, char** argv) {
  test_incorrect_tls_version();
  test_incorrect_key_size();
  test_deserialize_byte_buffer();
  size_t number_ciphersuites = 3;
  TLSCiphersuite ciphersuite[3] = {TLS_AES_128_GCM_SHA256_ciphersuite,
                                   TLS_AES_256_GCM_SHA384_ciphersuite,
                                   TLS_CHACHA20_POLY1305_SHA256_ciphersuite};
  for (size_t i = 0; i < number_ciphersuites; i++) {
    test_create_crypter_success(ciphersuite[i]);
    test_encrypt_record_bad_size(ciphersuite[i]);
    test_encrypt_record_success(ciphersuite[i]);
    test_encrypt_three_records(ciphersuite[i]);
    test_encrypt_empty_plaintext(ciphersuite[i]);
  }
  return 0;
}
