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
#include <stdlib.h>
#include <grpc/support/log.h>
#include <grpc/support/string_util.h>
#include <openssl/ssl3.h>
#include "src/core/tsi/s2a/record_protocol/s2a_crypter.h"
#include "src/core/tsi/s2a/record_protocol/s2a_crypter_util.h"
#include "src/core/tsi/s2a/s2a_constants.h"

uint8_t aes_128_gcm_key_bytes[17] = {0xc3, 0xae, 0x75, 0x09, 0xcf, 0xce,
                                     0xd2, 0xb8, 0x03, 0xa6, 0x18, 0x69,
                                     0x56, 0xcd, 0xa7, 0x9f, 0x00};
uint8_t aes_256_gcm_key_bytes[33] = {
    0xda, 0xc7, 0x31, 0xae, 0x48, 0x66, 0x67, 0x7e, 0xd2, 0xf6, 0x5c,
    0x49, 0x0e, 0x18, 0x81, 0x7b, 0xe5, 0xcb, 0xbb, 0xd0, 0x3f, 0x59,
    0x7a, 0xd5, 0x90, 0x41, 0xc1, 0x17, 0xb7, 0x31, 0x10, 0x9a, 0x00};
uint8_t chacha_poly_key_bytes[33] = {
    0x13, 0x0e, 0x20, 0x00, 0x50, 0x8a, 0xce, 0x00, 0xef, 0x26, 0x5e,
    0x17, 0x2d, 0x09, 0x89, 0x2e, 0x46, 0x72, 0x56, 0xcb, 0x90, 0xda,
    0xd9, 0xde, 0x99, 0x53, 0x3c, 0xf5, 0x48, 0xbe, 0x6a, 0x8b, 0x00};
uint8_t aes_128_gcm_nonce_bytes[13] = {0xb5, 0x80, 0x3d, 0x82, 0xad, 0x88, 0x54,
                                       0xd2, 0xe5, 0x98, 0x18, 0x7f, 0x00};
uint8_t aes_256_gcm_nonce_bytes[13] = {0x4d, 0xb1, 0x52, 0xd2, 0x7d, 0x18, 0x0b,
                                       0x1e, 0xe4, 0x8f, 0xa8, 0x9d, 0x00};
uint8_t chacha_poly_nonce_bytes[13] = {0xb5, 0x80, 0x3d, 0x82, 0xad, 0x88, 0x54,
                                       0xd2, 0xe5, 0x98, 0x18, 0x7f, 0x00};

const size_t correct_record_one_size = 28;
uint8_t aes_128_gcm_record_one_bytes[correct_record_one_size] = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0xf2, 0xe4, 0xe4, 0x11, 0xac,
    0x67, 0x60, 0xe4, 0xe3, 0xf0, 0x74, 0xa3, 0x65, 0x74, 0xc4,
    0x5e, 0xe4, 0xc1, 0x90, 0x61, 0x03, 0xdb, 0x0d};
uint8_t aes_256_gcm_record_one_bytes[correct_record_one_size] = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0x24, 0xef, 0xee, 0x5a, 0xf1,
    0xa6, 0x21, 0x70, 0xad, 0x5a, 0x95, 0xf8, 0x99, 0xd0, 0x38,
    0xb9, 0x65, 0x38, 0x6a, 0x1a, 0x7d, 0xae, 0xd9};
uint8_t chacha_poly_record_one_bytes[correct_record_one_size] = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0xc9, 0x47, 0xff, 0xa4, 0x70,
    0x30, 0x43, 0x70, 0x33, 0x8b, 0xb0, 0x7c, 0xe4, 0x68, 0xe6,
    0xb8, 0xa0, 0x94, 0x4a, 0x33, 0x8b, 0xa4, 0x02};

const size_t correct_record_two_size = 31;
uint8_t aes_128_gcm_record_two_bytes[correct_record_two_size] = {
    0x17, 0x03, 0x03, 0x00, 0x1a, 0xd7, 0x85, 0x3a, 0xfd, 0x6d, 0x7c,
    0xea, 0xab, 0xab, 0x95, 0x0a, 0x0b, 0x67, 0x07, 0x90, 0x5d, 0x2b,
    0x90, 0x88, 0x94, 0x87, 0x1c, 0x7c, 0x62, 0x02, 0x1f};
uint8_t aes_256_gcm_record_two_bytes[correct_record_two_size] = {
    0x17, 0x03, 0x03, 0x00, 0x1a, 0x83, 0x2a, 0x5f, 0xd2, 0x71, 0xb6,
    0x44, 0x2e, 0x74, 0xbc, 0x02, 0x11, 0x1a, 0x8e, 0x8b, 0x52, 0xa7,
    0x4b, 0x14, 0xdd, 0x3e, 0xca, 0x85, 0x98, 0xb2, 0x93};
uint8_t chacha_poly_record_two_bytes[correct_record_two_size] = {
    0x17, 0x03, 0x03, 0x00, 0x1a, 0x0c, 0xed, 0xeb, 0x92, 0x21, 0x70,
    0xc1, 0x10, 0xc1, 0x72, 0x26, 0x25, 0x42, 0xc6, 0x79, 0x16, 0xb7,
    0x8f, 0xa0, 0xd1, 0xc1, 0x26, 0x17, 0x09, 0xcd, 0x00};

const size_t correct_record_three_size = 26;
uint8_t aes_128_gcm_record_three_bytes[correct_record_three_size] = {
    0x17, 0x03, 0x03, 0x00, 0x15, 0xaf, 0x77, 0x8b, 0xe,
    0xd6, 0x6e, 0xfe, 0xe7, 0x13, 0xfb, 0xed, 0xa2, 0x35,
    0x7b, 0x83, 0x2f, 0x75, 0x95, 0x00, 0xee, 0xcd};
uint8_t aes_256_gcm_record_three_bytes[correct_record_three_size] = {
    0x17, 0x03, 0x03, 0x00, 0x15, 0x96, 0xcb, 0x84, 0xcc,
    0x5d, 0xbd, 0x27, 0xa5, 0x13, 0xc6, 0xd2, 0x23, 0xcc,
    0x0f, 0x4a, 0x58, 0x40, 0xe1, 0x7e, 0x56, 0xd8};
uint8_t chacha_poly_record_three_bytes[correct_record_three_size] = {
    0x17, 0x03, 0x03, 0x00, 0x15, 0x92, 0x4a, 0x53, 0x43,
    0xcf, 0x1d, 0xc6, 0x95, 0x09, 0x49, 0x41, 0xab, 0xa1,
    0x6c, 0x6c, 0x24, 0x30, 0x5c, 0xc8, 0x40, 0x8a};

const size_t empty_record_size = 22;
uint8_t aes_128_gcm_empty_record_bytes[empty_record_size] = {
    0x17, 0x03, 0x03, 0x00, 0x11, 0xd4, 0x7c, 0xb2, 0xec, 0x04, 0x0f,
    0x26, 0xcc, 0x89, 0x89, 0x33, 0x03, 0x39, 0xc6, 0x69, 0xdd, 0x4e};

uint8_t aes_256_gcm_empty_record_bytes[empty_record_size] = {
    0x17, 0x03, 0x03, 0x00, 0x11, 0x02, 0xa0, 0x41, 0x34, 0xd3, 0x8c,
    0x11, 0x18, 0xf3, 0x6b, 0x01, 0xd1, 0x77, 0xc5, 0xd2, 0xdc, 0xf7};
uint8_t chacha_poly_empty_record_bytes[empty_record_size] = {
    0x17, 0x03, 0x03, 0x00, 0x11, 0xef, 0x8f, 0x7a, 0x42, 0x8d, 0xdc,
    0x84, 0xee, 0x59, 0x68, 0xcd, 0x63, 0x06, 0xbf, 0x1d, 0x2d, 0x1b};

grpc_byte_buffer* create_example_session_state(bool admissible_tls_version,
                                               TLSCiphersuite ciphersuite,
                                               bool has_in_out_key,
                                               bool correct_key_size,
                                               bool has_in_out_sequence,
                                               bool has_in_out_fixed_nonce) {
  upb::Arena arena;
  s2a_SessionState* session_state = s2a_SessionState_new(arena.ptr());

  uint16_t tls_version = admissible_tls_version ?
                                                /** TLS 1.3 **/ 0
                                                : /** TLS 1.2 **/ 1;
  uint16_t tls_ciphersuite;
  switch (ciphersuite) {
    case TLS_AES_128_GCM_SHA256_ciphersuite:
      tls_ciphersuite = TLS_AES_128_GCM_SHA256;
      break;
    case TLS_AES_256_GCM_SHA384_ciphersuite:
      tls_ciphersuite = TLS_AES_256_GCM_SHA384;
      break;
    case TLS_CHACHA20_POLY1305_SHA256_ciphersuite:
      tls_ciphersuite = TLS_CHACHA20_POLY1305_SHA256;
      break;
  }

  s2a_SessionState_set_tls_version(session_state, (int32_t)tls_version);
  s2a_SessionState_set_tls_ciphersuite(session_state, (int32_t)tls_ciphersuite);

  if (has_in_out_sequence) {
    s2a_SessionState_set_in_sequence(session_state, 0);
    s2a_SessionState_set_out_sequence(session_state, 0);
  }
  if (has_in_out_key) {
    if (correct_key_size) {
      switch (ciphersuite) {
        case TLS_AES_128_GCM_SHA256_ciphersuite: {
          s2a_SessionState_set_in_key(
              session_state, upb_strview_make((char*)aes_128_gcm_key_bytes,
                                              /** key size **/ 16));
          s2a_SessionState_set_out_key(
              session_state, upb_strview_make((char*)aes_128_gcm_key_bytes,
                                              /** key size **/ 16));
        } break;
        case TLS_AES_256_GCM_SHA384_ciphersuite: {
          s2a_SessionState_set_in_key(
              session_state, upb_strview_make((char*)aes_256_gcm_key_bytes,
                                              /** key size **/ 32));
          s2a_SessionState_set_out_key(
              session_state, upb_strview_make((char*)aes_256_gcm_key_bytes,
                                              /** key size **/ 32));
        } break;
        case TLS_CHACHA20_POLY1305_SHA256_ciphersuite: {
          s2a_SessionState_set_in_key(
              session_state, upb_strview_make((char*)chacha_poly_key_bytes,
                                              /** key size **/ 32));
          s2a_SessionState_set_out_key(
              session_state, upb_strview_make((char*)chacha_poly_key_bytes,
                                              /** key size **/ 32));
        } break;
      }
    } else {
      const char* key = (ciphersuite == TLS_AES_128_GCM_SHA256_ciphersuite)
                            ? "kkkkkkkkkkkkkkkkj"
                            : "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkj";
      s2a_SessionState_set_in_key(session_state, upb_strview_makez(key));
      s2a_SessionState_set_out_key(session_state, upb_strview_makez(key));
    }
  }
  if (has_in_out_fixed_nonce) {
    switch (ciphersuite) {
      case TLS_AES_128_GCM_SHA256_ciphersuite: {
        s2a_SessionState_set_in_fixed_nonce(
            session_state, upb_strview_make((char*)aes_128_gcm_nonce_bytes,
                                            /** nonce size **/ 12));
        s2a_SessionState_set_out_fixed_nonce(
            session_state, upb_strview_make((char*)aes_128_gcm_nonce_bytes,
                                            /** nonce size **/ 12));
      } break;
      case TLS_AES_256_GCM_SHA384_ciphersuite: {
        s2a_SessionState_set_in_fixed_nonce(
            session_state, upb_strview_make((char*)aes_256_gcm_nonce_bytes,
                                            /** nonce size **/ 12));
        s2a_SessionState_set_out_fixed_nonce(
            session_state, upb_strview_make((char*)aes_256_gcm_nonce_bytes,
                                            /** nonce size **/ 12));
      } break;
      case TLS_CHACHA20_POLY1305_SHA256_ciphersuite: {
        s2a_SessionState_set_in_fixed_nonce(
            session_state, upb_strview_make((char*)chacha_poly_nonce_bytes,
                                            /** nonce size **/ 12));
        s2a_SessionState_set_out_fixed_nonce(
            session_state, upb_strview_make((char*)chacha_poly_nonce_bytes,
                                            /** nonce size **/ 12));
      } break;
    }
  }
  size_t buf_size;
  char* buf = s2a_SessionState_serialize(session_state, arena.ptr(), &buf_size);
  grpc_slice slice = gpr_slice_from_copied_buffer(buf, buf_size);
  grpc_byte_buffer* buffer =
      grpc_raw_byte_buffer_create(&slice, 1 /* number of slices */);
  grpc_slice_unref(slice);
  return buffer;
}

size_t expected_message_size(size_t plaintext_size) {
  /** This is the expected size of any TLS 1.3 record. It is independent of the
   *  TLS ciphersuite that is used. **/
  return 5u /* header */ + plaintext_size + 16u /* tag */ +
         1u /* record type */;
}

void verify_record(uint8_t* record, size_t record_size, uint8_t* correct_record,
                   size_t correct_record_size) {
  GPR_ASSERT(record_size == correct_record_size);
  for (size_t i = 0; i < record_size; i++) {
    GPR_ASSERT(record[i] == correct_record[i]);
  }
}

bool check_encrypt_record(TLSCiphersuite ciphersuite, uint8_t* record_one,
                          size_t record_one_size, uint8_t* record_two,
                          size_t record_two_size, uint8_t* record_three,
                          size_t record_three_size, char** error_details) {
  if (record_one == nullptr) {
    GPR_ASSERT(record_one_size == 0);
  }
  if (record_two == nullptr) {
    GPR_ASSERT(record_two_size == 0);
  }
  if (record_three == nullptr) {
    GPR_ASSERT(record_three_size == 0);
  }
  switch (ciphersuite) {
    case TLS_AES_128_GCM_SHA256_ciphersuite:
      verify_record(record_one, record_one_size, aes_128_gcm_record_one_bytes,
                    correct_record_one_size);
      break;
    case TLS_AES_256_GCM_SHA384_ciphersuite:
      verify_record(record_one, record_one_size, aes_256_gcm_record_one_bytes,
                    correct_record_one_size);
      break;
    case TLS_CHACHA20_POLY1305_SHA256_ciphersuite:
      verify_record(record_one, record_one_size, chacha_poly_record_one_bytes,
                    correct_record_one_size);
      break;
  }
  if (record_two == nullptr && record_three == nullptr) {
    return true;
  }
  switch (ciphersuite) {
    case TLS_AES_128_GCM_SHA256_ciphersuite:
      verify_record(record_two, record_two_size, aes_128_gcm_record_two_bytes,
                    correct_record_two_size);
      break;
    case TLS_AES_256_GCM_SHA384_ciphersuite:
      verify_record(record_two, record_two_size, aes_256_gcm_record_two_bytes,
                    correct_record_two_size);
      break;
    case TLS_CHACHA20_POLY1305_SHA256_ciphersuite:
      verify_record(record_two, record_two_size, chacha_poly_record_two_bytes,
                    correct_record_two_size);
      break;
  }
  if (record_three == nullptr) {
    return true;
  }
  switch (ciphersuite) {
    case TLS_AES_128_GCM_SHA256_ciphersuite:
      verify_record(record_three, record_three_size,
                    aes_128_gcm_record_three_bytes, correct_record_three_size);
      break;
    case TLS_AES_256_GCM_SHA384_ciphersuite:
      verify_record(record_three, record_three_size,
                    aes_256_gcm_record_three_bytes, correct_record_three_size);
      break;
    case TLS_CHACHA20_POLY1305_SHA256_ciphersuite:
      verify_record(record_three, record_three_size,
                    chacha_poly_record_three_bytes, correct_record_three_size);
      break;
  }
  return true;
}

bool check_record_empty_plaintext(TLSCiphersuite ciphersuite, uint8_t* record,
                                  size_t record_size, char** error_details) {
  if (record == nullptr) {
    GPR_ASSERT(record_size == 0);
  }
  switch (ciphersuite) {
    case TLS_AES_128_GCM_SHA256_ciphersuite:
      verify_record(record, record_size, aes_128_gcm_empty_record_bytes,
                    empty_record_size);
      break;
    case TLS_AES_256_GCM_SHA384_ciphersuite:
      verify_record(record, record_size, aes_256_gcm_empty_record_bytes,
                    empty_record_size);
      break;
    case TLS_CHACHA20_POLY1305_SHA256_ciphersuite:
      verify_record(record, record_size, chacha_poly_empty_record_bytes,
                    empty_record_size);
      break;
  }
  return true;
}

void random_array(uint8_t** bytes, size_t length) {
  GPR_ASSERT(bytes != nullptr);
  *bytes = (uint8_t*)gpr_malloc(length * sizeof(uint8_t));
  for (size_t i = 0; i < length; i++) {
    (*bytes)[i] = static_cast<uint8_t>(rand() % 255 + 1);
  }
}

void send_random_message(size_t message_size, s2a_crypter* out_crypter,
                         s2a_crypter* in_crypter) {
  GPR_ASSERT(out_crypter != nullptr && in_crypter != nullptr);
  GPR_ASSERT(out_crypter != in_crypter);
  GPR_ASSERT(message_size <=
             SSL3_RT_MAX_PLAIN_LENGTH + s2a_max_record_overhead(out_crypter));
  uint8_t* message = nullptr;
  random_array(&message, message_size);
  if (message_size > 0) {
    GPR_ASSERT(message != nullptr);
  }

  size_t record_allocated_size =
      message_size + s2a_max_record_overhead(out_crypter);
  uint8_t* record =
      (uint8_t*)gpr_malloc(record_allocated_size * sizeof(uint8_t));
  size_t record_size;

  char* error_details = nullptr;
  grpc_status_code encrypt_status =
      s2a_encrypt(out_crypter, message, message_size, record,
                  record_allocated_size, &record_size, &error_details);
  GPR_ASSERT(encrypt_status == GRPC_STATUS_OK);
  GPR_ASSERT(error_details == nullptr);
  GPR_ASSERT(record_size == expected_message_size(message_size));

  size_t plaintext_allocated_size =
      s2a_max_plaintext_size(in_crypter, record_size);
  uint8_t* plaintext =
      (uint8_t*)gpr_malloc(plaintext_allocated_size * sizeof(uint8_t));
  size_t plaintext_size;
/**  s2a_decrypt_status decrypt_status =
      s2a_decrypt(in_crypter, record, record_size, plaintext,
                  plaintext_allocated_size, &plaintext_size, &error_details);
  GPR_ASSERT(decrypt_status == OK);
  GPR_ASSERT(error_details == nullptr);
  GPR_ASSERT(plaintext_size == message_size);
  GPR_ASSERT(memcmp(plaintext, message, plaintext_size) == 0);
**/
  // Cleanup.
  gpr_free(message);
  gpr_free(record);
  gpr_free(plaintext);
}

grpc_status_code create_random_crypter_pair(TLSCiphersuite ciphersuite,
                                s2a_crypter** crypter_one,
                                s2a_crypter** crypter_two,
                                grpc_channel* channel) {
  if (ciphersuite == TLS_CHACHA20_POLY1305_SHA256_ciphersuite) {
    return GRPC_STATUS_UNIMPLEMENTED;
  }

  size_t key_size;
  size_t nonce_size;
  uint16_t tls_ciphersuite;
  switch (ciphersuite) {
    case TLS_AES_128_GCM_SHA256_ciphersuite:
      tls_ciphersuite = TLS_AES_128_GCM_SHA256;
      key_size = TLS_AES_128_GCM_SHA256_KEY_SIZE;
      nonce_size = TLS_AES_128_GCM_SHA256_NONCE_SIZE;
      break;
    case TLS_AES_256_GCM_SHA384_ciphersuite:
      tls_ciphersuite = TLS_AES_256_GCM_SHA384;
      key_size = TLS_AES_256_GCM_SHA384_KEY_SIZE;
      nonce_size = TLS_AES_256_GCM_SHA384_NONCE_SIZE;
      break;
    case TLS_CHACHA20_POLY1305_SHA256_ciphersuite:
      tls_ciphersuite = TLS_CHACHA20_POLY1305_SHA256;
      key_size = TLS_CHACHA20_POLY1305_SHA256_KEY_SIZE;
      nonce_size = TLS_CHACHA20_POLY1305_SHA256_NONCE_SIZE;
      break;
    default:
      return GRPC_STATUS_INVALID_ARGUMENT;
  }
  uint8_t* key_one;
  uint8_t* key_two;
  uint8_t* nonce_one;
  uint8_t* nonce_two;
  random_array(&key_one, key_size);
  random_array(&key_two, key_size);
  random_array(&nonce_one, nonce_size);
  random_array(&nonce_two, nonce_size);

  char* error_details = nullptr;
  grpc_status_code in_status = s2a_crypter_create(/** tls_version **/ 0,
                                                  tls_ciphersuite,
                                                  key_one, key_two, key_size,
                                                  nonce_one, nonce_two, nonce_size,
                                                  channel, crypter_one, &error_details);
  GPR_ASSERT(in_status == GRPC_STATUS_OK);

  grpc_status_code out_status = s2a_crypter_create(/** tls_version **/ 0,
                                                   tls_ciphersuite,
                                                   key_two, key_one, key_size,
                                                   nonce_two, nonce_one, nonce_size,
                                                   channel, crypter_two, &error_details);
  GPR_ASSERT(out_status == GRPC_STATUS_OK);

  gpr_free(key_one);
  gpr_free(key_two);
  gpr_free(nonce_one);
  gpr_free(nonce_two);
  return GRPC_STATUS_OK;
}
