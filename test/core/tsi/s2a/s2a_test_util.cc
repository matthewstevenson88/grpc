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
#include "src/core/tsi/s2a/record_protocol/s2a_crypter.h"
#include "src/core/tsi/s2a/record_protocol/s2a_crypter_util.h"
#include "src/core/tsi/s2a/s2a_constants.h"

grpc_byte_buffer* create_example_session_state(bool admissible_tls_version,
                                               TLSCiphersuite ciphersuite,
                                               bool has_in_out_key,
                                               bool correct_key_size,
                                               bool has_in_out_sequence,
                                               bool has_in_out_fixed_nonce) {
  upb::Arena arena;
  s2a_SessionState* session_state = s2a_SessionState_new(arena.ptr());

  uint16_t tls_version = admissible_tls_version ? 0 : 1;
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
  uint8_t aes_128_gcm_nonce_bytes[13] = {0xb5, 0x80, 0x3d, 0x82, 0xad,
                                         0x88, 0x54, 0xd2, 0xe5, 0x98,
                                         0x18, 0x7f, 0x00};
  uint8_t aes_256_gcm_nonce_bytes[13] = {0x4d, 0xb1, 0x52, 0xd2, 0x7d,
                                         0x18, 0x0b, 0x1e, 0xe4, 0x8f,
                                         0xa8, 0x9d, 0x00};
  uint8_t chacha_poly_nonce_bytes[13] = {0xb5, 0x80, 0x3d, 0x82, 0xad,
                                         0x88, 0x54, 0xd2, 0xe5, 0x98,
                                         0x18, 0x7f, 0x00};

  if (has_in_out_sequence) {
    s2a_SessionState_set_in_sequence(session_state, 0);
    s2a_SessionState_set_out_sequence(session_state, 0);
  }
  if (has_in_out_key) {
    if (correct_key_size) {
      switch (ciphersuite) {
        case TLS_AES_128_GCM_SHA256_ciphersuite: {
          /** In decimal form, the key bytes are as follows:
           *  {195, 174, 117, 9, 207, 206, 210, 184,
              3, 166, 24, 105, 86, 205, 167, 159}
              followed by the zero byte.
          **/
          s2a_SessionState_set_in_key(
              session_state,
              upb_strview_make((char*)aes_128_gcm_key_bytes, 16));
          s2a_SessionState_set_out_key(
              session_state,
              upb_strview_make((char*)aes_128_gcm_key_bytes, 16));
        } break;
        case TLS_AES_256_GCM_SHA384_ciphersuite: {
          /** In decimal form, the key bytes are as follows:
           *  {218, 199, 49, 174, 72, 102, 103, 126,
           *  210, 246, 92, 73, 14, 24, 129, 123,
           *  229, 203, 187, 208, 63, 89, 122, 213,
           *  144, 65, 193, 23, 183, 49, 16, 154}
              followed by the zero byte.
          **/
          s2a_SessionState_set_in_key(
              session_state,
              upb_strview_make((char*)aes_256_gcm_key_bytes, 32));
          s2a_SessionState_set_out_key(
              session_state,
              upb_strview_make((char*)aes_256_gcm_key_bytes, 32));
        } break;
        case TLS_CHACHA20_POLY1305_SHA256_ciphersuite: {
          /** In decimal form, the key bytes are as follows:
           *  {19, 14, 32, 0, 80, 138, 206, 0,
           *  239, 38, 94, 23, 45, 9, 137, 46,
           *  70, 114, 86, 203, 144, 218, 217, 222,
           *  153, 84, 60, 245, 72, 190, 106, 139}
              followed by the zero byte.
          **/
          s2a_SessionState_set_in_key(
              session_state,
              upb_strview_make((char*)chacha_poly_key_bytes, 32));
          s2a_SessionState_set_out_key(
              session_state,
              upb_strview_make((char*)chacha_poly_key_bytes, 32));
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
        /** In decimal form, the nonce bytes are as follows:
         *  {181, 128, 61, 130, 173, 136, 84, 210,
            229, 152, 24, 127}
            followed by the zero byte.
        **/
        s2a_SessionState_set_in_fixed_nonce(
            session_state,
            upb_strview_make((char*)aes_128_gcm_nonce_bytes, 12));
        s2a_SessionState_set_out_fixed_nonce(
            session_state,
            upb_strview_make((char*)aes_128_gcm_nonce_bytes, 12));
      } break;
      case TLS_AES_256_GCM_SHA384_ciphersuite: {
        /** In decimal form, the nonce bytes are as follows:
           *  {77, 177, 82, 210, 125, 24, 11, 30,
           *  228, 143, 168, 157}
              followed by the zero byte.
          **/
        s2a_SessionState_set_in_fixed_nonce(
            session_state,
            upb_strview_make((char*)aes_256_gcm_nonce_bytes, 12));
        s2a_SessionState_set_out_fixed_nonce(
            session_state,
            upb_strview_make((char*)aes_256_gcm_nonce_bytes, 12));
      } break;
      case TLS_CHACHA20_POLY1305_SHA256_ciphersuite: {
        /** In decimal form, the nonce bytes are as follows:
         *  {181, 128, 61, 130, 173, 136, 84, 210,
         *  229, 152, 24, 127}
            followed by the zero byte.
        **/
        s2a_SessionState_set_in_fixed_nonce(
            session_state,
            upb_strview_make((char*)chacha_poly_nonce_bytes, 12));
        s2a_SessionState_set_out_fixed_nonce(
            session_state,
            upb_strview_make((char*)chacha_poly_nonce_bytes, 12));
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

bool check_encrypt_record(TLSCiphersuite ciphersuite, uint8_t* record_one,
                          size_t record_one_size, uint8_t* record_two,
                          size_t record_two_size, uint8_t* record_three,
                          size_t record_three_size, char** error_details) {
  if (record_one == nullptr && record_one_size != 0) {
    *error_details = gpr_strdup(
        "If |record_one| is nullptr, then |record_one_size| must be zero.");
    return false;
  }
  if (record_two == nullptr && record_two_size != 0) {
    *error_details = gpr_strdup(
        "If |record_two| is nullptr, then |record_two_size| must be zero.");
    return false;
  }
  if (record_three == nullptr && record_three_size != 0) {
    *error_details = gpr_strdup(
        "If |record_three| is nullptr, then |record_three_size| must be zero.");
    return false;
  }
  switch (ciphersuite) {
    case TLS_AES_128_GCM_SHA256_ciphersuite: {
      /**  This record arises from the plaintext 123456 when encrypted using the
       *   AES-128-GCM cipher created by the create_example_session_state
       *   method. In decimal form, the encrypted record is the following:
       *   {23, 3, 3, 0, 23, 242, 228, 228, 17, 172, 103, 96, 228, 227,
       *   240, 116, 163, 101, 116, 196, 94, 228, 193, 144, 97, 3, 219, 13}.
       */
      uint8_t correct_record_one_bytes[28] = {
          0x17, 0x03, 0x03, 0x00, 0x17, 0xf2, 0xe4, 0xe4, 0x11, 0xac,
          0x67, 0x60, 0xe4, 0xe3, 0xf0, 0x74, 0xa3, 0x65, 0x74, 0xc4,
          0x5e, 0xe4, 0xc1, 0x90, 0x61, 0x03, 0xdb, 0x0d};
      GPR_ASSERT(record_one_size == 28);
      for (size_t i = 0; i < record_one_size; i++) {
        GPR_ASSERT(record_one[i] == correct_record_one_bytes[i]);
      }
    } break;
    case TLS_AES_256_GCM_SHA384_ciphersuite: {
      /**  This record arises from the plaintext 123456 when encrypted using the
       *   AES-256-GCM cipher created by the create_example_session_state
       *   method. In decimal form, the encrypted record is the following:
       *   {23, 3, 3, 0, 23, 36, 239, 238, 90, 241, 166, 33, 112, 173, 90, 149,
       *   248, 153, 208, 56, 185, 101, 56, 106, 26, 125, 174, 217}.
       */
      uint8_t correct_record_one_bytes[28] = {
          0x17, 0x03, 0x03, 0x00, 0x17, 0x24, 0xef, 0xee, 0x5a, 0xf1,
          0xa6, 0x21, 0x70, 0xad, 0x5a, 0x95, 0xf8, 0x99, 0xd0, 0x38,
          0xb9, 0x65, 0x38, 0x6a, 0x1a, 0x7d, 0xae, 0xd9};
      GPR_ASSERT(record_one_size == 28);
      for (size_t i = 0; i < record_one_size; i++) {
        GPR_ASSERT(record_one[i] == correct_record_one_bytes[i]);
      }
    } break;
    case TLS_CHACHA20_POLY1305_SHA256_ciphersuite: {
      /**  This record arises from the plaintext 123456 when encrypted using the
       *   CHACHA-POLY cipher created by the create_example_session_state
       *   method. In decimal form, the encrypted record is the following:
       *   {23, 3, 3, 0, 23, 201, 71, 255, 164, 112, 48, 67, 112, 51, 139, 176,
       *   124, 228, 104, 230, 184, 160, 148, 74, 51, 139, 164, 2}.
       */
      uint8_t correct_record_one_bytes[28] = {
          0x17, 0x03, 0x03, 0x00, 0x17, 0xc9, 0x47, 0xff, 0xa4, 0x70,
          0x30, 0x43, 0x70, 0x33, 0x8b, 0xb0, 0x7c, 0xe4, 0x68, 0xe6,
          0xb8, 0xa0, 0x94, 0x4a, 0x33, 0x8b, 0xa4, 0x02};
      GPR_ASSERT(record_one_size == 28);
      for (size_t i = 0; i < record_one_size; i++) {
        GPR_ASSERT(record_one[i] == correct_record_one_bytes[i]);
      }
    } break;
  }
  if (record_two == nullptr && record_three == nullptr) {
    return true;
  }
  switch (ciphersuite) {
    case TLS_AES_128_GCM_SHA256_ciphersuite: {
      /** This record arises from the plaintext 789123456 when encrypted using
       *  the AES-128-GCM cipher created by the create_example_session_state
       *  method. In decimal form, the encrypted record is the following:
       *  {23, 3, 3, 0, 26, 215, 133, 58, 253, 109, 124, 234, 171, 171, 149,
       *  10, 11, 103, 7, 144, 93, 43, 144, 136, 148, 135, 28, 124, 98, 2, 31}.
       */
      uint8_t correct_record_two_bytes[31] = {
          0x17, 0x03, 0x03, 0x00, 0x1a, 0xd7, 0x85, 0x3a, 0xfd, 0x6d, 0x7c,
          0xea, 0xab, 0xab, 0x95, 0x0a, 0x0b, 0x67, 0x07, 0x90, 0x5d, 0x2b,
          0x90, 0x88, 0x94, 0x87, 0x1c, 0x7c, 0x62, 0x02, 0x1f};
      GPR_ASSERT(record_two_size == 31);
      for (size_t i = 0; i < record_two_size; i++) {
        GPR_ASSERT(record_two[i] == correct_record_two_bytes[i]);
      }
    } break;
    case TLS_AES_256_GCM_SHA384_ciphersuite: {
      /** This record arises from the plaintext 789123456 when encrypted using
       *  the AES-256-GCM cipher created by the create_example_session_state
       *  method. In decimal form, the encrypted record is the following:
       *  {23, 3, 3, 0, 26, 131, 42, 95, 210, 113, 182, 68, 46, 116, 188, 2,
       *  17, 26, 142, 139, 82, 167, 75, 20, 221, 62, 202, 133, 152, 178, 147}.
       */
      uint8_t correct_record_two_bytes[31] = {
          0x17, 0x03, 0x03, 0x00, 0x1a, 0x83, 0x2a, 0x5f, 0xd2, 0x71, 0xb6,
          0x44, 0x2e, 0x74, 0xbc, 0x02, 0x11, 0x1a, 0x8e, 0x8b, 0x52, 0xa7,
          0x4b, 0x14, 0xdd, 0x3e, 0xca, 0x85, 0x98, 0xb2, 0x93};
      GPR_ASSERT(record_two_size == 31);
      for (size_t i = 0; i < record_two_size; i++) {
        GPR_ASSERT(record_two[i] == correct_record_two_bytes[i]);
      }
    } break;
    case TLS_CHACHA20_POLY1305_SHA256_ciphersuite: {
      /** This record arises from the plaintext 789123456 when encrypted using
       *  the CHACHA-POLY cipher created by the create_example_session_state
       *  method. In decimal form, the encrypted record is the following:
       *  {23, 3, 3, 0, 26, 12, 237, 235, 146, 33, 112, 193, 16, 193, 114, 38,
       *  37, 66, 198, 121, 22, 183, 143, 160, 209, 193, 38, 23, 9, 205, 0}.
       */
      uint8_t correct_record_two_bytes[31] = {
          0x17, 0x03, 0x03, 0x00, 0x1a, 0x0c, 0xed, 0xeb, 0x92, 0x21, 0x70,
          0xc1, 0x10, 0xc1, 0x72, 0x26, 0x25, 0x42, 0xc6, 0x79, 0x16, 0xb7,
          0x8f, 0xa0, 0xd1, 0xc1, 0x26, 0x17, 0x09, 0xcd, 0x00};
      GPR_ASSERT(record_two_size == 31);
      for (size_t i = 0; i < record_two_size; i++) {
        GPR_ASSERT(record_two[i] == correct_record_two_bytes[i]);
      }
    } break;
  }
  if (record_three == nullptr) {
    return true;
  }
  switch (ciphersuite) {
    case TLS_AES_128_GCM_SHA256_ciphersuite: {
      /**  This record arises from the plaintext 7891 when encrypted using the
       *   AES-128-GCM cipher created by the create_example_session_state
       *   method. In decimal form, the encrypted record is the following:
       *   {23, 3, 3, 0, 21, 175, 119, 139, 14, 214, 110, 254, 231, 19, 251,
       *   237, 162, 53, 123, 131, 47, 117, 149, 0, 238, 205}.
       */
      uint8_t correct_record_three_bytes[26] = {
          0x17, 0x03, 0x03, 0x00, 0x15, 0xaf, 0x77, 0x8b, 0xe,
          0xd6, 0x6e, 0xfe, 0xe7, 0x13, 0xfb, 0xed, 0xa2, 0x35,
          0x7b, 0x83, 0x2f, 0x75, 0x95, 0x00, 0xee, 0xcd};
      GPR_ASSERT(record_three_size == 26);
      for (size_t i = 0; i < record_three_size; i++) {
        GPR_ASSERT(record_three[i] == correct_record_three_bytes[i]);
      }
    } break;
    case TLS_AES_256_GCM_SHA384_ciphersuite: {
      /**  This record arises from the plaintext 7891 when encrypted using the
       *   AES-256-GCM cipher created by the create_example_session_state
       *   method. In decimal form, the encrypted record is the following:
       *   {23, 3, 3, 0, 21, 150, 203, 132, 204, 93, 189, 39, 165, 19, 198,
       *   210, 35, 204, 15, 74, 88, 64, 225, 126, 86, 216}.
       */
      uint8_t correct_record_three_bytes[26] = {
          0x17, 0x03, 0x03, 0x00, 0x15, 0x96, 0xcb, 0x84, 0xcc,
          0x5d, 0xbd, 0x27, 0xa5, 0x13, 0xc6, 0xd2, 0x23, 0xcc,
          0x0f, 0x4a, 0x58, 0x40, 0xe1, 0x7e, 0x56, 0xd8};
      GPR_ASSERT(record_three_size == 26);
      for (size_t i = 0; i < record_three_size; i++) {
        GPR_ASSERT(record_three[i] == correct_record_three_bytes[i]);
      }
    } break;
    case TLS_CHACHA20_POLY1305_SHA256_ciphersuite: {
      /**  This record arises from the plaintext 7891 when encrypted using the
       *   CHACHA-POLY cipher created by the create_example_session_state
       *   method. In decimal form, the encrypted record is the following:
       *   {23, 3, 3, 0, 21, 146, 74, 83, 67, 207, 29, 198, 149, 9, 73, 65,
       *   171, 161, 108, 108, 36, 48, 92, 200, 64, 138}.
       */
      uint8_t correct_record_three_bytes[26] = {
          0x17, 0x03, 0x03, 0x00, 0x15, 0x92, 0x4a, 0x53, 0x43,
          0xcf, 0x1d, 0xc6, 0x95, 0x09, 0x49, 0x41, 0xab, 0xa1,
          0x6c, 0x6c, 0x24, 0x30, 0x5c, 0xc8, 0x40, 0x8a};
      GPR_ASSERT(record_three_size == 26);
      for (size_t i = 0; i < record_three_size; i++) {
        GPR_ASSERT(record_three[i] == correct_record_three_bytes[i]);
      }
    } break;
  }
  return true;
}
