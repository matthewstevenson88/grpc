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
      0x7a, 0xd5, 0x90, 0x41, 0xc1, 0x17, 0xb7, 0x32, 0x10, 0x9a, 0x00};
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
