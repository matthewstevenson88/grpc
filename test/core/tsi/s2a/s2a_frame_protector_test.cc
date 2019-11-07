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

#include <grpc/slice.h>
#include <grpc/slice_buffer.h>
#include <grpc/support/alloc.h>
#include <grpc/support/log.h>
#include <grpc/support/string_util.h>
#include <openssl/ssl3.h>

#include "src/core/lib/gprpp/memory.h"
#include "src/core/lib/iomgr/exec_ctx.h"
#include "src/core/lib/slice/slice_internal.h"
#include "src/core/lib/surface/channel.h"
#include "src/core/tsi/s2a/frame_protector/s2a_frame_protector.h"
#include "src/core/tsi/s2a/record_protocol/s2a_crypter_util.h"
#include "src/core/tsi/s2a/s2a_constants.h"
#include "src/core/tsi/transport_security_grpc.h"
#include "test/core/tsi/s2a/s2a_test_util.h"

static void s2a_zero_copy_grpc_protector_create_test(
    TLSCiphersuite ciphersuite) {
  grpc_core::ExecCtx exec_ctx;
  uint16_t tls_ciphersuite;
  char* key;
  size_t key_size;
  char* nonce;
  size_t nonce_size;
  size_t tag_size;
  switch (ciphersuite) {
    case TLS_AES_128_GCM_SHA256_ciphersuite:
      tls_ciphersuite = TLS_AES_128_GCM_SHA256;
      key = gpr_strdup("aes_128_key_aaaa");
      key_size = TLS_AES_128_GCM_SHA256_KEY_SIZE;
      nonce = gpr_strdup("aes_128_nonc");
      nonce_size = TLS_AES_128_GCM_SHA256_NONCE_SIZE;
      tag_size = EVP_AEAD_AES_GCM_TAG_LEN;
      break;
    case TLS_AES_256_GCM_SHA384_ciphersuite:
      tls_ciphersuite = TLS_AES_256_GCM_SHA384;
      key = gpr_strdup("aes_256_key_aaaaaaaaaaaaaaaaaaaa");
      key_size = TLS_AES_256_GCM_SHA384_KEY_SIZE;
      nonce = gpr_strdup("aes_256_nonc");
      nonce_size = TLS_AES_256_GCM_SHA384_NONCE_SIZE;
      tag_size = EVP_AEAD_AES_GCM_TAG_LEN;
      break;
    case TLS_CHACHA20_POLY1305_SHA256_ciphersuite:
      tls_ciphersuite = TLS_CHACHA20_POLY1305_SHA256;
      key = gpr_strdup("chacha20_key_aaaaaaaaaaaaaaaaaaa");
      key_size = TLS_CHACHA20_POLY1305_SHA256_KEY_SIZE;
      nonce = gpr_strdup("chacha20_non");
      nonce_size = TLS_CHACHA20_POLY1305_SHA256_NONCE_SIZE;
      tag_size = POLY1305_TAG_LEN;
      break;
  }
  tsi_zero_copy_grpc_protector* protector = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();

  /** Attempt to create an s2a_zero_copy_grpc_protector instance using
   *  nullptr arguments. **/
  tsi_result create_result = s2a_zero_copy_grpc_protector_create(
      /** tls_version **/ 0, tls_ciphersuite, (uint8_t*)key, (uint8_t*)key,
      key_size, (uint8_t*)nonce, (uint8_t*)nonce, nonce_size, channel,
      nullptr);
  GPR_ASSERT(create_result == TSI_INVALID_ARGUMENT);

  create_result = s2a_zero_copy_grpc_protector_create(
      /** tls_version **/ 0, tls_ciphersuite, nullptr, (uint8_t*)key,
      key_size, (uint8_t*)nonce, (uint8_t*)nonce, nonce_size, channel,
      &protector);
  GPR_ASSERT(create_result == TSI_INVALID_ARGUMENT);

  create_result = s2a_zero_copy_grpc_protector_create(
      /** tls_version **/ 0, tls_ciphersuite, (uint8_t*)key, nullptr,
      key_size, (uint8_t*)nonce, (uint8_t*)nonce, nonce_size, channel,
      &protector);
  GPR_ASSERT(create_result == TSI_INVALID_ARGUMENT);

  create_result = s2a_zero_copy_grpc_protector_create(
      /** tls_version **/ 0, tls_ciphersuite, (uint8_t*)key, (uint8_t*)key,
      key_size, nullptr, (uint8_t*)nonce, nonce_size, channel,
      &protector);
  GPR_ASSERT(create_result == TSI_INVALID_ARGUMENT);

  create_result = s2a_zero_copy_grpc_protector_create(
      /** tls_version **/ 0, tls_ciphersuite, (uint8_t*)key, (uint8_t*)key,
      key_size, (uint8_t*)nonce, nullptr, nonce_size, channel,
      &protector);
  GPR_ASSERT(create_result == TSI_INVALID_ARGUMENT);

  create_result = s2a_zero_copy_grpc_protector_create(
      /** tls_version **/ 0, tls_ciphersuite, (uint8_t*)key, (uint8_t*)key,
      key_size, (uint8_t*)nonce, (uint8_t*)nonce, nonce_size, nullptr,
      &protector);
  GPR_ASSERT(create_result == TSI_INVALID_ARGUMENT);
  GPR_ASSERT(protector == nullptr);

  /** Attempt to create an s2a_zero_copy_grpc_protector instance using
   *  an invalid TLS version. **/
  create_result = s2a_zero_copy_grpc_protector_create(
      /** tls_version **/ 1, tls_ciphersuite, (uint8_t*)key, (uint8_t*)key,
      key_size, (uint8_t*)nonce, (uint8_t*)nonce, nonce_size, channel,
      &protector);
  GPR_ASSERT(create_result == TSI_FAILED_PRECONDITION);
  GPR_ASSERT(protector == nullptr);

  /** Attempt to create an s2a_zero_copy_grpc_protector instance using
   *  an incorrect key size. **/
  create_result = s2a_zero_copy_grpc_protector_create(
      /** tls_version **/ 0, tls_ciphersuite, (uint8_t*)key, (uint8_t*)key,
      key_size + 1, (uint8_t*)nonce, (uint8_t*)nonce, nonce_size, channel,
      &protector);
  GPR_ASSERT(create_result == TSI_FAILED_PRECONDITION);
  GPR_ASSERT(protector == nullptr);

  /** Successfully create an s2a_zero_copy_grpc_protector instance. **/
  create_result = s2a_zero_copy_grpc_protector_create(
      /** tls_version **/ 0, tls_ciphersuite, (uint8_t*)key, (uint8_t*)key,
      key_size, (uint8_t*)nonce, (uint8_t*)nonce, nonce_size, channel,
      &protector);
  if (ciphersuite == TLS_CHACHA20_POLY1305_SHA256_ciphersuite) {
    // The CHACHA-POLY ciphersuite is not yet supported.
    GPR_ASSERT(create_result == TSI_UNIMPLEMENTED);
    GPR_ASSERT(protector == nullptr);
  } else {
    GPR_ASSERT(create_result == TSI_OK);
    GPR_ASSERT(protector != nullptr);
    size_t max_protected_frame_size =
        SSL3_RT_HEADER_LENGTH + SSL3_RT_MAX_PLAIN_LENGTH + 1 + tag_size;
    size_t actual_max_protected_frame_size;
    GPR_ASSERT(tsi_zero_copy_grpc_protector_max_frame_size(
                   protector, actual_max_protected_frame_size) == TSI_OK);
    GPR_ASSERT(max_protected_frame_size == actual_max_protected_frame_size);
  }

  tsi_zero_copy_grpc_protector_destroy(protector);
  grpc_core::Delete<grpc_channel>(channel);
  gpr_free(key);
  gpr_free(nonce);
  grpc_core::ExecCtx::Get()->Flush();
  return;
}

static tsi_result setup_protector(TLSCiphersuite ciphersuite,
                                  grpc_channel* channel,
                                  tsi_zero_copy_grpc_protector** protector) {
  grpc_byte_buffer* session_state_buffer = create_example_session_state(
      /** admissible_tls_version **/ true, ciphersuite,
      /** has_in_out_key **/ true, /** correct_key_size **/ true,
      /** has_in_out_sequence **/ true, /** has_in_out_fixed_nonce **/ true);
  upb::Arena arena;
  s2a_SessionState* session_state = nullptr;
  char* error_details = nullptr;
  grpc_status_code deserialize_status = s2a_deserialize_session_state(
      session_state_buffer, arena.ptr(), &session_state, &error_details);
  GPR_ASSERT(deserialize_status == GRPC_STATUS_OK);
  GPR_ASSERT(session_state != nullptr);
  GPR_ASSERT(error_details == nullptr);
  grpc_byte_buffer_destroy(session_state_buffer);

  upb_strview in_key = s2a_SessionState_in_key(session_state);
  upb_strview out_key = s2a_SessionState_out_key(session_state);
  size_t key_size;
  if (in_key.size != out_key.size) {
    return TSI_INTERNAL_ERROR;
  } else {
    key_size = in_key.size;
  }
  upb_strview in_nonce = s2a_SessionState_in_fixed_nonce(session_state);
  upb_strview out_nonce = s2a_SessionState_out_fixed_nonce(session_state);
  size_t nonce_size;
  if (in_nonce.size != out_nonce.size) {
    return TSI_INTERNAL_ERROR;
  } else {
    nonce_size = in_nonce.size;
  }

  return s2a_zero_copy_grpc_protector_create(
      s2a_SessionState_tls_version(session_state),
      s2a_SessionState_tls_ciphersuite(session_state),
      (uint8_t*)in_key.data, (uint8_t*)out_key.data,
      key_size, (uint8_t*)in_nonce.data,
      (uint8_t*)out_nonce.data, nonce_size,
      channel, protector);
}

static void s2a_zero_copy_grpc_protector_small_protect_test(TLSCiphersuite ciphersuite) {
  grpc_core::ExecCtx exec_ctx;
  tsi_zero_copy_grpc_protector* protector = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  tsi_result create_result = setup_protector(ciphersuite, channel,
                                             &protector);
  if (ciphersuite == TLS_CHACHA20_POLY1305_SHA256_ciphersuite) {
    GPR_ASSERT(create_result == TSI_UNIMPLEMENTED);

    // Cleanup.
    tsi_zero_copy_grpc_protector_destroy(protector);
    grpc_core::Delete<grpc_channel>(channel);
    grpc_core::ExecCtx::Get()->Flush();
    return;
  }
  GPR_ASSERT(create_result == TSI_OK);

  size_t test_plaintext_size = 6;
  uint8_t test_plaintext[7] = "123456";
  grpc_slice test_slice = grpc_slice_from_static_buffer(test_plaintext,
                                                        test_plaintext_size);
  grpc_slice_buffer plaintext_buffer;
  grpc_slice_buffer_init(&plaintext_buffer);
  grpc_slice_buffer_add(&plaintext_buffer, test_slice);
  grpc_slice_buffer record_buffer;
  grpc_slice_buffer_init(&record_buffer);

  GPR_ASSERT(tsi_zero_copy_grpc_protector_protect(
      protector, &plaintext_buffer, &record_buffer) == TSI_OK);
  GPR_ASSERT(record_buffer.count == 1);
  uint8_t* record = GRPC_SLICE_START_PTR(record_buffer.slices[0]);
  size_t record_size = GRPC_SLICE_LENGTH(record_buffer.slices[0]);
  GPR_ASSERT(record_size == expected_message_size(test_plaintext_size));

  char* error_details = nullptr;
  bool correct_record = check_encrypt_record(
      ciphersuite, record, record_size,
      /** record_two **/ nullptr, /** record_two_size **/ 0,
      /** record_three **/ nullptr, /** record_three_size **/0,
      &error_details);
  GPR_ASSERT(correct_record);
  GPR_ASSERT(error_details == nullptr);

  grpc_slice_buffer_destroy_internal(&plaintext_buffer);
  grpc_slice_buffer_destroy_internal(&record_buffer);
  tsi_zero_copy_grpc_protector_destroy(protector);
  grpc_core::Delete<grpc_channel>(channel);
  grpc_core::ExecCtx::Get()->Flush();
}

static void s2a_zero_copy_grpc_protector_empty_protect_test(TLSCiphersuite ciphersuite) {
  grpc_core::ExecCtx exec_ctx;
  tsi_zero_copy_grpc_protector* protector = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  tsi_result create_result = setup_protector(ciphersuite, channel,
                                             &protector);
  if (ciphersuite == TLS_CHACHA20_POLY1305_SHA256_ciphersuite) {
    GPR_ASSERT(create_result == TSI_UNIMPLEMENTED);

    // Cleanup.
    tsi_zero_copy_grpc_protector_destroy(protector);
    grpc_core::Delete<grpc_channel>(channel);
    grpc_core::ExecCtx::Get()->Flush();
    return;
  }
  GPR_ASSERT(create_result == TSI_OK);

  grpc_slice test_slice = grpc_slice_from_static_buffer(/** source **/ nullptr,
                                                        /** length **/ 0);
  grpc_slice_buffer plaintext_buffer;
  grpc_slice_buffer_init(&plaintext_buffer);
  grpc_slice_buffer_add(&plaintext_buffer, test_slice);
  grpc_slice_buffer record_buffer;
  grpc_slice_buffer_init(&record_buffer);

  GPR_ASSERT(tsi_zero_copy_grpc_protector_protect(
      protector, &plaintext_buffer, &record_buffer) == TSI_OK);
  GPR_ASSERT(record_buffer.count == 1);
  uint8_t* record = GRPC_SLICE_START_PTR(record_buffer.slices[0]);
  size_t record_size = GRPC_SLICE_LENGTH(record_buffer.slices[0]);
  GPR_ASSERT(record_size == expected_message_size(/** plaintext_size **/ 0));
  char* error_details = nullptr;
  GPR_ASSERT(check_record_empty_plaintext(ciphersuite, record,
                                          record_size, &error_details));
  GPR_ASSERT(error_details == nullptr);

  grpc_slice_buffer_destroy_internal(&plaintext_buffer);
  grpc_slice_buffer_destroy_internal(&record_buffer);
  tsi_zero_copy_grpc_protector_destroy(protector);
  grpc_core::Delete<grpc_channel>(channel);
  grpc_core::ExecCtx::Get()->Flush();
}


int main(int /** argc **/, char** /** argv **/) {
  size_t number_ciphersuites = 3;
  TLSCiphersuite ciphersuite[3] = {TLS_AES_128_GCM_SHA256_ciphersuite,
                                   TLS_AES_256_GCM_SHA384_ciphersuite,
                                   TLS_CHACHA20_POLY1305_SHA256_ciphersuite};
  for (size_t i = 0; i < number_ciphersuites; i++) {
    s2a_zero_copy_grpc_protector_create_test(ciphersuite[i]);
    s2a_zero_copy_grpc_protector_small_protect_test(ciphersuite[i]);
    s2a_zero_copy_grpc_protector_empty_protect_test(ciphersuite[i]);
  }
  return 0;
}
