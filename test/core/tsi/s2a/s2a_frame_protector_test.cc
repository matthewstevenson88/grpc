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
#include <vector>

#include "src/core/lib/gprpp/memory.h"
#include "src/core/lib/iomgr/exec_ctx.h"
#include "src/core/lib/slice/slice_internal.h"
#include "src/core/lib/surface/channel.h"
#include "src/core/tsi/s2a/frame_protector/s2a_frame_protector.h"
#include "src/core/tsi/s2a/record_protocol/s2a_crypter_util.h"
#include "src/core/tsi/s2a/s2a_constants.h"
#include "src/core/tsi/transport_security_grpc.h"
#include "test/core/tsi/s2a/s2a_test_data.h"
#include "test/core/tsi/s2a/s2a_test_util.h"

static void s2a_zero_copy_grpc_protector_create_test(uint16_t ciphersuite) {
  grpc_core::ExecCtx exec_ctx;
  uint8_t* traffic_secret;
  size_t traffic_secret_size;
  size_t tag_size;
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      traffic_secret = s2a_test_data::aes_128_gcm_traffic_secret.data();
      traffic_secret_size = s2a_test_data::aes_128_gcm_traffic_secret.size();
      tag_size = kEvpAeadAesGcmTagLength;
      break;
    case kTlsAes256GcmSha384:
      traffic_secret = s2a_test_data::aes_256_gcm_traffic_secret.data();
      traffic_secret_size = s2a_test_data::aes_256_gcm_traffic_secret.size();
      tag_size = kEvpAeadAesGcmTagLength;
      break;
    case kTlsChacha20Poly1305Sha256:
      traffic_secret = s2a_test_data::chacha_poly_traffic_secret.data();
      traffic_secret_size = s2a_test_data::chacha_poly_traffic_secret.size();
      tag_size = kPoly1305TagLength;
      break;
    default:
      gpr_log(GPR_ERROR, kS2AUnsupportedCiphersuite);
      abort();
  }
  tsi_zero_copy_grpc_protector* protector = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();

  /** Attempt to create an s2a_zero_copy_grpc_protector instance using
   *  nullptr arguments. **/
  tsi_result create_result = s2a_zero_copy_grpc_protector_create(
      /* tls_version=*/0, ciphersuite, traffic_secret, traffic_secret_size,
      traffic_secret, traffic_secret_size, channel, /* protector=*/nullptr);
  GPR_ASSERT(create_result == TSI_INVALID_ARGUMENT);

  create_result = s2a_zero_copy_grpc_protector_create(
      /* tls_version=*/0, ciphersuite, /* in_traffic_secret=*/nullptr,
      traffic_secret_size, traffic_secret, traffic_secret_size, channel,
      &protector);
  GPR_ASSERT(create_result == TSI_INVALID_ARGUMENT);

  create_result = s2a_zero_copy_grpc_protector_create(
      /* tls_version=*/0, ciphersuite, traffic_secret, traffic_secret_size,
      /* out_traffic_secret=*/nullptr, traffic_secret_size, channel,
      &protector);
  GPR_ASSERT(create_result == TSI_INVALID_ARGUMENT);

  create_result = s2a_zero_copy_grpc_protector_create(
      /* tls_version=*/0, ciphersuite, traffic_secret, traffic_secret_size,
      traffic_secret, traffic_secret_size,
      /* channel=*/nullptr, &protector);
  GPR_ASSERT(create_result == TSI_INVALID_ARGUMENT);
  GPR_ASSERT(protector == nullptr);

  /** Attempt to create an s2a_zero_copy_grpc_protector instance using
   *  an invalid TLS version. **/
  create_result = s2a_zero_copy_grpc_protector_create(
      /* tls_version=*/1, ciphersuite, traffic_secret, traffic_secret_size,
      traffic_secret, traffic_secret_size, channel, &protector);
  GPR_ASSERT(create_result == TSI_FAILED_PRECONDITION);
  GPR_ASSERT(protector == nullptr);

  /** Attempt to create an s2a_zero_copy_grpc_protector instance using
   *  incorrect key sizes. **/
  create_result = s2a_zero_copy_grpc_protector_create(
      /* tls_version=*/0, ciphersuite, traffic_secret, traffic_secret_size,
      traffic_secret, traffic_secret_size + 1, channel, &protector);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(create_result == TSI_UNIMPLEMENTED);
  } else {
    GPR_ASSERT(create_result == TSI_FAILED_PRECONDITION);
  }
  GPR_ASSERT(protector == nullptr);

  create_result = s2a_zero_copy_grpc_protector_create(
      /* tls_version=*/0, ciphersuite, traffic_secret, traffic_secret_size + 1,
      traffic_secret, traffic_secret_size, channel, &protector);
  GPR_ASSERT(create_result == TSI_FAILED_PRECONDITION);
  GPR_ASSERT(protector == nullptr);

  /** Successfully create an s2a_zero_copy_grpc_protector instance. **/
  create_result = s2a_zero_copy_grpc_protector_create(
      /* tls_version=*/0, ciphersuite, traffic_secret, traffic_secret_size,
      traffic_secret, traffic_secret_size, channel, &protector);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    /** The CHACHA-POLY ciphersuite is not yet supported. **/
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

  // Cleanup.
  tsi_zero_copy_grpc_protector_destroy(protector);
  grpc_core::Delete<grpc_channel>(channel);
  grpc_core::ExecCtx::Get()->Flush();
}

static tsi_result setup_protector(uint16_t ciphersuite, grpc_channel* channel,
                                  tsi_zero_copy_grpc_protector** protector) {
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
      return TSI_UNIMPLEMENTED;
  }
  return s2a_zero_copy_grpc_protector_create(
      /* TLS 1.3=*/0, ciphersuite, traffic_secret, traffic_secret_size,
      traffic_secret, traffic_secret_size, channel, protector);
}

static void s2a_zero_copy_grpc_protector_small_protect_test(
    uint16_t ciphersuite) {
  grpc_core::ExecCtx exec_ctx;
  tsi_zero_copy_grpc_protector* protector = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  tsi_result create_result = setup_protector(ciphersuite, channel, &protector);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(create_result == TSI_UNIMPLEMENTED);

    // Cleanup.
    tsi_zero_copy_grpc_protector_destroy(protector);
    grpc_core::Delete<grpc_channel>(channel);
    grpc_core::ExecCtx::Get()->Flush();
    return;
  }
  GPR_ASSERT(create_result == TSI_OK);

  std::vector<uint8_t> test_plaintext = {'1', '2', '3', '4', '5', '6'};
  grpc_slice test_slice = grpc_slice_from_static_buffer(test_plaintext.data(),
                                                        test_plaintext.size());
  grpc_slice_buffer plaintext_buffer;
  grpc_slice_buffer_init(&plaintext_buffer);
  grpc_slice_buffer_add(&plaintext_buffer, test_slice);
  grpc_slice_buffer record_buffer;
  grpc_slice_buffer_init(&record_buffer);

  GPR_ASSERT(tsi_zero_copy_grpc_protector_protect(protector, &plaintext_buffer,
                                                  &record_buffer) == TSI_OK);
  GPR_ASSERT(record_buffer.count == 1);
  uint8_t* record = GRPC_SLICE_START_PTR(record_buffer.slices[0]);
  size_t record_size = GRPC_SLICE_LENGTH(record_buffer.slices[0]);
  GPR_ASSERT(record_size == expected_message_size(test_plaintext.size()));
  uint8_t* correct_record;
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      correct_record = s2a_test_data::aes_128_gcm_decrypt_record_1.data();
      break;
    case kTlsAes256GcmSha384:
      correct_record = s2a_test_data::aes_256_gcm_decrypt_record_1.data();
      break;
    case kTlsChacha20Poly1305Sha256:
      correct_record = s2a_test_data::chacha_poly_decrypt_record_1.data();
      break;
  }
  for (size_t i = 0; i < record_size; i++) {
    GPR_ASSERT(record[i] == correct_record[i]);
  }

  // Cleanup.
  grpc_slice_buffer_destroy_internal(&plaintext_buffer);
  grpc_slice_buffer_destroy_internal(&record_buffer);
  tsi_zero_copy_grpc_protector_destroy(protector);
  grpc_core::Delete<grpc_channel>(channel);
  grpc_core::ExecCtx::Get()->Flush();
}

static void s2a_zero_copy_grpc_protector_empty_protect_test(
    uint16_t ciphersuite) {
  grpc_core::ExecCtx exec_ctx;
  tsi_zero_copy_grpc_protector* protector = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  tsi_result create_result = setup_protector(ciphersuite, channel, &protector);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(create_result == TSI_UNIMPLEMENTED);

    // Cleanup.
    tsi_zero_copy_grpc_protector_destroy(protector);
    grpc_core::Delete<grpc_channel>(channel);
    grpc_core::ExecCtx::Get()->Flush();
    return;
  }
  GPR_ASSERT(create_result == TSI_OK);

  grpc_slice test_slice = grpc_slice_from_static_buffer(/* source=*/nullptr,
                                                        /* length=*/0);
  grpc_slice_buffer plaintext_buffer;
  grpc_slice_buffer_init(&plaintext_buffer);
  grpc_slice_buffer_add(&plaintext_buffer, test_slice);
  grpc_slice_buffer record_buffer;
  grpc_slice_buffer_init(&record_buffer);

  GPR_ASSERT(tsi_zero_copy_grpc_protector_protect(protector, &plaintext_buffer,
                                                  &record_buffer) == TSI_OK);
  GPR_ASSERT(record_buffer.count == 1);
  uint8_t* record = GRPC_SLICE_START_PTR(record_buffer.slices[0]);
  size_t record_size = GRPC_SLICE_LENGTH(record_buffer.slices[0]);
  GPR_ASSERT(record_size == expected_message_size(/* plaintext_size=*/0));
  uint8_t* correct_record;
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      correct_record = s2a_test_data::aes_128_gcm_empty_record_bytes.data();
      break;
    case kTlsAes256GcmSha384:
      correct_record = s2a_test_data::aes_256_gcm_empty_record_bytes.data();
      break;
    case kTlsChacha20Poly1305Sha256:
      correct_record = s2a_test_data::chacha_poly_empty_record_bytes.data();
      break;
  }
  for (size_t i = 0; i < record_size; i++) {
    GPR_ASSERT(record[i] == correct_record[i]);
  }

  // Cleanup.
  grpc_slice_buffer_destroy_internal(&plaintext_buffer);
  grpc_slice_buffer_destroy_internal(&record_buffer);
  tsi_zero_copy_grpc_protector_destroy(protector);
  grpc_core::Delete<grpc_channel>(channel);
  grpc_core::ExecCtx::Get()->Flush();
}

static void s2a_zero_copy_grpc_protector_unprotect_test(uint16_t ciphersuite) {
  grpc_core::ExecCtx exec_ctx;
  tsi_zero_copy_grpc_protector* protector = nullptr;
  grpc_channel* channel = grpc_core::New<grpc_channel>();
  tsi_result create_result = setup_protector(ciphersuite, channel, &protector);
  if (ciphersuite == kTlsChacha20Poly1305Sha256) {
    GPR_ASSERT(create_result == TSI_UNIMPLEMENTED);

    // Cleanup.
    tsi_zero_copy_grpc_protector_destroy(protector);
    grpc_core::Delete<grpc_channel>(channel);
    grpc_core::ExecCtx::Get()->Flush();
    return;
  }
  GPR_ASSERT(create_result == TSI_OK);

  uint8_t* record;
  size_t record_size;
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      record = s2a_test_data::aes_128_gcm_decrypt_record_1.data();
      record_size = s2a_test_data::aes_128_gcm_decrypt_record_1.size();
      break;
    case kTlsAes256GcmSha384:
      record = s2a_test_data::aes_256_gcm_decrypt_record_1.data();
      record_size = s2a_test_data::aes_256_gcm_decrypt_record_1.size();
      break;
    case kTlsChacha20Poly1305Sha256:
      record = s2a_test_data::chacha_poly_decrypt_record_1.data();
      record_size = s2a_test_data::chacha_poly_decrypt_record_1.size();
      break;
    default:
      gpr_log(GPR_ERROR, kS2AUnsupportedCiphersuite);
      abort();
  }

  grpc_slice test_slice = grpc_slice_from_static_buffer(record, record_size);
  grpc_slice_buffer record_buffer;
  grpc_slice_buffer_init(&record_buffer);
  grpc_slice_buffer_add(&record_buffer, test_slice);
  grpc_slice_buffer plaintext_buffer;
  grpc_slice_buffer_init(&plaintext_buffer);

  GPR_ASSERT(tsi_zero_copy_grpc_protector_unprotect(
                 protector, &record_buffer, &plaintext_buffer) == TSI_OK);
  GPR_ASSERT(plaintext_buffer.count == 1);
  uint8_t* plaintext = GRPC_SLICE_START_PTR(plaintext_buffer.slices[0]);
  size_t plaintext_size = GRPC_SLICE_LENGTH(plaintext_buffer.slices[0]);
  GPR_ASSERT(plaintext_size == s2a_test_data::decrypt_plaintext_1.size());
  for (size_t i = 0; i < plaintext_size; i++) {
    GPR_ASSERT(plaintext[i] == s2a_test_data::decrypt_plaintext_1[i]);
  }

  // Cleanup.
  grpc_slice_buffer_destroy_internal(&plaintext_buffer);
  grpc_slice_buffer_destroy_internal(&record_buffer);
  tsi_zero_copy_grpc_protector_destroy(protector);
  grpc_core::Delete<grpc_channel>(channel);
  grpc_core::ExecCtx::Get()->Flush();
}

int main(int /** argc **/, char** /** argv **/) {
  const size_t number_ciphersuites = 3;
  uint16_t ciphersuite[number_ciphersuites] = {
      kTlsAes128GcmSha256, kTlsAes256GcmSha384, kTlsChacha20Poly1305Sha256};
  for (size_t i = 0; i < number_ciphersuites; i++) {
    s2a_zero_copy_grpc_protector_create_test(ciphersuite[i]);
    s2a_zero_copy_grpc_protector_small_protect_test(ciphersuite[i]);
    s2a_zero_copy_grpc_protector_empty_protect_test(ciphersuite[i]);
    s2a_zero_copy_grpc_protector_unprotect_test(ciphersuite[i]);
  }
  return 0;
}
