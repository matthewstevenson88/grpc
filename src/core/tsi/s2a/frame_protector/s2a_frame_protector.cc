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

#include <grpc/support/port_platform.h>

#include <grpc/support/alloc.h>
#include <grpc/support/log.h>
#include <openssl/ssl3.h>
#include "src/core/lib/iomgr/exec_ctx.h"
#include "src/core/lib/slice/slice_internal.h"
#include "src/core/tsi/alts/handshaker/alts_tsi_utils.h"
#include "src/core/tsi/s2a/frame_protector/s2a_frame_protector.h"
#include "src/core/tsi/s2a/record_protocol/s2a_crypter.h"

typedef struct s2a_zero_copy_grpc_protector {
  tsi_zero_copy_grpc_protector base;
  s2a_crypter* crypter;
  size_t max_protected_frame_size;
  size_t max_unprotected_data_size;
  grpc_slice_buffer protected_staging_sb;
  grpc_slice_buffer unprotected_staging_sb;
} s2a_zero_copy_grpc_protector;

/** --- tsi_zero_copy_grpc_protector methods implementation. --- **/

static tsi_result s2a_zero_copy_grpc_protector_protect(
    tsi_zero_copy_grpc_protector* self, grpc_slice_buffer* unprotected_slices,
    grpc_slice_buffer* protected_slices) {
  if (self == nullptr || unprotected_slices == nullptr ||
      protected_slices == nullptr) {
    gpr_log(
        GPR_ERROR,
        "Invalid nullptr arguments to s2a_zero_copy_grpc_protector_protect.");
    return TSI_INVALID_ARGUMENT;
  }
  s2a_zero_copy_grpc_protector* protector =
      reinterpret_cast<s2a_zero_copy_grpc_protector*>(self);
  char* error_details = nullptr;

  // TODO: make sure it's ok that protected_slices will consist of a bunch of
  // complete TLS records appended to one another.
  while (unprotected_slices->length > protector->max_unprotected_data_size) {
    grpc_slice_buffer_move_first(unprotected_slices,
                                 protector->max_unprotected_data_size,
                                 &(protector->unprotected_staging_sb));
    grpc_status_code status = s2a_protect_record(
        protector->crypter, SSL3_RT_APPLICATION_DATA,
        &(protector->unprotected_staging_sb), protected_slices, &error_details);
    if (status != GRPC_STATUS_OK) {
      gpr_log(GPR_ERROR, "Failed to protect record: %s", error_details);
      gpr_free(error_details);
      return alts_tsi_utils_convert_to_tsi_result(status);
    }
  }
  grpc_status_code status = s2a_protect_record(protector->crypter, SSL3_RT_APPLICATION_DATA,
                            unprotected_slices, protected_slices, &error_details);
  if (status != GRPC_STATUS_OK) {
    gpr_log(GPR_ERROR, "Failed to protect record: %s", error_details);
    gpr_free(error_details);
  }
  return alts_tsi_utils_convert_to_tsi_result(status);
}

static tsi_result s2a_zero_copy_grpc_protector_unprotect(
    tsi_zero_copy_grpc_protector* self, grpc_slice_buffer* protected_slices,
    grpc_slice_buffer* unprotected_slices) {
  // TODO(mattstev): implement.
  return TSI_UNIMPLEMENTED;
}

static void s2a_zero_copy_grpc_protector_destroy(
    tsi_zero_copy_grpc_protector* self) {
  if (self == nullptr) {
    return;
  }
  s2a_zero_copy_grpc_protector* impl =
      reinterpret_cast<s2a_zero_copy_grpc_protector*>(self);
  s2a_crypter_destroy(impl->crypter);
  grpc_slice_buffer_destroy_internal(&(impl->unprotected_staging_sb));
  gpr_free(impl);
}

static tsi_result s2a_zero_copy_grpc_protector_max_frame_size(
    tsi_zero_copy_grpc_protector* self, size_t& max_frame_size) {
  if (self == nullptr) {
    return TSI_INVALID_ARGUMENT;
  }
  s2a_zero_copy_grpc_protector* protector =
      reinterpret_cast<s2a_zero_copy_grpc_protector*>(self);
  max_frame_size = protector->max_protected_frame_size;
  return TSI_OK;
}

static const tsi_zero_copy_grpc_protector_vtable
    s2a_zero_copy_grpc_protector_vtable = {
        s2a_zero_copy_grpc_protector_protect,
        s2a_zero_copy_grpc_protector_unprotect,
        s2a_zero_copy_grpc_protector_destroy,
        s2a_zero_copy_grpc_protector_max_frame_size};

tsi_result s2a_zero_copy_grpc_protector_create(
    uint16_t tls_version, uint16_t tls_ciphersuite, uint8_t* in_key,
    uint8_t* out_key, size_t key_size, uint8_t* in_nonce, uint8_t* out_nonce,
    size_t nonce_size, grpc_channel* channel,
    tsi_zero_copy_grpc_protector** protector) {
  if (grpc_core::ExecCtx::Get() == nullptr || in_key == nullptr ||
      out_key == nullptr || in_nonce == nullptr || out_nonce == nullptr
      || channel == nullptr || protector == nullptr) {
    gpr_log(
        GPR_ERROR,
        "Invalid nullptr arguments to s2a_zero_copy_grpc_protector create.");
    return TSI_INVALID_ARGUMENT;
  }
  s2a_zero_copy_grpc_protector* impl =
      static_cast<s2a_zero_copy_grpc_protector*>(
          gpr_zalloc(sizeof(s2a_zero_copy_grpc_protector)));

  s2a_crypter* crypter = nullptr;
  char* error_details = nullptr;
  // TODO(mattstev): change the use of this API once s2a_crypter_create changes.
  grpc_status_code crypter_status = s2a_crypter_create(
      tls_version, tls_ciphersuite, in_key, out_key, key_size, in_nonce,
      out_nonce, nonce_size, channel, &crypter, &error_details);
  if (crypter_status != GRPC_STATUS_OK) {
    if (error_details != nullptr) {
      gpr_log(GPR_ERROR, "Failed to create s2a_crypter: %s", error_details);
      gpr_free(error_details);
    }
    s2a_crypter_destroy(crypter);
    gpr_free(impl);
    return TSI_INTERNAL_ERROR;
  }
  impl->crypter = crypter;
  impl->max_protected_frame_size =
      s2a_max_plaintext_size(crypter) + s2a_max_record_overhead(crypter);
  impl->max_unprotected_data_size = s2a_max_plaintext_size(crypter);
  grpc_slice_buffer_init(&(impl->protected_staging_sb));
  grpc_slice_buffer_init(&(impl->unprotected_staging_sb));
  impl->base.vtable = &s2a_zero_copy_grpc_protector_vtable;
  *protector = &(impl->base);
  return TSI_OK;
}
