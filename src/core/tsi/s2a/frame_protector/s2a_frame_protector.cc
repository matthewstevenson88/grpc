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
#include "src/core/tsi/s2a/record_protocol/s2a_crypter_util.h"
#include "src/core/tsi/s2a/s2a_constants.h"

typedef struct s2a_zero_copy_grpc_protector {
  tsi_zero_copy_grpc_protector base;
  s2a_crypter* crypter;
  size_t max_protected_frame_size;
  size_t max_unprotected_data_size;
  grpc_slice_buffer protected_sb;
  grpc_slice_buffer protected_staging_sb;
  grpc_slice_buffer unprotected_staging_sb;
  size_t current_frame_size;
} s2a_zero_copy_grpc_protector;

/** --- tsi_zero_copy_grpc_protector methods implementation. --- **/

static tsi_result s2a_zero_copy_grpc_protector_protect(
    tsi_zero_copy_grpc_protector* self, grpc_slice_buffer* unprotected_slices,
    grpc_slice_buffer* protected_slices) {
  if (self == nullptr || unprotected_slices == nullptr ||
      protected_slices == nullptr) {
    gpr_log(GPR_ERROR, kS2AProtectNullptr);
    return TSI_INVALID_ARGUMENT;
  }
  s2a_zero_copy_grpc_protector* protector =
      reinterpret_cast<s2a_zero_copy_grpc_protector*>(self);
  char* error_details = nullptr;

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
  grpc_status_code status =
      s2a_protect_record(protector->crypter, SSL3_RT_APPLICATION_DATA,
                         unprotected_slices, protected_slices, &error_details);
  if (status != GRPC_STATUS_OK) {
    gpr_log(GPR_ERROR, "Failed to protect record: %s", error_details);
    gpr_free(error_details);
  }
  return alts_tsi_utils_convert_to_tsi_result(status);
}

/** This method populates |total_frame_size| with the size of the TLS 1.3 frame
 *  built from |sb|. The caller must not pass in nullptr for |total_frame_size|.
 *  **/
static bool s2a_read_frame_size(const grpc_slice_buffer* sb,
                                size_t* total_frame_size) {
  GPR_ASSERT(total_frame_size != nullptr);
  if (sb == nullptr || sb->length < SSL3_RT_HEADER_LENGTH) {
    return false;
  }
  uint8_t header_buffer[SSL3_RT_HEADER_LENGTH];
  uint8_t* buffer = header_buffer;
  size_t bytes_remaining = SSL3_RT_HEADER_LENGTH;
  for (size_t i = 0; i < sb->count; i++) {
    size_t slice_length = GRPC_SLICE_LENGTH(sb->slices[i]);
    if (bytes_remaining <= slice_length) {
      memcpy(buffer, GRPC_SLICE_START_PTR(sb->slices[i]), bytes_remaining);
      bytes_remaining = 0;
      break;
    } else {
      memcpy(buffer, GRPC_SLICE_START_PTR(sb->slices[i]), slice_length);
      buffer += slice_length;
      bytes_remaining -= slice_length;
    }
  }
  GPR_ASSERT(bytes_remaining == 0);
  size_t payload_size = (header_buffer[3] << 8) + header_buffer[4];
  if (payload_size + SSL3_RT_HEADER_LENGTH > kS2AMaxFrameSize) {
    gpr_log(GPR_ERROR, kS2AFrameExceededMaxSize);
    return false;
  }
  *total_frame_size = payload_size + SSL3_RT_HEADER_LENGTH;
  return true;
}

static tsi_result s2a_zero_copy_grpc_protector_unprotect(
    tsi_zero_copy_grpc_protector* self, grpc_slice_buffer* protected_slices,
    grpc_slice_buffer* unprotected_slices) {
  if (self == nullptr || protected_slices == nullptr ||
      unprotected_slices == nullptr) {
    gpr_log(GPR_ERROR, kS2AUnprotectNullptr);
    return TSI_INVALID_ARGUMENT;
  }
  s2a_zero_copy_grpc_protector* protector =
      reinterpret_cast<s2a_zero_copy_grpc_protector*>(self);
  char* error_details = nullptr;
  grpc_slice_buffer_move_into(protected_slices, &(protector->protected_sb));

  while (protector->protected_sb.length >= SSL3_RT_HEADER_LENGTH) {
    if (protector->current_frame_size == 0) {
      if (!s2a_read_frame_size(&(protector->protected_sb),
                               &(protector->current_frame_size))) {
        grpc_slice_buffer_reset_and_unref_internal(&(protector->protected_sb));
        return TSI_DATA_CORRUPTED;
      }
    }
    if (protector->protected_sb.length < protector->current_frame_size) {
      break;
    }
    S2ADecryptStatus status;
    if (protector->protected_sb.length == protector->current_frame_size) {
      status =
          s2a_unprotect_record(protector->crypter, &(protector->protected_sb),
                               unprotected_slices, &error_details);
    } else {
      grpc_slice_buffer_move_first(&(protector->protected_sb),
                                   protector->current_frame_size,
                                   &(protector->protected_staging_sb));
      status = s2a_unprotect_record(protector->crypter,
                                    &(protector->protected_staging_sb),
                                    unprotected_slices, &error_details);
    }
    protector->current_frame_size = 0;
    if (status != S2ADecryptStatus::OK) {
      grpc_slice_buffer_reset_and_unref_internal(&(protector->protected_sb));
      gpr_log(GPR_ERROR, "Failed to unprotect record: %s", error_details);
      gpr_free(error_details);
      return s2a_util_convert_to_tsi_result(status);
    }
  }
  return TSI_OK;
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
    tsi_zero_copy_grpc_protector* self, size_t* max_frame_size) {
  if (self == nullptr || max_frame_size == nullptr) {
    return TSI_INVALID_ARGUMENT;
  }
  s2a_zero_copy_grpc_protector* protector =
      reinterpret_cast<s2a_zero_copy_grpc_protector*>(self);
  *max_frame_size = protector->max_protected_frame_size;
  return TSI_OK;
}

static const tsi_zero_copy_grpc_protector_vtable
    s2a_zero_copy_grpc_protector_vtable = {
        s2a_zero_copy_grpc_protector_protect,
        s2a_zero_copy_grpc_protector_unprotect,
        s2a_zero_copy_grpc_protector_destroy,
        s2a_zero_copy_grpc_protector_max_frame_size};

tsi_result s2a_zero_copy_grpc_protector_create(
    uint16_t tls_version, uint16_t tls_ciphersuite, uint8_t* in_traffic_secret,
    size_t in_traffic_secret_size, uint8_t* out_traffic_secret,
    size_t out_traffic_secret_size, grpc_channel* channel,
    size_t* max_protected_frame_size,
    tsi_zero_copy_grpc_protector** protector) {
  if (grpc_core::ExecCtx::Get() == nullptr || in_traffic_secret == nullptr ||
      out_traffic_secret == nullptr || channel == nullptr ||
      protector == nullptr) {
    gpr_log(GPR_ERROR, kS2AProtectorCreateNullptr);
    return TSI_INVALID_ARGUMENT;
  }
  s2a_zero_copy_grpc_protector* impl =
      static_cast<s2a_zero_copy_grpc_protector*>(
          gpr_zalloc(sizeof(s2a_zero_copy_grpc_protector)));

  s2a_crypter* crypter = nullptr;
  char* error_details = nullptr;
  grpc_status_code crypter_status = s2a_crypter_create(
      tls_version, tls_ciphersuite, in_traffic_secret, in_traffic_secret_size,
      out_traffic_secret, out_traffic_secret_size, channel, &crypter,
      &error_details);
  if (crypter_status != GRPC_STATUS_OK) {
    if (error_details != nullptr) {
      gpr_log(GPR_ERROR, "Failed to create s2a_crypter: %s", error_details);
      gpr_free(error_details);
    }
    s2a_crypter_destroy(crypter);
    gpr_free(impl);
    return alts_tsi_utils_convert_to_tsi_result(crypter_status);
  }
  impl->crypter = crypter;

  size_t max_record_overhead;
  grpc_status_code overhead_status =
      s2a_max_record_overhead(*crypter, &max_record_overhead, &error_details);
  if (overhead_status != GRPC_STATUS_OK) {
    if (error_details != nullptr) {
      gpr_log(GPR_ERROR, "Failed to compute max record overhead: %s",
              error_details);
      gpr_free(error_details);
    }
    s2a_crypter_destroy(crypter);
    gpr_free(impl);
    return alts_tsi_utils_convert_to_tsi_result(crypter_status);
  }
  impl->max_protected_frame_size =
      SSL3_RT_MAX_PLAIN_LENGTH + max_record_overhead;
  if (max_protected_frame_size != nullptr) {
    *max_protected_frame_size = impl->max_protected_frame_size;
  }
  impl->max_unprotected_data_size = SSL3_RT_MAX_PLAIN_LENGTH;
  grpc_slice_buffer_init(&(impl->protected_sb));
  grpc_slice_buffer_init(&(impl->protected_staging_sb));
  grpc_slice_buffer_init(&(impl->unprotected_staging_sb));
  impl->base.vtable = &s2a_zero_copy_grpc_protector_vtable;
  *protector = &(impl->base);
  return TSI_OK;
}
