/*
 *
 * Copyright 2021 gRPC authors.
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

#include "src/core/tsi/s2a/frame_protector/s2a_zero_copy_grpc_protector.h"

#include <grpc/support/alloc.h>

#include "absl/status/status.h"
#include "src/core/lib/slice/slice_internal.h"

namespace s2a {
namespace {

using ::absl::Status;
using ::absl::StatusCode;
using ::absl::StatusOr;
using aead_crypter::Iovec;
using S2AFrameProtectorOptions =
    ::s2a::frame_protector::S2AFrameProtector::S2AFrameProtectorOptions;

constexpr uint8_t kTls12ApplicationData = 0x17;
constexpr uint8_t kTls12WireVersion = 0x03;
constexpr size_t kTls13RecordHeaderLength = 5;

tsi_result StatusToTsiResult(StatusCode code) {
  switch (code) {
    case StatusCode::kOk:
      return TSI_OK;
    case StatusCode::kUnknown:
      return TSI_UNKNOWN_ERROR;
    case StatusCode::kInvalidArgument:
      return TSI_INVALID_ARGUMENT;
    case StatusCode::kPermissionDenied:
      return TSI_PERMISSION_DENIED;
    case StatusCode::kFailedPrecondition:
      return TSI_FAILED_PRECONDITION;
    case StatusCode::kUnimplemented:
      return TSI_UNIMPLEMENTED;
    default:
      return TSI_INTERNAL_ERROR;
  }
}

// |ComputeTlsRecordSize| returns the size of the first TLS record stored in
// |buffer|, or an error status if no such record exists.
StatusOr<size_t> ComputeTlsRecordSize(const grpc_slice_buffer* buffer) {
  ABSL_ASSERT(buffer != nullptr);
  if (buffer->length < kTls13RecordHeaderLength) {
    return Status(StatusCode::kFailedPrecondition,
                  "|buffer| does not contain a complete TLS record.");
  }
  size_t header_index = 0;
  size_t slice_index = 0;
  size_t on_slice_index = 0;
  int first_payload_component;
  int second_payload_component;
  while (header_index < kTls13RecordHeaderLength) {
    uint8_t* slice = GRPC_SLICE_START_PTR(buffer->slices[slice_index]);
    size_t slice_length = GRPC_SLICE_LENGTH(buffer->slices[slice_index]);
    switch (header_index) {
      case 0:
        if (slice[on_slice_index] != kTls12ApplicationData) {
          return Status(StatusCode::kInvalidArgument,
                        "|buffer| does not contain a valid TLS record.");
        }
        break;
      case 1:
      case 2:
        if (slice[on_slice_index] != kTls12WireVersion) {
          return Status(StatusCode::kInvalidArgument,
                        "|buffer| does not contain a valid TLS record.");
        }
        break;
      case 3:
        first_payload_component = static_cast<int>(slice[on_slice_index] & 0xff)
                                  << 8;
        break;
      case 4:
        second_payload_component =
            static_cast<int>(slice[on_slice_index] & 0xff);
        break;
      default:
        return Status(StatusCode::kInvalidArgument,
                      "|buffer| does not contain a valid TLS record.");
    }
    header_index += 1;
    on_slice_index += 1;
    if (on_slice_index >= slice_length) {
      slice_index += 1;
      on_slice_index = 0;
    }
  }
  return kTls13RecordHeaderLength + first_payload_component +
         second_payload_component;
}

typedef struct s2a_zero_copy_grpc_protector {
  tsi_zero_copy_grpc_protector base;
  std::unique_ptr<frame_protector::S2AFrameProtector> frame_protector;
  // |protected_buffer| contains the bytes that still need to be unprotected
  grpc_slice_buffer protected_buffer;
  grpc_slice_buffer staging_buffer;
  size_t current_record_size = 0;
} s2a_zero_copy_grpc_protector;

static tsi_result s2a_zero_copy_grpc_protector_protect(
    tsi_zero_copy_grpc_protector* self, grpc_slice_buffer* unprotected_slices,
    grpc_slice_buffer* protected_slices) {
  if (self == nullptr || unprotected_slices == nullptr ||
      protected_slices == nullptr) {
    gpr_log(GPR_ERROR,
            "Invalid nullptptr argument to "
            "|s2a_zero_copy_grpc_protector_protect|.");
    return TSI_INVALID_ARGUMENT;
  }
  s2a_zero_copy_grpc_protector* protector =
      reinterpret_cast<s2a_zero_copy_grpc_protector*>(self);

  // Convert the |unprotected_slices| into a vector of |Iovec|'s.
  std::vector<Iovec> unprotected_vec(unprotected_slices->count);
  for (size_t i = 0; i < unprotected_slices->count; i++) {
    unprotected_vec[i].iov_base =
        GRPC_SLICE_START_PTR(unprotected_slices->slices[i]);
    unprotected_vec[i].iov_len =
        GRPC_SLICE_LENGTH(unprotected_slices->slices[i]);
  }

  // Allocate a slice to hold the TLS records formed from |unprotected_slices|.
  size_t protected_record_length =
      protector->frame_protector->NumberBytesToProtect(
          unprotected_slices->length);
  grpc_slice protected_record_slice =
      GRPC_SLICE_MALLOC(protected_record_length);
  Iovec protected_record = {GRPC_SLICE_START_PTR(protected_record_slice),
                            GRPC_SLICE_LENGTH(protected_record_slice)};

  // Write the TLS record in |unprotected_vec| to |protected_record|.
  Status status =
      protector->frame_protector->Protect(unprotected_vec, protected_record);
  if (!status.ok()) {
    grpc_slice_unref(protected_record_slice);
    return StatusToTsiResult(status.code());
  }

  // Add |protected_record_slice| to the buffer of protected slices, and clean
  // up the unprotected slices.
  grpc_slice_buffer_add(protected_slices, protected_record_slice);
  grpc_slice_buffer_reset_and_unref_internal(unprotected_slices);
  return TSI_OK;
}

static tsi_result s2a_zero_copy_grpc_protector_unprotect(
    tsi_zero_copy_grpc_protector* self, grpc_slice_buffer* protected_slices,
    grpc_slice_buffer* unprotected_slices) {
  if (self == nullptr || protected_slices == nullptr ||
      unprotected_slices == nullptr) {
    gpr_log(GPR_ERROR,
            "Invalid nullptr argumment to "
            "|s2a_zero_copy_grpc_protector_unprotect|.");
    return TSI_INVALID_ARGUMENT;
  }
  s2a_zero_copy_grpc_protector* protector =
      reinterpret_cast<s2a_zero_copy_grpc_protector*>(self);

  grpc_slice_buffer_move_into(protected_slices, &protector->protected_buffer);
  while (protector->protected_buffer.length >= kTls13RecordHeaderLength) {
    if (protector->current_record_size == 0) {
      StatusOr<size_t> record_size_or =
          ComputeTlsRecordSize(&protector->protected_buffer);
      if (!record_size_or.ok()) {
        grpc_slice_buffer_reset_and_unref_internal(
            &protector->protected_buffer);
        gpr_log(GPR_INFO, "Trying to read corrupted data.");
        return TSI_DATA_CORRUPTED;
      }
      protector->current_record_size = *record_size_or;
    }
    if (protector->protected_buffer.length < protector->current_record_size) {
      // |protector->protected_buffer| does not contain a complete TLS record,
      // so break out of the loop and the next call to
      // |s2a_zero_copy_grpc_protector_unprotect| should add bytes that
      // hopefully complete the TLS record.
      break;
    }
    grpc_slice_buffer_move_first(&protector->protected_buffer,
                                 protector->current_record_size,
                                 &protector->staging_buffer);

    size_t unprotected_slice_length =
        protector->frame_protector->NumberBytesToUnprotect(
            protector->staging_buffer.length);
    grpc_slice unprotected_slice = GRPC_SLICE_MALLOC(unprotected_slice_length);
    Iovec unprotected_vec = {GRPC_SLICE_START_PTR(unprotected_slice),
                             GRPC_SLICE_LENGTH(unprotected_slice)};

    std::vector<Iovec> protected_vec(protector->staging_buffer.count);
    for (size_t i = 0; i < protector->staging_buffer.count; i++) {
      protected_vec[i].iov_base =
          GRPC_SLICE_START_PTR(protector->staging_buffer.slices[i]);
      protected_vec[i].iov_len =
          GRPC_SLICE_LENGTH(protector->staging_buffer.slices[i]);
    }

    Status status =
        protector->frame_protector->Unprotect(protected_vec, unprotected_vec);
    if (!status.ok()) {
      gpr_log(GPR_INFO, "%s", std::string(status.message()).c_str());
      grpc_slice_buffer_reset_and_unref_internal(&protector->protected_buffer);
      return StatusToTsiResult(status.code());
    }
    protector->current_record_size = 0;
    GRPC_SLICE_SET_LENGTH(unprotected_slice, unprotected_vec.iov_len);
    grpc_slice_buffer_reset_and_unref_internal(&protector->staging_buffer);
    grpc_slice_buffer_add(unprotected_slices, unprotected_slice);
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
  grpc_slice_buffer_destroy(&(impl->protected_buffer));
  grpc_slice_buffer_destroy(&(impl->staging_buffer));
  delete impl;
  gpr_log(GPR_INFO, "Destroyed |s2a_zero_copy_grpc_protector|.");
}

static tsi_result s2a_zero_copy_grpc_protector_max_frame_size(
    tsi_zero_copy_grpc_protector* self, size_t* max_frame_size) {
  if (self == nullptr || max_frame_size == nullptr) {
    return TSI_INVALID_ARGUMENT;
  }
  s2a_zero_copy_grpc_protector* protector =
      reinterpret_cast<s2a_zero_copy_grpc_protector*>(self);
  *max_frame_size = protector->frame_protector->MaxRecordSize();
  return TSI_OK;
}

static const tsi_zero_copy_grpc_protector_vtable
    s2a_zero_copy_grpc_protector_vtable = {
        s2a_zero_copy_grpc_protector_protect,
        s2a_zero_copy_grpc_protector_unprotect,
        s2a_zero_copy_grpc_protector_destroy,
        s2a_zero_copy_grpc_protector_max_frame_size};

}  // namespace

absl::StatusOr<tsi_zero_copy_grpc_protector*>
s2a_zero_copy_grpc_protector_create(
    std::unique_ptr<frame_protector::S2AFrameProtector> frame_protector) {
  if (frame_protector == nullptr) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Invalid nullptr argument to |s2a_zero_copy_grpc_protector_create|.");
  }
  s2a_zero_copy_grpc_protector* impl = new s2a_zero_copy_grpc_protector();
  impl->frame_protector = std::move(frame_protector);
  grpc_slice_buffer_init(&(impl->protected_buffer));
  grpc_slice_buffer_init(&(impl->staging_buffer));
  impl->base.vtable = &s2a_zero_copy_grpc_protector_vtable;
  gpr_log(GPR_INFO, "Created |s2a_zero_copy_grpc_protector|.");
  return &impl->base;
}

}  // namespace s2a
