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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/variant.h"
#include "s2a/include/s2a_options.h"
#include "s2a/src/test_util/s2a_test_data.h"
#include "src/core/lib/slice/slice_internal.h"
#include "src/core/tsi/s2a/s2a_security.h"

namespace s2a {
namespace {

using ::absl::Status;
using ::absl::StatusCode;
using ::absl::StatusOr;
using ::s2a::aead_crypter::Iovec;
using ::s2a::frame_protector::S2AFrameProtector;
using Ciphersuite = ::s2a::s2a_options::S2AOptions::Ciphersuite;
using TlsVersion = ::s2a::s2a_options::S2AOptions::TlsVersion;
using S2AFrameProtectorOptions =
    ::s2a::frame_protector::S2AFrameProtector::S2AFrameProtectorOptions;

constexpr char kTestLocalIdentity[] = "test_local_identity";
constexpr uint64_t kTestConnectionId = 1234;
constexpr size_t kTls13MaxPlaintextBytesPerRecord = 16384;

Iovec Allocator(size_t length) { return {new uint8_t[length], length}; }

void Destroy(Iovec iovec) { delete[] static_cast<uint8_t*>(iovec.iov_base); }

void Logger(const std::string& message) {}

std::unique_ptr<S2AFrameProtector> CreateTestFrameProtector() {
  std::vector<uint8_t> traffic_secret(kSha256DigestLength, 0x6b);
  S2AFrameProtectorOptions options = {
      TlsVersion::TLS1_3,
      Ciphersuite::AES_128_GCM_SHA256,
      traffic_secret,
      traffic_secret,
      /*in_sequence=*/0,
      /*out_sequence=*/0,
      kS2AHandshakerServiceUrlForTesting,
      s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
      kTestConnectionId,
      /*channel_factory=*/nullptr,
      /*channel_options=*/nullptr,
      Allocator,
      Destroy,
      Logger};
  absl::StatusOr<std::unique_ptr<S2AFrameProtector>> frame_protector_or =
      S2AFrameProtector::Create(options);
  if (!frame_protector_or.ok()) {
    return nullptr;
  }
  return std::move(*frame_protector_or);
}

TEST(S2AZeroCopyGrpcProtectorTest, CreateSuccess) {
  StatusOr<tsi_zero_copy_grpc_protector*> protector_or =
      s2a_zero_copy_grpc_protector_create(CreateTestFrameProtector());
  EXPECT_TRUE(protector_or.ok());
  EXPECT_NE(*protector_or, nullptr);

  tsi_zero_copy_grpc_protector_destroy(*protector_or);
}

TEST(S2AZeroCopyGrpcProtectorTest, CreateFailure) {
  StatusOr<tsi_zero_copy_grpc_protector*> protector_or =
      s2a_zero_copy_grpc_protector_create(/*frame_protector=*/nullptr);
  EXPECT_EQ(protector_or.status(),
            Status(StatusCode::kInvalidArgument,
                   "Invalid nullptr argument to "
                   "|s2a_zero_copy_grpc_protector_create|."));
}

TEST(S2AZeroCopyGrpcProtectorTest, MaxFrameSizeSuccess) {
  std::unique_ptr<S2AFrameProtector> frame_protector =
      CreateTestFrameProtector();
  size_t max_record_size = frame_protector->MaxRecordSize();

  tsi_zero_copy_grpc_protector* protector =
      *s2a_zero_copy_grpc_protector_create(std::move(frame_protector));
  size_t max_frame_size = 0;

  EXPECT_EQ(
      tsi_zero_copy_grpc_protector_max_frame_size(protector, &max_frame_size),
      TSI_OK);
  EXPECT_EQ(max_frame_size, max_record_size);

  tsi_zero_copy_grpc_protector_destroy(protector);
}

TEST(S2AZeroCopyGrpcProtectorTest, MaxFrameSizeFailure) {
  tsi_zero_copy_grpc_protector* protector =
      *s2a_zero_copy_grpc_protector_create(CreateTestFrameProtector());

  EXPECT_EQ(tsi_zero_copy_grpc_protector_max_frame_size(
                protector, /*max_frame_size=*/nullptr),
            TSI_INVALID_ARGUMENT);

  tsi_zero_copy_grpc_protector_destroy(protector);
}

TEST(S2AZeroCopyGrpcProtectorTest, ProtectSuccess) {
  tsi_zero_copy_grpc_protector* protector =
      *s2a_zero_copy_grpc_protector_create(CreateTestFrameProtector());

  std::vector<uint8_t> test_plaintext = {'1', '2', '3', '4', '5', '6'};
  grpc_slice test_slice = grpc_slice_from_static_buffer(test_plaintext.data(),
                                                        test_plaintext.size());
  grpc_slice_buffer plaintext_buffer;
  grpc_slice_buffer_init(&plaintext_buffer);
  grpc_slice_buffer_add(&plaintext_buffer, test_slice);
  grpc_slice_buffer record_buffer;
  grpc_slice_buffer_init(&record_buffer);

  EXPECT_EQ(tsi_zero_copy_grpc_protector_protect(protector, &plaintext_buffer,
                                                 &record_buffer),
            TSI_OK);
  EXPECT_EQ(record_buffer.count, 1);

  uint8_t* record = GRPC_SLICE_START_PTR(record_buffer.slices[0]);
  size_t record_size = GRPC_SLICE_LENGTH(record_buffer.slices[0]);
  EXPECT_EQ(record_size, s2a_test_data::aes_128_gcm_decrypt_record_1_size);
  const uint8_t* correct_record = s2a_test_data::aes_128_gcm_decrypt_record_1;
  for (size_t i = 0; i < record_size; i++) {
    EXPECT_EQ(record[i], correct_record[i]);
  }

  // Cleanup.
  grpc_slice_buffer_destroy_internal(&plaintext_buffer);
  grpc_slice_buffer_destroy_internal(&record_buffer);
  tsi_zero_copy_grpc_protector_destroy(protector);
}

TEST(S2AZeroCopyGrpcProtectorTest, ProtectFailureBecauseNullptrArgument) {
  tsi_zero_copy_grpc_protector* protector =
      *s2a_zero_copy_grpc_protector_create(CreateTestFrameProtector());

  EXPECT_EQ(tsi_zero_copy_grpc_protector_protect(protector,
                                                 /*unprotected_slices=*/nullptr,
                                                 /*protected_slices=*/nullptr),
            TSI_INVALID_ARGUMENT);

  tsi_zero_copy_grpc_protector_destroy(protector);
}

// TODO(b/161283415) Add test cases where |protected_bytes| has a full record
// and a partial record, and we need to call unprotect a second time.

TEST(S2AZeroCopyGrpcProtectorTest, UnprotectSuccess) {
  tsi_zero_copy_grpc_protector* protector =
      *s2a_zero_copy_grpc_protector_create(CreateTestFrameProtector());

  const uint8_t* record = s2a_test_data::aes_128_gcm_decrypt_record_1;
  size_t record_size = s2a_test_data::aes_128_gcm_decrypt_record_1_size;
  grpc_slice test_slice = grpc_slice_from_static_buffer(record, record_size);
  grpc_slice_buffer record_buffer;
  grpc_slice_buffer_init(&record_buffer);
  grpc_slice_buffer_add(&record_buffer, test_slice);
  grpc_slice_buffer plaintext_buffer;
  grpc_slice_buffer_init(&plaintext_buffer);

  EXPECT_EQ(tsi_zero_copy_grpc_protector_unprotect(protector, &record_buffer,
                                                   &plaintext_buffer),
            TSI_OK);
  EXPECT_EQ(plaintext_buffer.count, 1);

  uint8_t* plaintext = GRPC_SLICE_START_PTR(plaintext_buffer.slices[0]);
  size_t plaintext_size = GRPC_SLICE_LENGTH(plaintext_buffer.slices[0]);
  GPR_ASSERT(plaintext_size == s2a_test_data::decrypt_plaintext_1_size);
  for (size_t i = 0; i < plaintext_size; i++) {
    EXPECT_EQ(plaintext[i], s2a_test_data::decrypt_plaintext_1[i]);
  }

  grpc_slice_buffer_destroy_internal(&plaintext_buffer);
  grpc_slice_buffer_destroy_internal(&record_buffer);
  tsi_zero_copy_grpc_protector_destroy(protector);
}

TEST(S2AZeroCopyGrpcProtectorTest, UnprotectFailureBecauseNullptrArgument) {
  tsi_zero_copy_grpc_protector* protector =
      *s2a_zero_copy_grpc_protector_create(CreateTestFrameProtector());

  EXPECT_EQ(tsi_zero_copy_grpc_protector_unprotect(
                protector, /*protected_slices=*/nullptr,
                /*unprotected_slices=*/nullptr),
            TSI_INVALID_ARGUMENT);

  tsi_zero_copy_grpc_protector_destroy(protector);
}

TEST(S2AZeroCopyGrpcProtectorTest, UnprotectFailureBecauseBadRecord) {
  tsi_zero_copy_grpc_protector* protector =
      *s2a_zero_copy_grpc_protector_create(CreateTestFrameProtector());

  const uint8_t* record = s2a_test_data::aes_128_gcm_decrypt_record_1;
  size_t record_size = s2a_test_data::aes_128_gcm_decrypt_record_1_size;
  std::vector<uint8_t> bad_record(record_size);
  memcpy(bad_record.data(), record, record_size);
  bad_record[bad_record.size() - 1] += 1;

  grpc_slice test_slice =
      grpc_slice_from_static_buffer(bad_record.data(), bad_record.size());
  grpc_slice_buffer record_buffer;
  grpc_slice_buffer_init(&record_buffer);
  grpc_slice_buffer_add(&record_buffer, test_slice);
  grpc_slice_buffer plaintext_buffer;
  grpc_slice_buffer_init(&plaintext_buffer);

  EXPECT_EQ(tsi_zero_copy_grpc_protector_unprotect(protector, &record_buffer,
                                                   &plaintext_buffer),
            TSI_INTERNAL_ERROR);
  EXPECT_EQ(plaintext_buffer.count, 0);

  grpc_slice_buffer_destroy_internal(&plaintext_buffer);
  grpc_slice_buffer_destroy_internal(&record_buffer);
  tsi_zero_copy_grpc_protector_destroy(protector);
}

TEST(S2AZeroCopyGrpcProtectorTest, Roundtrip) {
  // The same frame protector should be used for all test cases so that we vary
  // the sequence numbers used in the encryption and decryption.
  tsi_zero_copy_grpc_protector* protector =
      *s2a_zero_copy_grpc_protector_create(CreateTestFrameProtector());

  const struct {
    size_t message_size;
    size_t number_of_tls_records;
  } tests[] = {
      {1, 1},
      {kTls13MaxPlaintextBytesPerRecord - 1u, 1},
      {kTls13MaxPlaintextBytesPerRecord, 1},
      {kTls13MaxPlaintextBytesPerRecord + 1u, 2},
      {2 * kTls13MaxPlaintextBytesPerRecord - 1u, 2},
      {2 * kTls13MaxPlaintextBytesPerRecord, 2},
      {2 * kTls13MaxPlaintextBytesPerRecord + 1u, 3},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    // Prepare a message of all zeroes.
    std::vector<uint8_t> message(tests[i].message_size);
    grpc_slice test_slice =
        grpc_slice_from_static_buffer(message.data(), message.size());

    // Protect the bytes in |test_slice| and write the resulting TLS records to
    // |record_buffer|.
    grpc_slice_buffer plaintext_buffer;
    grpc_slice_buffer_init(&plaintext_buffer);
    grpc_slice_buffer_add(&plaintext_buffer, test_slice);
    grpc_slice_buffer record_buffer;
    grpc_slice_buffer_init(&record_buffer);
    EXPECT_EQ(tsi_zero_copy_grpc_protector_protect(protector, &plaintext_buffer,
                                                   &record_buffer),
              TSI_OK);
    EXPECT_EQ(record_buffer.count, 1);

    // Unprotect the bytes in |record_buffer| and write the resulting plaintext
    // to |unprotected_bytes|.
    grpc_slice_buffer unprotected_buffer;
    grpc_slice_buffer_init(&unprotected_buffer);
    EXPECT_EQ(tsi_zero_copy_grpc_protector_unprotect(protector, &record_buffer,
                                                     &unprotected_buffer),
              TSI_OK);
    EXPECT_EQ(unprotected_buffer.count, tests[i].number_of_tls_records);

    // Ensure that |unprotected_buffer| has |tests[i].message_size| bytes in
    // total, and each byte is zero (i.e. the same as |message|).
    EXPECT_EQ(unprotected_buffer.length, tests[i].message_size);
    for (size_t i = 0; i < unprotected_buffer.count; i++) {
      for (size_t j = 0; j < GRPC_SLICE_LENGTH(unprotected_buffer.slices[i]);
           j++) {
        EXPECT_EQ(GRPC_SLICE_START_PTR(unprotected_buffer.slices[i])[j], 0);
      }
    }

    // Cleanup.
    grpc_slice_buffer_destroy_internal(&plaintext_buffer);
    grpc_slice_buffer_destroy_internal(&record_buffer);
    grpc_slice_buffer_destroy_internal(&unprotected_buffer);
  }

  tsi_zero_copy_grpc_protector_destroy(protector);
}

}  // namespace
}  // namespace s2a

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  grpc_init();
  int ret = RUN_ALL_TESTS();
  grpc_shutdown();
  return ret;
}
