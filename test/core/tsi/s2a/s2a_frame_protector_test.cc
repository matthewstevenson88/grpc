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

#include <grpc/slice_buffer.h>
#include <grpc/support/alloc.h>
#include <grpc/support/log.h>

#include "src/core/lib/iomgr/exec_ctx.h"
#include "src/core/lib/slice/slice_internal.h"
#include "src/core/tsi/s2a/frame_protector/s2a_frame_protector.h"
#include "src/core/tsi/transport_security_grpc.h"
#include "test/core/tsi/s2a/s2a_test_util.h"

static void s2a_zero_copy_grpc_protector_create_test(
    TLSCiphersuite ciphersuite) {
  grpc_core::ExecCtx exec_ctx;
  grpc_core::ExecCtx::Get()->Flush();
  return;
}

int main(int /*argc*/, char** /*argv*/) {
  size_t number_ciphersuites = 3;
  TLSCiphersuite ciphersuite[3] = {TLS_AES_128_GCM_SHA256_ciphersuite,
                                   TLS_AES_256_GCM_SHA384_ciphersuite,
                                   TLS_CHACHA20_POLY1305_SHA256_ciphersuite};
  for (size_t i = 0; i < number_ciphersuites; i++) {
    s2a_zero_copy_grpc_protector_create_test(ciphersuite[i]);
  }
  return 0;
}
