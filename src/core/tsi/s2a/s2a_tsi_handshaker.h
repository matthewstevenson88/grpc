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

#ifndef GRPC_CORE_TSI_S2A_S2A_TSI_HANDSHAKER_H_
#define GRPC_CORE_TSI_S2A_S2A_TSI_HANDSHAKER_H_

#include <string>

#include <grpc/grpc.h>

#include "src/core/tsi/s2a/grpc_s2a_credentials_options.h"
#include "absl/status/statusor.h"
#include "src/core/lib/iomgr/pollset_set.h"
#include "src/core/tsi/transport_security.h"
#include "src/core/tsi/transport_security_interface.h"
#include "s2a/include/s2a_proxy.h"

namespace s2a {
namespace tsi {

struct S2ATsiHandshakerOptions {
  // Set of pollsets interested in the application-to-S2A channel.
  grpc_pollset_set* interested_parties;
  // Indicates if the application is a client or a server.
  bool is_client;
  // Configures how the |s2a_tsi_handshaker| communicates with an S2A, including
  // the URL of the S2A that should be used for handshake offloading.
  grpc_s2a_credentials_options* s2a_options;
  // Authority of that target that this application intends to connect to, e.g.
  // a string of the form '[hostname]:[port]'
  const char* target_name;
};

// Creates a TSI handshaker instance that uses S2A to do the mTLS handshake.
//
// Takes ownership of (the pointers held by) |options|.
absl::StatusOr<tsi_handshaker*> CreateS2ATsiHandshaker(
    S2ATsiHandshakerOptions& options);

// Creates a TSI handshaker result instance produced by the S2A.
absl::StatusOr<tsi_handshaker_result*> CreateS2ATsiHandshakerResult(
    std::unique_ptr<s2a_proxy::S2AProxy> proxy);

// Returns true if |handshaker| is shutdown.
//
// Does not take ownership of |handshaker|. Caller must ensure that |handshaker|
// is an instance of the S2A TSI handshaker.
bool IsShutdown(tsi_handshaker* handshaker);

// Sets the unused bytes of the TSI handshaker result
//
// Does not take ownership of |result| or of |recv_bytes|. Caller must ensure
// that |result| is an instance of the S2A TSI handshaker result, that |result|
// is not nullptr, and that |recv_bytes| is not nullptr.
void SetUnusedBytes(tsi_handshaker_result* result, grpc_slice* recv_bytes,
                    size_t bytes_consumed);

}  // namespace tsi
}  // namespace s2a

#endif  // GRPC_CORE_TSI_S2A_S2A_TSI_HANDSHAKER_H_
