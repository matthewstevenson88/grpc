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

#include "src/core/tsi/s2a/handshaker/s2a_handshaker_client.h"
#include <grpc/support/alloc.h>
#include <grpc/support/log.h>
#include "src/core/tsi/s2a/s2a_constants.h"
#include "src/core/tsi/transport_security_grpc.h"
#include "src/core/tsi/transport_security_interface.h"

namespace grpc_core {
namespace experimental {

static void s2a_handshaker_client_test() {
  // TODO(mattstev): implement.
  return;
}

}  // namespace experimental
}  // namespace grpc_core

int main(int argc, char** argv) {
  grpc_core::experimental::s2a_handshaker_client_test();
  return 0;
}
