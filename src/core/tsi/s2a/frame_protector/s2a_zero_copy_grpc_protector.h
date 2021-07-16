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

#ifndef GRPC_CORE_TSI_S2A_FRAME_PROTECTOR_S2A_ZERO_COPY_GRPC_PROTECTOR_H_
#define GRPC_CORE_TSI_S2A_FRAME_PROTECTOR_S2A_ZERO_COPY_GRPC_PROTECTOR_H_

#include "absl/status/statusor.h"
#include "src/core/tsi/transport_security_grpc.h"
#include "s2a/include/s2a_frame_protector.h"

namespace s2a {

absl::StatusOr<tsi_zero_copy_grpc_protector*>
s2a_zero_copy_grpc_protector_create(
    std::unique_ptr<frame_protector::S2AFrameProtector> frame_protector);

}  // namespace s2a

#endif  // GRPC_CORE_TSI_S2A_FRAME_PROTECTOR_S2A_ZERO_COPY_GRPC_PROTECTOR_H_
