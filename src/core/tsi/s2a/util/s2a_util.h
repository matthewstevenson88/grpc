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

#ifndef GRPC_CORE_TSI_S2A_UTIL_S2A_UTIL_H_
#define GRPC_CORE_TSI_S2A_UTIL_S2A_UTIL_H_

#include <grpc/impl/codegen/status.h>

#include "src/core/tsi/transport_security_interface.h"

namespace s2a {

/** This method returns the |tsi_result| corresponding to |code| if one exists,
 *  and otherwise it returns TSI_UNKNOWN_ERROR. **/
tsi_result convert_grpc_status_to_tsi_result(grpc_status_code code);

}  // namespace s2a

#endif  // GRPC_CORE_TSI_S2A_UTIL_S2A_UTIL_H_
