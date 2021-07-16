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

#include "src/core/tsi/s2a/util/s2a_util.h"

namespace s2a {

tsi_result convert_grpc_status_to_tsi_result(grpc_status_code code) {
  switch (code) {
    case GRPC_STATUS_OK:
      return TSI_OK;
    case GRPC_STATUS_UNKNOWN:
      return TSI_UNKNOWN_ERROR;
    case GRPC_STATUS_INVALID_ARGUMENT:
      return TSI_INVALID_ARGUMENT;
    case GRPC_STATUS_FAILED_PRECONDITION:
      return TSI_FAILED_PRECONDITION;
    case GRPC_STATUS_UNIMPLEMENTED:
      return TSI_UNIMPLEMENTED;
    case GRPC_STATUS_NOT_FOUND:
      return TSI_NOT_FOUND;
    case GRPC_STATUS_INTERNAL:
      return TSI_INTERNAL_ERROR;
    default:
      return TSI_UNKNOWN_ERROR;
  }
}

}  // namespace s2a
