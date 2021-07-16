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

#ifndef GRPC_CORE_TSI_S2A_GRPC_S2A_CREDENTIALS_OPTIONS_H_
#define GRPC_CORE_TSI_S2A_GRPC_S2A_CREDENTIALS_OPTIONS_H_

#include "s2a/include/s2a_options.h"

// C wrapper around |S2AOptions| to be used by the wrapped languages.
struct grpc_s2a_credentials_options {
  s2a::s2a_options::S2AOptions s2a_options;
};

#endif  // GRPC_CORE_TSI_S2A_GRPC_S2A_CREDENTIALS_OPTIONS_H_
