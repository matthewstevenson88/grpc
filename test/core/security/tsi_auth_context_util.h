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

#ifndef GRPC_TEST_CORE_SECURITY_TSI_AUTH_CONTEXT_UTIL_H
#define GRPC_TEST_CORE_SECURITY_TSI_AUTH_CONTEXT_UTIL_H

#include <grpc/grpc_security.h>
#include <grpc/support/port_platform.h>

/** This method returns true if |ctx| has a peer property of name
 *  |expected_property_name| with identity equal to |expected_identity|. **/
bool check_identity_from_auth_context_for_testing(
    const grpc_auth_context* ctx, const char* expected_property_name,
    const char* expected_identity);

#endif  // GRPC_TEST_CORE_SECURITY_TSI_AUTH_CONTEXT_UTIL_H
