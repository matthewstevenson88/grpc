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

#ifndef GRPC_CORE_TSI_S2A_RECORD_PROTOCOL_S2A_CRYPTER_UTIL_H
#define GRPC_CORE_TSI_S2A_RECORD_PROTOCOL_S2A_CRYPTER_UTIL_H

#include "src/core/tsi/alts/crypt/gsec.h"

/** This method sets |hash_function| to the hash function belonging to
 *  |ciphersuite| if |ciphersuite| is a supported ciphersuite, and returns
 *  TSI_OK; otherwise, it returns an error code and populates |error_details|
 *  with further info, and this must be freed using gpr_free. The caller must
 *  not pass in nullptr for |hash_function|. **/
grpc_status_code s2a_ciphersuite_to_hash_function(uint16_t ciphersuite,
                                                  GsecHashFunction* hash_function,
                                                  char** error_details);

#endif  // GRPC_CORE_TSI_S2A_RECORD_PROTOCOL_S2A_CRYPTER_UTIL_H
