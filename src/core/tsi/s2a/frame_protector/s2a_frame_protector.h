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

#ifndef GRPC_CORE_TSI_S2A_FRAME_PROTECTOR_S2A_FRAME_PROTECTOR_H
#define GRPC_CORE_TSI_S2A_FRAME_PROTECTOR_S2A_FRAME_PROTECTOR_H

#include <grpc/support/port_platform.h>
#include "src/core/tsi/transport_security_grpc.h"

/** This method populates |protector| with an s2a_zero_copy_grpc_protector
 *  instance.
 *  - tls_version: the TLS version.
 *  - tls_ciphersuite: the ciphersuite used for encryption and decryption.
 *  - in_traffic_secret: the traffic secret used to derive the in key and in
 *    nonce; this data is owned by the caller, and the caller must not pass in
 *    nullptr for this argument.
 *  - in_traffic_secret_size: the size of the |in_traffic_secret| buffer.
 *  - out_traffic_secret: the traffic secret used to derive the out key and
 *    out nonce; this data is owned by the caller, and the caller must not pass
 *    in nullptr for this argument.
 *  - out_traffic_secret_size: the size of the |out_traffic_secret| buffer.
 *  - channel: an open channel to the S2A; the s2a_zero_copy_grpc_protector does
 *    not take ownership of the channel, and the caller must not pass in nullptr
 *    for this argument.
 *  - protector: a pointer to an s2a_zero_copy_grpc_protector instance,
 *    which will be populated by the method. The caller must not pass in nullptr
 *    for this argument.
 *
 *  When creation succeeds, the method returns TSI_OK; otherwise, it returns an
 *  error code. **/
tsi_result s2a_zero_copy_grpc_protector_create(
    uint16_t tls_version, uint16_t tls_ciphersuite, uint8_t* in_traffic_secret,
    size_t in_traffic_secret_size, uint8_t* out_traffic_secret,
    size_t out_traffic_secret_size, grpc_channel* channel,
    tsi_zero_copy_grpc_protector** protector);

#endif  // GRPC_CORE_TSI_FRAME_PROTECTOR_S2A_FRAME_PROTECTOR_H
