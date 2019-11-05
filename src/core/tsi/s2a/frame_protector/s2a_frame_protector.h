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
#include <stdbool.h>
#include "src/core/tsi/transport_security_grpc.h"

/** This method populates |protector| with an s2a_zero_copy_grpc_protector
 *  instance.
 *  - tls_version: the TLS version.
 *  - tls_ciphersuite: the ciphersuite used for encryption and decryption.
 *  - derived_in_key: the key used for decryption; this data is owned by the
 *    caller.
 *  - derived_out_key: the key used for encryption; this data is owned by the
 *    caller.
 *  - key_size: the size of the derived_in_key and derived_out_key; this must
 *    match the key size prescribed by |tls_ciphersuite|.
 *  - derived_in_nonce: the nonce used for decryption; this data is owned by the
 *    caller.
 *  - derived_out_nonce: the nonce used for encryption; this data is owned by
 *    the caller.
 *  - nonce_size: the size of the derived_in_nonce and derived_out_nonce; this
 *    must match the nonce size prescribed by |tls_ciphersuite|.
 *  - channel: an open channel to the S2A; the s2a_zero_copy_grpc_protector does
 *    not take ownership of the channel.
 *  - crypter: a pointer to an s2a_crypter, which will be populated by the
 *    s2a_crypter created by the method. It is legal (and expected) to pass in
 *    nullptr as an argument.
 *
 *  When creation succeeds, the method returns TSI_OK; otherwise, it returns a
 *  specific error code. **/
tsi_result s2a_zero_copy_grpc_protector_create(
    uint16_t tls_version, uint16_t tls_ciphersuite, uint8_t* in_key,
    uint8_t* out_key, size_t key_size, uint8_t* in_nonce, uint8_t* out_nonce,
    size_t nonce_size, grpc_channel* channel,
    tsi_zero_copy_grpc_protector** protector);

#endif  // GRPC_CORE_TSI_FRAME_PROTECTOR_S2A_FRAME_PROTECTOR_H
