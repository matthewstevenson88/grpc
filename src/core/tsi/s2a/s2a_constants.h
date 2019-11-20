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

#ifndef GRPC_CORE_TSI_S2A_S2A_CONSTANTS_H
#define GRPC_CORE_TSI_S2A_S2A_CONSTANTS_H

/** The following constants are ciphersuite-specific data. **/
constexpr size_t kEvpAeadAesGcmTagLength = 16;
constexpr size_t kEvpAeadMaxNonceLength = 24;
constexpr size_t kPoly1305TagLength = 16;

/** The uint16_t's for the supported TLS 1.3 ciphersuites. **/
constexpr uint16_t kTlsAes128GcmSha256 = 0x009c;
constexpr uint16_t kTlsAes256GcmSha384 = 0x1302;
constexpr uint16_t kTlsChacha20Poly1305Sha256 = 0xcca8;

/** The following constants represent the key and nonce sizes of the supported
 *  ciphersuites. **/
constexpr size_t kTlsAes128GcmSha256KeySize = 16;
constexpr size_t kTlsAes256GcmSha384KeySize = 32;
constexpr size_t kTlsChacha20Poly1305Sha256KeySize = 32;

constexpr size_t kTlsAes128GcmSha256NonceSize = 12;
constexpr size_t kTlsAes256GcmSha384NonceSize = 12;
constexpr size_t kTlsChacha20Poly1305Sha256NonceSize = 12;

/** The size of the additional data bytes buffer used for encrypting and
 *  decrypting TLS 1.3 records. **/
constexpr size_t kTlsAdditionalDataBytesSize = 13;

/** S2A error messages. **/
constexpr char kS2AUnsupportedTlsVersion[] =
    "S2A does not support the desired TLS version.";
constexpr char kS2AUnsupportedCiphersuite[] =
    "S2A does not support the desired TLS ciphersuite.";
constexpr char kS2AKeySizeMismatch[] =
    "The size of the provisioned keys does not match the ciphersuite key size.";
constexpr char kS2ANonceSizeMismatch[] =
    "The size of the provisioned nonces does not match the ciphersuite nonce "
    "size.";
constexpr char kS2AChachaPolyUnimplemented[] =
    "The CHACHA-POLY AEAD crypter is not yet implemented.";
constexpr char kS2APlaintextInsufficientRecordSize[] =
    "The plaintext size is too large to fit in the allocated TLS 1.3 record.";
constexpr char kS2APlaintextExceedMaxSize[] =
    "The plaintext size exceeds the maximum plaintext size for a single TLS "
    "1.3 record.";
constexpr char kS2APlaintextNullptr[] =
    "If |plaintext| is nullptr, then |plaintext_size| must be set to zero.";
constexpr char kS2AInvalidUnprotectedVec[] =
    "Ensure |unprotected_vec| is nullptr iff |unprotected_vec_size| = 0.";

#endif  // GRPC_CORE_TSI_S2A_S2A_CONSTANTS_H
