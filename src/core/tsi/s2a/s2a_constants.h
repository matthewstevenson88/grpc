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

/** The following constants are defined in BoringSSL but not OpenSSL.
 *  See the aead.h file in BoringSSL for more documentation. **/
#ifndef EVP_AEAD_AES_GCM_TAG_LEN
#define EVP_AEAD_AES_GCM_TAG_LEN 16
#endif

#ifndef POLY1305_TAG_LEN
#define POLY1305_TAG_LEN 16
#endif

#ifndef EVP_AEAD_MAX_NONCE_LENGTH
#define EVP_AEAD_MAX_NONCE_LENGTH 24
#endif

/** The uint16_t's for the supported TLS 1.3 ciphersuites. **/
#define TLS_AES_128_GCM_SHA256 0x009c
#define TLS_AES_256_GCM_SHA384 0x1302
#define TLS_CHACHA20_POLY1305_SHA256 0xcca8

/** The following constants represent the key and nonce sizes of the supported
 *  ciphersuites. **/
#define TLS_AES_128_GCM_SHA256_KEY_SIZE 16
#define TLS_AES_256_GCM_SHA384_KEY_SIZE 32
#define TLS_CHACHA20_POLY1305_SHA256_KEY_SIZE 32

#define TLS_AES_128_GCM_SHA256_NONCE_SIZE 12
#define TLS_AES_256_GCM_SHA384_NONCE_SIZE 12
#define TLS_CHACHA20_POLY1305_SHA256_NONCE_SIZE 12

#endif  // GRPC_CORE_TSI_S2A_S2A_CONSTANTS_H
