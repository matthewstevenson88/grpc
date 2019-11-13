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

/** The size of the additional data bytes buffer used for encrypting and
 *  decrypting TLS 1.3 records. **/
#define TLS_ADDITIONAL_DATA_BYTES_SIZE 13

/** S2A error messages. **/
#define S2A_UNSUPPORTED_TLS_VERSION \
  "S2A does not support the desired TLS version."
#define S2A_UNSUPPORTED_CIPHERSUITE \
  "S2A does not support the desired TLS ciphersuite."
#define S2A_KEY_SIZE_MISMATCH \
  "The size of the provisioned keys does not match the ciphersuite key size."
#define S2A_NONCE_SIZE_MISMATCH                                              \
  "The size of the provisioned nonces does not match the ciphersuite nonce " \
  "size."
#define S2A_CHACHA_POLY_UNIMPLEMENTED \
  "The CHACHA-POLY AEAD crypter is not yet implemented."
#define S2A_PLAINTEXT_INSUFFICIENT_RECORD_SIZE \
  "The plaintext size is too large to fit in the allocated TLS 1.3 record."
#define S2A_PLAINTEXT_EXCEED_MAX_SIZE                                       \
  "The plaintext size exceeds the maximum plaintext size for a single TLS " \
  "1.3 record."
#define S2A_PLAINTEXT_NULLPTR \
  "If |plaintext| is nullptr, then |plaintext_size| must be set to zero."
#define S2A_RECORD_EXCEED_MAX_SIZE \
  "The TLS 1.3 payload exceeds the maximum size."
#define S2A_RECORD_HEADER_INCORRECT_FORMAT \
  "The TLS 1.3 record header does not have the correct format."
#define S2A_RECORD_INVALID_FORMAT "The format of the TLS 1.3 record is invalid."
#define S2A_RECORD_SMALL_ALERT "The TLS 1.3 alert record is too small."
#define S2A_RECORD_NULLPTR \
  "If |record| is nullptr, then |record_size| must be set to zero."
#define S2A_INVALID_UNPROTECTED_VEC \
  "Ensure |unprotected_vec| is nullptr iff |unprotected_vec_size| = 0."

#endif  // GRPC_CORE_TSI_S2A_S2A_CONSTANTS_H
