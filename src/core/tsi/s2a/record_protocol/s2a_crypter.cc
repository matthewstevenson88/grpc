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

#include "src/core/tsi/s2a/record_protocol/s2a_crypter.h"
#include "src/core/tsi/s2a/record_protocol/s2a_crypter_util.h"

#include <grpc/support/log.h>
#include <grpc/support/string_util.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>

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

/** The following constants represent the key and nonce sizes of the supported
 *  ciphersuites. **/
#define TLS_AES_128_GCM_SHA256_KEY_SIZE 16
#define TLS_AES_256_GCM_SHA384_KEY_SIZE 32
#define TLS_CHACHA20_POLY1305_SHA256_KEY_SIZE 32

#define TLS_AES_128_GCM_SHA256_NONCE_SIZE 12
#define TLS_AES_256_GCM_SHA384_NONCE_SIZE 12
#define TLS_CHACHA20_POLY1305_SHA256_NONCE_SIZE 12

/** The struct that represents the state of an S2A connection in a single
 *  direction. **/
typedef struct s2a_half_connection {
  uint64_t sequence = 0;
  bool initialized = false;
  uint8_t fixed_nonce_size = 0;
  uint8_t* fixed_nonce;
  uint8_t additional_data_size = 0;
} s2a_half_connection;

/** The main struct for the s2a_crypter interface. **/
typedef struct s2a_crypter {
  const uint16_t tls_version = 0;
  const uint16_t ciphersuite = 0;
  /** The in_aead_crypter is used to decrypt incoming traffic, and
   *  in_connection stores the auxiliary data necessary to decrypt. **/
  gsec_aead_crypter* in_aead_crypter;
  s2a_half_connection* in_connection;
  /** The out_aead_crypter is used to encrypt outgoing traffic, and
   *  out_connection stores the auxiliary data necessary to encrypt. **/
  gsec_aead_crypter* out_aead_crypter;
  s2a_half_connection* out_connection;
  /** The s2a_channel points to the (open) channel that was established with the
   *  client's S2A module during the handshake. **/
  grpc_channel* s2a_channel;
  s2a_crypter(const int version, const int cipher)
      : tls_version(version), ciphersuite(cipher) {}
} s2a_crypter;

static grpc_status_code assign_crypter(bool in, uint8_t* derived_key,
                                       size_t key_size, uint8_t* derived_nonce,
                                       size_t nonce_size, size_t tag_size,
                                       uint64_t sequence, s2a_crypter** crypter,
                                       char** error_details) {
  s2a_crypter* rp_crypter = *crypter;

  /** Create the aead crypter. **/
  gsec_aead_crypter* aead_crypter = nullptr;
  grpc_status_code aead_crypter_status;
  switch (rp_crypter->ciphersuite) {
    case TLS_AES_128_GCM_SHA256:
    case TLS_AES_256_GCM_SHA384:
      aead_crypter_status = gsec_aes_gcm_aead_crypter_create(
          derived_key, key_size, nonce_size, tag_size,
          /** rekey **/ false, &aead_crypter, error_details);
      break;
    case TLS_CHACHA20_POLY1305_SHA256:
      aead_crypter_status = gsec_chacha_poly_aead_crypter_create(
          derived_key, key_size, nonce_size, tag_size, &aead_crypter,
          error_details);
      break;
    default:
      *error_details = gpr_strdup(
          "The crypter's ciphersuite is not supported; cannot initialize AEAD "
          "crypter.");
      return GRPC_STATUS_FAILED_PRECONDITION;
  }
  if (aead_crypter_status != GRPC_STATUS_OK) {
    return aead_crypter_status;
  }
  if (in) {
    rp_crypter->in_aead_crypter = aead_crypter;
  } else {
    rp_crypter->out_aead_crypter = aead_crypter;
  }

  /** Assign the remaining data for the half connection. **/
  s2a_half_connection* half_connection =
      (s2a_half_connection*)gpr_malloc(sizeof(s2a_half_connection));
  if (in) {
    rp_crypter->in_connection = half_connection;
  } else {
    rp_crypter->out_connection = half_connection;
  }
  half_connection->initialized = true;
  half_connection->sequence = sequence;
  half_connection->fixed_nonce_size = nonce_size;
  half_connection->fixed_nonce =
      (uint8_t*)gpr_zalloc(nonce_size * sizeof(uint8_t));
  memcpy(half_connection->fixed_nonce, derived_nonce, nonce_size);
  half_connection->additional_data_size = SSL3_RT_HEADER_LENGTH;

  return GRPC_STATUS_OK;
}

grpc_status_code s2a_crypter_create(
    uint16_t tls_version, uint16_t tls_ciphersuite, uint8_t* derived_in_key,
    uint8_t* derived_out_key, size_t key_size, uint8_t* derived_in_nonce,
    uint8_t* derived_out_nonce, size_t nonce_size, grpc_channel* channel,
    s2a_crypter** crypter, char** error_details) {
  if (crypter == nullptr) {
    *error_details = gpr_strdup("The argument |crypter| must not be nullptr.");
    return GRPC_STATUS_FAILED_PRECONDITION;
  }
  if (tls_version != 0) {
    *error_details =
        gpr_strdup("S2A does not support the desired TLS version.");
    return GRPC_STATUS_FAILED_PRECONDITION;
  }
  if (derived_in_key == nullptr || derived_out_key == nullptr ||
      derived_in_nonce == nullptr || derived_out_nonce == nullptr) {
    *error_details = gpr_strdup("The key materials must not be nullptr.");
    return GRPC_STATUS_FAILED_PRECONDITION;
  }
  if (channel == nullptr) {
    *error_details = gpr_strdup("The argument |channel| must not be nullptr.");
    return GRPC_STATUS_FAILED_PRECONDITION;
  }

  *crypter = grpc_core::New<s2a_crypter>(tls_version, tls_ciphersuite);
  s2a_crypter* rp_crypter = *crypter;
  rp_crypter->in_aead_crypter = nullptr;
  rp_crypter->out_aead_crypter = nullptr;
  rp_crypter->in_connection = nullptr;
  rp_crypter->out_connection = nullptr;

  // TODO(mattstev): change the keys from "already derived" to "non derived" and
  // apply the HKDF.

  /** The following extracts the keys and nonces used for encryption and
   *  decryption. **/
  size_t expected_key_size;
  size_t expected_nonce_size;
  switch (rp_crypter->ciphersuite) {
    case TLS_AES_128_GCM_SHA256:
      expected_key_size = TLS_AES_128_GCM_SHA256_KEY_SIZE;
      expected_nonce_size = TLS_AES_128_GCM_SHA256_NONCE_SIZE;
      break;
    case TLS_AES_256_GCM_SHA384:
      expected_key_size = TLS_AES_256_GCM_SHA384_KEY_SIZE;
      expected_nonce_size = TLS_AES_256_GCM_SHA384_NONCE_SIZE;
      break;
    case TLS_CHACHA20_POLY1305_SHA256:
      expected_key_size = TLS_CHACHA20_POLY1305_SHA256_KEY_SIZE;
      expected_nonce_size = TLS_CHACHA20_POLY1305_SHA256_NONCE_SIZE;
      break;
    default:
      *error_details = gpr_strdup(
          "The crypter's ciphersuite is not supported; cannot set expected "
          "key/nonce size.");
      return GRPC_STATUS_FAILED_PRECONDITION;
  }
  if (expected_key_size != key_size) {
    *error_details = gpr_strdup(
        "The size of the provisioned keys does not match the ciphersuite key "
        "size.");
    return GRPC_STATUS_FAILED_PRECONDITION;
  }
  if (expected_nonce_size != nonce_size) {
    *error_details = gpr_strdup(
        "The size of the provisioned nonces does not match the ciphersuite "
        "nonce size.");
    return GRPC_STATUS_FAILED_PRECONDITION;
  }

  size_t tag_size = (rp_crypter->ciphersuite == TLS_CHACHA20_POLY1305_SHA256)
                        ? POLY1305_TAG_LEN
                        : EVP_AEAD_AES_GCM_TAG_LEN;

  grpc_status_code in_crypter_status = assign_crypter(
      /** in **/ true, derived_in_key, key_size, derived_in_nonce, nonce_size,
      tag_size, /** sequence **/ 0, crypter, error_details);
  if (in_crypter_status != GRPC_STATUS_OK) {
    return in_crypter_status;
  }

  grpc_status_code out_crypter_status = assign_crypter(
      /** in **/ false, derived_out_key, key_size, derived_out_nonce,
      nonce_size, tag_size, /** sequence **/ 0, crypter, error_details);
  if (out_crypter_status != GRPC_STATUS_OK) {
    return out_crypter_status;
  }

  rp_crypter->s2a_channel = channel;
  return GRPC_STATUS_OK;
}

void s2a_crypter_destroy(s2a_crypter* crypter) {
  if (crypter != nullptr) {
    if (crypter->in_connection != nullptr &&
        crypter->in_connection->initialized) {
      gpr_free(crypter->in_connection->fixed_nonce);
      gpr_free(crypter->in_connection);
    }
    if (crypter->out_connection != nullptr &&
        crypter->out_connection->initialized) {
      gpr_free(crypter->out_connection->fixed_nonce);
      gpr_free(crypter->out_connection);
    }
    if (crypter->in_aead_crypter != nullptr) {
      gsec_aead_crypter_destroy(crypter->in_aead_crypter);
    }
    if (crypter->out_aead_crypter != nullptr) {
      gsec_aead_crypter_destroy(crypter->out_aead_crypter);
    }
    grpc_core::Delete<s2a_crypter>(crypter);
  }
}

gsec_aead_crypter* s2a_in_aead_crypter(s2a_crypter* crypter) {
  if (crypter == nullptr) {
    return nullptr;
  }
  return crypter->in_aead_crypter;
}

gsec_aead_crypter* s2a_out_aead_crypter(s2a_crypter* crypter) {
  if (crypter == nullptr) {
    return nullptr;
  }
  return crypter->out_aead_crypter;
}

void check_half_connection(s2a_crypter* crypter, bool in_half_connection,
                           uint64_t expected_sequence,
                           uint8_t expected_fixed_nonce_size,
                           uint8_t* expected_fixed_nonce,
                           uint8_t expected_additional_data_size) {
  s2a_half_connection* half_connection =
      in_half_connection ? crypter->in_connection : crypter->out_connection;
  GPR_ASSERT(half_connection != nullptr);
  GPR_ASSERT(half_connection->initialized);
  GPR_ASSERT(half_connection->sequence == expected_sequence);
  GPR_ASSERT(half_connection->fixed_nonce_size == expected_fixed_nonce_size);
  for (size_t i = 0; i < expected_fixed_nonce_size; i++) {
    GPR_ASSERT(half_connection->fixed_nonce[i] == expected_fixed_nonce[i]);
  }
  GPR_ASSERT(half_connection->additional_data_size ==
             expected_additional_data_size);
}
