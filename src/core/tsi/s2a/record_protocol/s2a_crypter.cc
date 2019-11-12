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
#include "src/core/tsi/alts/zero_copy_frame_protector/alts_iovec_record_protocol.h"
#include "src/core/tsi/s2a/record_protocol/s2a_crypter_util.h"
#include "src/core/tsi/s2a/s2a_constants.h"

#include <grpc/support/log.h>
#include <grpc/support/string_util.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>

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
    *error_details = gpr_strdup(S2A_UNSUPPORTED_TLS_VERSION);
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
      *error_details = gpr_strdup(S2A_UNSUPPORTED_CIPHERSUITE);
      return GRPC_STATUS_FAILED_PRECONDITION;
  }
  if (expected_key_size != key_size) {
    *error_details = gpr_strdup(S2A_KEY_SIZE_MISMATCH);
    return GRPC_STATUS_FAILED_PRECONDITION;
  }
  if (expected_nonce_size != nonce_size) {
    *error_details = gpr_strdup(S2A_NONCE_SIZE_MISMATCH);
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

/** This function returns the tag size of the ciphersuite supported by
 *  |crypter|. The caller must not pass in nullptr for |crypter|.
 *  - crypter: an instance of s2a_crypter. **/
static size_t s2a_tag_size(const s2a_crypter* crypter) {
  GPR_ASSERT(crypter != nullptr);
  switch (crypter->ciphersuite) {
    case TLS_AES_128_GCM_SHA256:
    case TLS_AES_256_GCM_SHA384:
      return EVP_AEAD_AES_GCM_TAG_LEN;
    case TLS_CHACHA20_POLY1305_SHA256:
      return POLY1305_TAG_LEN;
    default:
      gpr_log(GPR_ERROR, S2A_UNSUPPORTED_CIPHERSUITE);
      abort();
  }
}

/** This function returns the max number of bytes occupied by the nonce of a
 *  TLS 1.3 record that is handled by |crypter|. The caller must not pass in
 *  nullptr for |crypter|.
 *  - crypter: an instance of s2a_crypter. **/
static size_t s2a_max_aead_nonce_size(const s2a_crypter* crypter) {
  GPR_ASSERT(crypter != nullptr);
  /** If additional supported ciphersuites are added, then there may be
   *  additional options for the return value. **/
  return EVP_AEAD_MAX_NONCE_LENGTH;
}

/** This function increments the sequence field of |half_connection|. If the
 *  sequence number overflows, then the function returns
 *  GRPC_STATUS_OUT_OF_RANGE, and the channel must be closed. If
 *  |half_connection| is nullptr, then the function returns
 *  GRPC_STATUS_INTERNAL. Otherwise, the function returns GRPC_STATUS_OK.
 *  - half_connection: an instance of s2a_half_connection. **/
grpc_status_code increment_sequence(s2a_half_connection* half_connection) {
  if (half_connection == nullptr) {
    return GRPC_STATUS_INTERNAL;
  }

  half_connection->sequence += 1;
  /** Check whether the sequence number has overflowed. **/
  if (half_connection->sequence == 0) {
    return GRPC_STATUS_OUT_OF_RANGE;
  }
  return GRPC_STATUS_OK;
}

/** This function populates the 8 bytes that follow |out_bytes| with the
 *  sequence number of |half_connection| converted into bytes. The caller
 *  must not pass in nullptr for |half_connection| or |out_bytes|.
 *  - half_connection: an instance of s2a_half_connection.
 *  - out_bytes: a pointer to a length 8 array of bytes. **/
static void sequence_to_bytes(const s2a_half_connection* half_connection,
                              uint8_t* out_bytes) {
  GPR_ASSERT(half_connection != nullptr);
  GPR_ASSERT(out_bytes != nullptr);
  out_bytes[0] = half_connection->sequence >> 56;
  out_bytes[1] = half_connection->sequence >> 48;
  out_bytes[2] = half_connection->sequence >> 40;
  out_bytes[3] = half_connection->sequence >> 32;
  out_bytes[4] = half_connection->sequence >> 24;
  out_bytes[5] = half_connection->sequence >> 16;
  out_bytes[6] = half_connection->sequence >> 8;
  out_bytes[7] = half_connection->sequence;
}

size_t s2a_max_record_overhead(const s2a_crypter* crypter) {
  GPR_ASSERT(crypter != nullptr);
  GPR_ASSERT(crypter->out_connection != nullptr);
  GPR_ASSERT(crypter->out_connection->initialized);
  return SSL3_RT_HEADER_LENGTH + s2a_tag_size(crypter) + /** record type **/ 1;
}

static grpc_status_code s2a_write_tls13_record_header(uint8_t record_type,
                                                      size_t header_size,
                                                      size_t payload_size,
                                                      uint8_t* record_header,
                                                      char** error_details) {
  GPR_ASSERT(record_header != nullptr);
  if (header_size != SSL3_RT_HEADER_LENGTH) {
    *error_details = gpr_strdup(
        "The header size does not match the size of a TLS 1.3 record header.");
    return GRPC_STATUS_FAILED_PRECONDITION;
  }
  record_header[0] = record_type;
  const uint16_t wire_version = static_cast<uint16_t>(TLS1_2_VERSION);
  record_header[1] = wire_version >> 8;
  record_header[2] = wire_version & 0xff;
  record_header[3] = payload_size >> 8;
  record_header[4] = payload_size & 0xff;
  return GRPC_STATUS_OK;
}

static uint8_t* s2a_additional_data(uint8_t* sequence, size_t sequence_size,
                                    uint8_t* record_header, size_t header_size,
                                    size_t payload_size) {
  size_t additional_data_size = sequence_size + header_size;
  GPR_ASSERT(additional_data_size == TLS_ADDITIONAL_DATA_BYTES_SIZE);
  uint8_t* additional_data =
      (uint8_t*)gpr_malloc(additional_data_size * sizeof(uint8_t));
  memcpy(additional_data, sequence, sequence_size);
  memcpy(additional_data + sequence_size, record_header, header_size);
  additional_data[11] = payload_size >> 8;
  additional_data[12] = payload_size & 0xff;
  return additional_data;
}

static uint8_t* s2a_nonce(s2a_crypter* crypter, uint8_t* sequence,
                          size_t sequence_size, size_t* nonce_size) {
  GPR_ASSERT(crypter != nullptr);
  size_t max_nonce_size = s2a_max_aead_nonce_size(crypter);
  GPR_ASSERT(max_nonce_size > sequence_size);
  GPR_ASSERT(sequence != nullptr);
  GPR_ASSERT(nonce_size != nullptr);
  uint8_t* nonce = (uint8_t*)gpr_malloc(max_nonce_size * sizeof(uint8_t));
  *nonce_size = crypter->out_connection->fixed_nonce_size;
  memset(nonce, 0, max_nonce_size);
  memcpy(nonce, crypter->out_connection->fixed_nonce, *nonce_size);
  for (size_t i = 0; i < sequence_size; i++) {
    nonce[*nonce_size - sequence_size + i] ^= sequence[i];
  }
  return nonce;
}

grpc_status_code s2a_write_tls13_record(
    s2a_crypter* crypter, uint8_t record_type, const iovec* unprotected_vec,
    size_t unprotected_vec_size, iovec protected_record, size_t* bytes_written,
    char** error_details) {
  GPR_ASSERT(crypter != nullptr);
  GPR_ASSERT(crypter->out_connection != nullptr);
  GPR_ASSERT(crypter->out_connection->initialized);
  GPR_ASSERT(protected_record.iov_base != nullptr);
  GPR_ASSERT(bytes_written != nullptr);
  if (unprotected_vec == nullptr || unprotected_vec_size == 0) {
    GPR_ASSERT(unprotected_vec == nullptr && unprotected_vec_size == 0);
  }
  size_t plaintext_size =
      get_total_length(unprotected_vec, unprotected_vec_size);
  size_t payload_size = plaintext_size + s2a_tag_size(crypter) + 1;

  if (plaintext_size > SSL3_RT_MAX_PLAIN_LENGTH) {
    *error_details = gpr_strdup(S2A_PLAINTEXT_EXCEED_MAX_SIZE);
    return GRPC_STATUS_FAILED_PRECONDITION;
  }
  if (payload_size + SSL3_RT_HEADER_LENGTH > protected_record.iov_len) {
    *error_details = gpr_strdup(S2A_PLAINTEXT_INSUFFICIENT_RECORD_SIZE);
    return GRPC_STATUS_FAILED_PRECONDITION;
  }

  /** Write the record header at the start of |protected_record|. **/
  uint8_t* record_header = static_cast<uint8_t*>(protected_record.iov_base);
  grpc_status_code header_status =
      s2a_write_tls13_record_header(record_type, SSL3_RT_HEADER_LENGTH,
                                    payload_size, record_header, error_details);
  if (header_status != GRPC_STATUS_OK) {
    return header_status;
  }

  uint8_t sequence[8];
  sequence_to_bytes(crypter->out_connection, sequence);

  /** Set up the additional_data_bytes buffer, which is to be authenticated
   *  but not encrypted. **/
  uint8_t* additional_data =
      s2a_additional_data(sequence, /** sequence size **/ 8, record_header,
                          SSL3_RT_HEADER_LENGTH, payload_size);
  iovec aad_vec = {(void*)(additional_data + 8), SSL3_RT_HEADER_LENGTH};

  /** The following constructs the nonce for the TLS payload in local
   *  storage. It is built by taking the fixed nonce from |crypter|'s
   *  out_connection and applying XOR operations with the bytes of the
   *  current sequence number. **/
  size_t nonce_size;
  uint8_t* nonce =
      s2a_nonce(crypter, sequence, /** sequence_size **/ 8, &nonce_size);

  uint8_t record_type_base = record_type;
  iovec record_type_vec = {(void*)(&record_type_base), 1};
  iovec data_for_processing_vec[unprotected_vec_size + 1];
  for (size_t i = 0; i < unprotected_vec_size; i++) {
    data_for_processing_vec[i] = unprotected_vec[i];
  }
  data_for_processing_vec[unprotected_vec_size] = record_type_vec;

  size_t ciphertext_and_tag_size = 0;
  uint8_t* ciphertext_buffer = record_header + SSL3_RT_HEADER_LENGTH;
  iovec ciphertext = {(void*)ciphertext_buffer, payload_size};

  grpc_status_code encrypt_status = gsec_aead_crypter_encrypt_iovec(
      crypter->out_aead_crypter, nonce, nonce_size, &aad_vec, 1,
      data_for_processing_vec, unprotected_vec_size + 1, ciphertext,
      &ciphertext_and_tag_size, error_details);

  // Cleanup.
  gpr_free(additional_data);
  gpr_free(nonce);

  if (encrypt_status != GRPC_STATUS_OK) {
    return encrypt_status;
  }
  GPR_ASSERT(payload_size == ciphertext_and_tag_size);
  *bytes_written = ciphertext_and_tag_size + SSL3_RT_HEADER_LENGTH;

  grpc_status_code increment_status =
      increment_sequence(crypter->out_connection);
  return increment_status;
}

grpc_status_code s2a_encrypt(s2a_crypter* crypter, uint8_t* plaintext,
                             size_t plaintext_size, uint8_t* record,
                             size_t record_allocated_size, size_t* record_size,
                             char** error_details) {
  if (plaintext == nullptr && plaintext_size > 0) {
    *error_details = gpr_strdup(S2A_PLAINTEXT_NULLPTR);
    return GRPC_STATUS_INVALID_ARGUMENT;
  }
  iovec plaintext_vec = {(void*)plaintext, plaintext_size};
  iovec record_vec = {(void*)record, record_allocated_size};
  return s2a_write_tls13_record(crypter, SSL3_RT_APPLICATION_DATA,
                                &plaintext_vec, 1, record_vec, record_size,
                                error_details);
}
