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
#include <vector>

#include <iostream>

/** The struct that represents the state of an S2A connection in a single
 *  direction. **/
typedef struct s2a_half_connection {
  uint64_t sequence = 0;
  bool initialized = false;
  size_t traffic_secret_size = 0;
  uint8_t* traffic_secret;
  size_t nonce_size = 0;
  uint8_t* nonce;
  size_t additional_data_size = 0;
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

/** This function populates |tag size| with the tag size of the ciphersuite
 *  |ciphersuite|. The caller must not pass in nullptr for |tag_size| or
 *  |error_details|.
 *  - ciphersuite: the ciphersuite in question.
 *  - tag_size: a pointer that will be populated with the tag size of
 *    |ciphersuite|.
 *  - error_details: the error details generated when the execution of the
 *    function fails.
 *
 *  On success, the function returns GRPC_STATUS_OK; otherwise, |error_details|
 *  is populated with an error message, and it must be freed with gpr_free. **/
static grpc_status_code s2a_tag_size(uint16_t ciphersuite,
                                     size_t* tag_size, char** error_details) {
  GPR_ASSERT(tag_size != nullptr);
  GPR_ASSERT(error_details != nullptr);
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
    case kTlsAes256GcmSha384:
      *tag_size = kEvpAeadAesGcmTagLength;
      break;
    case kTlsChacha20Poly1305Sha256:
      *tag_size = kPoly1305TagLength;
      break;
    default:
      *error_details = gpr_strdup(kS2AUnsupportedCiphersuite);
      return GRPC_STATUS_INTERNAL;
  }
  return GRPC_STATUS_OK;
}

/** This method updates the traffic secret in |traffic_secret| based on
 *  |ciphersuite|. See https://tools.ietf.org/html/rfc8446#section-7.2 for
 *  details. **/
static grpc_status_code advance_secret(uint16_t ciphersuite, uint8_t* traffic_secret,
                                       size_t traffic_secret_size, char** error_details) {
  GsecHashFunction hash_function;
  grpc_status_code hash_function_status = s2a_ciphersuite_to_hash_function(
      ciphersuite, &hash_function, error_details);
  if (hash_function_status != GRPC_STATUS_OK) {
    return hash_function_status;
  }

  const uint8_t suffix[] = "\x11tls13 traffic upd\x00";
  const size_t suffix_size = 19;
  uint8_t label[2 + suffix_size];
  label[0] = traffic_secret_size >> 8;
  label[1] = traffic_secret_size;
  memcpy(&label[2], suffix, suffix_size);
  return hkdf_derive_secret(traffic_secret, traffic_secret_size, hash_function,
                            traffic_secret, traffic_secret_size, label, sizeof(label));
}

/** This method write |out_size| bytes of derived secret to |output|, based on
 *  |secret|, |suffix|, and |ciphersuite|. **/
static grpc_status_code derive_secret(uint16_t ciphersuite, uint8_t* suffix,
                                      size_t suffix_size, uint8_t* secret,
                                      size_t secret_size, size_t output_size,
                                      uint8_t* output, char** error_details) {
  GsecHashFunction hash_function;
  grpc_status_code hash_function_status = s2a_ciphersuite_to_hash_function(
      ciphersuite, &hash_function, error_details);
  if (hash_function_status != GRPC_STATUS_OK) {
    return hash_function_status;
  }

  /** The label buffer consists of 2 pieces: the first 2 bytes encode
   *  |output_size|, and the following 10 or 11 bytes encode |suffix| (note that
   *  the suffix is 10 bytes when deriving the nonce, and 11 bytes long when
   *  deriving the key). **/
  uint8_t label[2 + 11];
  const size_t label_size = 2 + suffix_size;
  GPR_ASSERT(sizeof(label) >= label_size);
  label[0] = output_size >> 8;
  label[1] = output_size;
  memcpy(label + 2, suffix, suffix_size);

  return hkdf_derive_secret(output, output_size, hash_function, secret,
                            secret_size, label, label_size);
}

/** This method write |out_size| bytes of derived key to |output|, based on
 *  |secret| and |ciphersuite|. **/
static grpc_status_code derive_key(uint16_t ciphersuite, uint8_t* secret,
                                   size_t secret_size, size_t output_size,
                                   uint8_t* output, char** error_details) {
  GPR_ASSERT(error_details != nullptr);
  uint8_t key_suffix[] = "\x09tls13 key\x00";
  size_t suffix_size = sizeof(key_suffix) - 1;
  return derive_secret(ciphersuite, key_suffix, suffix_size, secret,
                       secret_size, output_size, output, error_details);
}

/** This method write |out_size| bytes of derived nonce to |output|, based on
 *  |secret| and |ciphersuite|. **/
static grpc_status_code derive_nonce(uint16_t ciphersuite, uint8_t* secret,
                                     size_t secret_size, size_t output_size,
                                     uint8_t* output, char** error_details) {
  GPR_ASSERT(error_details != nullptr);
  uint8_t nonce_suffix[] = "\x08tls13 iv\x00";
  size_t suffix_size = sizeof(nonce_suffix) - 1;
  return derive_secret(ciphersuite, nonce_suffix, suffix_size, secret,
                       secret_size, output_size, output, error_details);
}

/** This method populates |aead_crypter| with a gsec_aead_crypter instance and
 *  returns GRPC_STATUS_OK on success; if |aead_crypter| points to a non-null
 *  gsec_aead_crypter, then this method first destroys that crypter. The caller
 *  must not pass in nullptr for |aead_crypter|. On failure,
 *  the method returns an error code and populates |error_details|, which must
 *  be freed using gpr_free. **/
static grpc_status_code assign_aead_crypter(uint16_t ciphersuite,
                                            uint8_t* key,
                                            size_t key_size,
                                            size_t nonce_size,
                                            size_t tag_size,
                                            gsec_aead_crypter** aead_crypter,
                                            char** error_details) {
  GPR_ASSERT(aead_crypter != nullptr);
  GPR_ASSERT(error_details != nullptr);
  if (*aead_crypter != nullptr) {
    gsec_aead_crypter_destroy(*aead_crypter);
  }
  grpc_status_code aead_crypter_status;
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
    case kTlsAes256GcmSha384:
      aead_crypter_status = gsec_aes_gcm_aead_crypter_create(
          key, key_size, nonce_size, tag_size,
          /* rekey=*/false, aead_crypter, error_details);
      break;
    case kTlsChacha20Poly1305Sha256:
      aead_crypter_status = gsec_chacha_poly_aead_crypter_create(
          key, key_size, nonce_size, tag_size, aead_crypter, error_details);
      break;
    default:
      *error_details = gpr_strdup(kS2AUnsupportedCiphersuite);
      return GRPC_STATUS_FAILED_PRECONDITION;
  }
  if (aead_crypter_status != GRPC_STATUS_OK) {
    return aead_crypter_status;
  }
  return GRPC_STATUS_OK;
}

static grpc_status_code assign_s2a_crypter(bool in, uint8_t* traffic_secret,
                                       size_t traffic_secret_size,
                                       size_t tag_size, uint64_t sequence,
                                       s2a_crypter** crypter,
                                       char** error_details) {
  GPR_ASSERT(crypter != nullptr);
  s2a_crypter* rp_crypter = *crypter;

  /** Derive the key and nonce from the traffic secret. **/
  size_t key_size;
  size_t nonce_size;
  size_t expected_traffic_secret_size;
  switch (rp_crypter->ciphersuite) {
    case kTlsAes128GcmSha256:
      key_size = kTlsAes128GcmSha256KeySize;
      nonce_size = kTlsAes128GcmSha256NonceSize;
      expected_traffic_secret_size = kSha256DigestLength;
      break;
    case kTlsAes256GcmSha384:
      key_size = kTlsAes256GcmSha384KeySize;
      nonce_size = kTlsAes256GcmSha384NonceSize;
      expected_traffic_secret_size = kSha384DigestLength;
      break;
    case kTlsChacha20Poly1305Sha256:
      key_size = kTlsChacha20Poly1305Sha256KeySize;
      nonce_size = kTlsChacha20Poly1305Sha256NonceSize;
      expected_traffic_secret_size = kSha256DigestLength;
      break;
    default:
      *error_details = gpr_strdup(kS2AUnsupportedCiphersuite);
      return GRPC_STATUS_FAILED_PRECONDITION;
  }
  if (traffic_secret_size != expected_traffic_secret_size) {
    *error_details = gpr_strdup(kS2ATrafficSecretSizeMismatch);
    return GRPC_STATUS_FAILED_PRECONDITION;
  }

  uint8_t key[kEvpAeadMaxKeyLength];
  uint8_t nonce[kEvpAeadMaxNonceLength];
  grpc_status_code key_status =
      derive_key(rp_crypter->ciphersuite, traffic_secret, traffic_secret_size,
                 key_size, key, error_details);
  if (key_status != GRPC_STATUS_OK) {
    return key_status;
  }

  grpc_status_code nonce_status =
      derive_nonce(rp_crypter->ciphersuite, traffic_secret, traffic_secret_size,
                   nonce_size, nonce, error_details);
  if (nonce_status != GRPC_STATUS_OK) {
    return nonce_status;
  }

  /** Create the aead crypter. **/
  gsec_aead_crypter* aead_crypter = nullptr;
  grpc_status_code aead_crypter_status = assign_aead_crypter(
    rp_crypter->ciphersuite, key, key_size, nonce_size, tag_size,
    &aead_crypter, error_details);
  if (aead_crypter_status != GRPC_STATUS_OK) {
    return aead_crypter_status;
  }
  if (in) {
    rp_crypter->in_aead_crypter = aead_crypter;
  } else {
    rp_crypter->out_aead_crypter = aead_crypter;
  }

  /** Assign the remaining data for the half connection. **/
  s2a_half_connection* half_connection = static_cast<s2a_half_connection*>(
      gpr_malloc(sizeof(s2a_half_connection)));
  if (in) {
    rp_crypter->in_connection = half_connection;
  } else {
    rp_crypter->out_connection = half_connection;
  }
  half_connection->initialized = true;
  half_connection->sequence = sequence;
  half_connection->traffic_secret_size = traffic_secret_size;
  half_connection->traffic_secret =
      static_cast<uint8_t*>(gpr_zalloc(traffic_secret_size * sizeof(uint8_t)));
  memcpy(half_connection->traffic_secret, traffic_secret, traffic_secret_size);
  half_connection->nonce_size = nonce_size;
  half_connection->nonce =
      static_cast<uint8_t*>(gpr_zalloc(nonce_size * sizeof(uint8_t)));
  memcpy(half_connection->nonce, nonce, nonce_size);
  half_connection->additional_data_size = SSL3_RT_HEADER_LENGTH;

  return GRPC_STATUS_OK;
}

grpc_status_code s2a_crypter_create(
    uint16_t tls_version, uint16_t tls_ciphersuite, uint8_t* in_traffic_secret,
    size_t in_traffic_secret_size, uint8_t* out_traffic_secret,
    size_t out_traffic_secret_size, grpc_channel* channel,
    s2a_crypter** crypter, char** error_details) {
  GPR_ASSERT(error_details != nullptr);
  if (crypter == nullptr || in_traffic_secret == nullptr ||
      out_traffic_secret == nullptr || channel == nullptr) {
    *error_details = gpr_strdup(kS2ACreateNullptr);
    return GRPC_STATUS_FAILED_PRECONDITION;
  }
  if (tls_version != 0) {
    *error_details = gpr_strdup(kS2AUnsupportedTlsVersion);
    return GRPC_STATUS_FAILED_PRECONDITION;
  }

  *crypter = grpc_core::New<s2a_crypter>(tls_version, tls_ciphersuite);
  s2a_crypter* rp_crypter = *crypter;
  rp_crypter->in_aead_crypter = nullptr;
  rp_crypter->out_aead_crypter = nullptr;
  rp_crypter->in_connection = nullptr;
  rp_crypter->out_connection = nullptr;

  size_t tag_size;
  grpc_status_code tag_status = s2a_tag_size(rp_crypter->ciphersuite, &tag_size, error_details);
  if (tag_status != GRPC_STATUS_OK) {
    return tag_status;
  }

  grpc_status_code in_crypter_status = assign_s2a_crypter(
      /* in=*/ true, in_traffic_secret, in_traffic_secret_size, tag_size,
      /* sequence=*/ 0, crypter, error_details);
  if (in_crypter_status != GRPC_STATUS_OK) {
    return in_crypter_status;
  }

  grpc_status_code out_crypter_status = assign_s2a_crypter(
      /* in=*/ false, out_traffic_secret, out_traffic_secret_size, tag_size,
      /* sequence=*/ 0, crypter, error_details);
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
      gpr_free(crypter->in_connection->traffic_secret);
      gpr_free(crypter->in_connection->nonce);
      gpr_free(crypter->in_connection);
    }
    if (crypter->out_connection != nullptr &&
        crypter->out_connection->initialized) {
      gpr_free(crypter->out_connection->traffic_secret);
      gpr_free(crypter->out_connection->nonce);
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
                           size_t expected_traffic_secret_size,
                           uint8_t* expected_traffic_secret,
                           size_t expected_nonce_size,
                           uint8_t* expected_nonce,
                           uint8_t expected_additional_data_size) {
  s2a_half_connection* half_connection =
      in_half_connection ? crypter->in_connection : crypter->out_connection;
  GPR_ASSERT(half_connection != nullptr);
  GPR_ASSERT(half_connection->initialized);
  GPR_ASSERT(half_connection->sequence == expected_sequence);
  GPR_ASSERT(half_connection->traffic_secret != nullptr);
  GPR_ASSERT(half_connection->traffic_secret_size ==
             expected_traffic_secret_size);
  for (size_t i = 0; i < expected_traffic_secret_size; i++) {
    GPR_ASSERT(half_connection->traffic_secret[i] ==
               expected_traffic_secret[i]);
  }
  GPR_ASSERT(half_connection->nonce != nullptr);
  GPR_ASSERT(half_connection->nonce_size == expected_nonce_size);
  for (size_t i = 0; i < expected_nonce_size; i++) {
    GPR_ASSERT(half_connection->nonce[i] == expected_nonce[i]);
  }
  GPR_ASSERT(half_connection->additional_data_size ==
             expected_additional_data_size);
}

/** This function returns the max number of bytes occupied by the nonce of a
 *  TLS 1.3 record that is handled by |crypter|. The caller must not pass in
 *  nullptr for |crypter|.
 *  - crypter: an instance of s2a_crypter. **/
static size_t s2a_max_aead_nonce_size(const s2a_crypter* crypter) {
  GPR_ASSERT(crypter != nullptr);
  /** If additional supported ciphersuites are added, then there may be
   *  additional options for the return value. **/
  return kEvpAeadMaxNonceLength;
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

grpc_status_code s2a_max_record_overhead(const s2a_crypter& crypter,
                                         size_t* max_record_overhead,
                                         char** error_details) {
  GPR_ASSERT(crypter.out_connection != nullptr);
  GPR_ASSERT(crypter.out_connection->initialized);
  GPR_ASSERT(max_record_overhead != nullptr);
  GPR_ASSERT(error_details != nullptr);
  size_t tag_size;
  grpc_status_code status = s2a_tag_size(crypter->ciphersuite, &tag_size, error_details);
  if (status != GRPC_STATUS_OK) {
    return status;
  }
  *max_record_overhead = SSL3_RT_HEADER_LENGTH + tag_size + /* record type=*/ 1;
  return GRPC_STATUS_OK;
}

static grpc_status_code s2a_write_tls13_record_header(size_t header_size,
                                                      size_t payload_size,
                                                      uint8_t* record_header,
                                                      char** error_details) {
  GPR_ASSERT(record_header != nullptr);
  GPR_ASSERT(error_details != nullptr);
  if (header_size != SSL3_RT_HEADER_LENGTH) {
    *error_details = gpr_strdup(kS2AHeaderSizeMismatch);
    return GRPC_STATUS_FAILED_PRECONDITION;
  }
  /** In TLS 1.3, the record header does not encode the record type or the TLS
   *  version. All record headers are built to look like a TLS 1.2 message of
   *  type "application data" for compatibility reasons. See
   *  https://tools.ietf.org/html/rfc8446#section-5.2. **/
  record_header[0] = SSL3_RT_APPLICATION_DATA;
  const uint16_t wire_version = static_cast<uint16_t>(TLS1_2_VERSION);
  record_header[1] = wire_version >> 8;
  record_header[2] = wire_version & 0xff;
  record_header[3] = payload_size >> 8;
  record_header[4] = payload_size & 0xff;
  return GRPC_STATUS_OK;
}

/** This method returns a buffer populated with the nonce used for
 *  encrypting and decrypting a TLS 1.3 record; the caller must free
 *  the buffer using gpr_free.
 *  - crypter: an instance of s2a_crypter.
 *  - sequence: a buffer containing the sequence number of a half connection.
 *  - sequence_size: the size (in bytes) of the |sequence| buffer.
 *  - nonce_size: the number of bytes written to the nonce buffer that is
 *    returned by the method. **/
static uint8_t* s2a_nonce(s2a_crypter* crypter, uint8_t* sequence,
                          size_t sequence_size, size_t* nonce_size) {
  GPR_ASSERT(crypter != nullptr);
  GPR_ASSERT(crypter->out_connection != nullptr);
  GPR_ASSERT(crypter->out_connection->initialized);
  size_t max_nonce_size = s2a_max_aead_nonce_size(crypter);
  GPR_ASSERT(max_nonce_size > sequence_size);
  GPR_ASSERT(sequence != nullptr);
  GPR_ASSERT(nonce_size != nullptr);
  uint8_t* nonce =
      static_cast<uint8_t*>(gpr_malloc(max_nonce_size * sizeof(uint8_t)));
  *nonce_size = crypter->out_connection->nonce_size;
  memset(nonce, 0, max_nonce_size);
  memcpy(nonce, crypter->out_connection->nonce, *nonce_size);
  for (size_t i = 0; i < sequence_size; i++) {
    nonce[*nonce_size - sequence_size + i] ^= sequence[i];
  }
  return nonce;
}

grpc_status_code s2a_write_tls13_record(
    s2a_crypter* crypter, uint8_t record_type, const iovec* unprotected_vec,
    size_t unprotected_vec_size, iovec protected_record,
    size_t* bytes_written, char** error_details) {
  GPR_ASSERT(crypter != nullptr);
  GPR_ASSERT(crypter->out_connection != nullptr);
  GPR_ASSERT(crypter->out_connection->initialized);
  GPR_ASSERT(protected_record.iov_base != nullptr);
  GPR_ASSERT(bytes_written != nullptr);
  GPR_ASSERT(error_details != nullptr);
  if (unprotected_vec == nullptr && unprotected_vec_size > 0) {
    *error_details = gpr_strdup(kS2AInvalidUnprotectedVec);
    return GRPC_STATUS_FAILED_PRECONDITION;
  }
  size_t plaintext_size =
      get_total_length(unprotected_vec, unprotected_vec_size);
  size_t tag_size;
  grpc_status_code tag_status = s2a_tag_size(crypter->ciphersuite, &tag_size, error_details);
  if (tag_status != GRPC_STATUS_OK) {
    return tag_status;
  }
  size_t payload_size = plaintext_size + tag_size + 1;

  if (plaintext_size > SSL3_RT_MAX_PLAIN_LENGTH) {
    *error_details = gpr_strdup(kS2APlaintextExceedMaxSize);
    return GRPC_STATUS_FAILED_PRECONDITION;
  }
  if (payload_size + SSL3_RT_HEADER_LENGTH > protected_record.iov_len) {
    *error_details = gpr_strdup(kS2APlaintextInsufficientRecordSize);
    return GRPC_STATUS_FAILED_PRECONDITION;
  }

  /** Write the record header at the start of |protected_record|. **/
  uint8_t* record_header = static_cast<uint8_t*>(protected_record.iov_base);
  grpc_status_code header_status = s2a_write_tls13_record_header(SSL3_RT_HEADER_LENGTH, payload_size, record_header, error_details);
  if (header_status != GRPC_STATUS_OK) {
    return header_status;
  }

  uint8_t sequence[kTlsSequenceSize];
  sequence_to_bytes(crypter->out_connection, sequence);

  iovec aad_vec = {reinterpret_cast<void*>(record_header),
                   SSL3_RT_HEADER_LENGTH};

  /** The following constructs the nonce for the TLS payload in local
   *  storage. It is built by taking the nonce mask from |crypter|'s
   *  out_connection and applying XOR operations with the bytes of the
   *  current sequence number. **/
  size_t nonce_size;
  uint8_t* nonce = s2a_nonce(crypter, sequence, kTlsSequenceSize, &nonce_size);

  uint8_t record_type_base = record_type;
  iovec record_type_vec = {(void*)(&record_type_base), 1};
  iovec data_for_processing_vec[unprotected_vec_size + 1];
  for (size_t i = 0; i < unprotected_vec_size; i++) {
    data_for_processing_vec[i] = unprotected_vec[i];
  }
  data_for_processing_vec[unprotected_vec_size] = record_type_vec;

  /** Note that this TLS 1.3 implementation chooses to NOT add padding by zeros
   *  after the ciphertext and record type. This is an optional feature, as
   *  described in https://tools.ietf.org/html/rfc8446#section-5.4 . **/
  size_t ciphertext_and_tag_size = 0;
  uint8_t* ciphertext_buffer = record_header + SSL3_RT_HEADER_LENGTH;
  iovec ciphertext = {reinterpret_cast<void*>(ciphertext_buffer), payload_size};

  grpc_status_code encrypt_status = gsec_aead_crypter_encrypt_iovec(
      crypter->out_aead_crypter, nonce, nonce_size, &aad_vec,
      /* aad_vec length=*/1, data_for_processing_vec, unprotected_vec_size + 1,
      ciphertext, &ciphertext_and_tag_size, error_details);
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
  GPR_ASSERT(error_details != nullptr);
  if (plaintext == nullptr && plaintext_size > 0) {
    *error_details = gpr_strdup(kS2APlaintextNullptr);
    return GRPC_STATUS_INVALID_ARGUMENT;
  }
  iovec plaintext_vec = {reinterpret_cast<void*>(plaintext), plaintext_size};
  iovec record_vec = {reinterpret_cast<void*>(record), record_allocated_size};
  return s2a_write_tls13_record(crypter, SSL3_RT_APPLICATION_DATA,
                                &plaintext_vec, /* plaintext_vec length=*/1,
                                record_vec, record_size, error_details);
}

grpc_status_code s2a_max_plaintext_size(const s2a_crypter& crypter,
                                        size_t record_size,
                                        size_t* plaintext_size,
                                        char** error_details) {
  GPR_ASSERT(plaintext_size != nullptr);
  GPR_ASSERT(error_details != nullptr);

  /** Note that we require this method returns 1 more than the size of the
   *  plaintext that is returned by decrypting a TLS 1.3 record of size
   *  |record_size|; this is because |crypter| requires 1 byte of extra space
   *  after the plaintext to decrypt the record type. **/
  size_t tag_size;
  grpc_status_code tag_status = s2a_tag_size(crypter->ciphersuite, &tag_size, error_details);
  if (tag_status != GRPC_STATUS_OK) {
    return tag_status;
  }
  GPR_ASSERT(record_size >= SSL3_RT_HEADER_LENGTH + tag_size);
  *plaintext_size = record_size - SSL3_RT_HEADER_LENGTH - tag_size;
  return GRPC_STATUS_OK;
}

S2ADecryptStatus s2a_decrypt_payload(s2a_crypter* crypter, iovec& record_header,
                                     const iovec* protected_vec,
                                     size_t protected_vec_size,
                                     iovec& unprotected_vec,
                                     size_t* bytes_written,
                                     char** error_details) {
  GPR_ASSERT(crypter != nullptr);
  GPR_ASSERT(bytes_written != nullptr);
  GPR_ASSERT(error_details != nullptr);
  size_t payload_size = get_total_length(protected_vec, protected_vec_size);
  size_t tag_size;
  grpc_status_code tag_status =
      s2a_tag_size(*crypter, &tag_size, error_details);
  if (tag_status != GRPC_STATUS_OK) {
    return S2ADecryptStatus::INTERNAL_ERROR;
  }
  if (tag_size > payload_size) {
    *error_details = gpr_strdup(kS2ARecordInvalidFormat);
    return S2ADecryptStatus::FAILED_PRECONDITION;
  }
  size_t expected_plaintext_and_record_byte_size = payload_size - tag_size;
  GPR_ASSERT(expected_plaintext_and_record_byte_size <=
             SSL3_RT_MAX_PLAIN_LENGTH + /* record byte=*/1);

  uint8_t sequence[kTlsSequenceSize];
  sequence_to_bytes(crypter->in_connection, sequence);
  size_t nonce_size;
  uint8_t* nonce = s2a_nonce(crypter, sequence, kTlsSequenceSize, &nonce_size);
  grpc_status_code decrypt_status = gsec_aead_crypter_decrypt_iovec(
      crypter->in_aead_crypter, nonce, nonce_size, &record_header,
      /* aad_vec length=*/1, protected_vec, protected_vec_size, unprotected_vec,
      bytes_written, error_details);

  gpr_free(nonce);

  if (decrypt_status != GRPC_STATUS_OK) {
    return S2ADecryptStatus::INTERNAL_ERROR;
  }
  GPR_ASSERT(bytes_written != nullptr);
  GPR_ASSERT(expected_plaintext_and_record_byte_size == *bytes_written);
  return S2ADecryptStatus::OK;
}

static grpc_status_code s2a_key_update(uint16_t ciphersuite,
                                       s2a_half_connection* half_connection,
                                       gsec_aead_crypter** aead_crypter,
                                       char** error_details) {
  GPR_ASSERT(half_connection != nullptr && aead_crypter != nullptr);
  GPR_ASSERT(half_connection->initialized);

  size_t key_size;
  size_t nonce_size;
  switch (ciphersuite) {
    case kTlsAes128GcmSha256:
      key_size = kTlsAes128GcmSha256KeySize;
      nonce_size = kTlsAes128GcmSha256NonceSize;
      break;
    case kTlsAes256GcmSha384:
      key_size = kTlsAes256GcmSha384KeySize;
      nonce_size = kTlsAes256GcmSha384NonceSize;
      break;
    case kTlsChacha20Poly1305Sha256:
      key_size = kTlsChacha20Poly1305Sha256KeySize;
      nonce_size = kTlsChacha20Poly1305Sha256NonceSize;
      break;
    default:
      *error_details = gpr_strdup(kS2AUnsupportedCiphersuite);
      return GRPC_STATUS_FAILED_PRECONDITION;
  }
  std::vector<uint8_t> key_buffer(key_size, 0);
  std::vector<uint8_t> nonce_buffer(nonce_size, 0);

  /** Advance the traffic secret and derive the updated key and nonce. **/
  grpc_status_code status = advance_secret(ciphersuite,
                                           half_connection->traffic_secret,
                                           half_connection->traffic_secret_size,
                                           error_details);
  if (status != GRPC_STATUS_OK) {
    return status;
  }
  std::cout << "*************Advanced traffic secret" << std::endl;
  for (size_t i = 0; i < half_connection->traffic_secret_size; i++) {
    std::cout << static_cast<unsigned>(half_connection->traffic_secret[i]) << ",";
  }
  std::cout << "." << std::endl;

  status = derive_key(ciphersuite, half_connection->traffic_secret,
                      half_connection->traffic_secret_size, key_size,
                      key_buffer.data(), error_details);
  if (status != GRPC_STATUS_OK) {
    return status;
  }
  status = derive_nonce(ciphersuite, half_connection->traffic_secret,
                        half_connection->traffic_secret_size, nonce_size,
                        nonce_buffer.data(), error_details);
  if (status != GRPC_STATUS_OK) {
    return status;
  }

  /** Populate |aead_crypter| with the updated AEAD crypter. **/
  size_t tag_size;
  grpc_status_code tag_status = s2a_tag_size(ciphersuite, &tag_size, error_details);
  if (tag_status != GRPC_STATUS_OK) {
    return tag_status;
  }
  grpc_status_code aead_crypter_status = assign_aead_crypter(
      ciphersuite, key_buffer.data(), key_size, nonce_size, tag_size, aead_crypter, error_details);
  if (aead_crypter_status != GRPC_STATUS_OK) {
    return aead_crypter_status;
  }

  /** Update the relevant fields of |half_connection|. Note that the sequence
   *  number must be reset to zero after a key update; see
   *  https://tools.ietf.org/html/rfc8446#section-5.3. **/
  half_connection->sequence = 0;
  memcpy(half_connection->nonce, nonce_buffer.data(), nonce_size);

  std::cout << "******Ciphersuite: " << static_cast<unsigned>(ciphersuite) << std::endl;
  for (size_t j = 0; j < half_connection->traffic_secret_size; j++) {
    std::cout << static_cast<unsigned>(half_connection->traffic_secret[j]) << std::endl;
  }
  GPR_ASSERT(0 == 1);
  return GRPC_STATUS_OK;
}

S2ADecryptStatus s2a_decrypt_record(s2a_crypter* crypter, iovec& record_header,
                                    const iovec* protected_vec,
                                    size_t protected_vec_size,
                                    iovec& unprotected_vec,
                                    size_t* plaintext_bytes_written,
                                    char** error_details) {
  GPR_ASSERT(crypter != nullptr);
  GPR_ASSERT(plaintext_bytes_written != nullptr);
  GPR_ASSERT(error_details != nullptr);
  size_t max_plaintext_size;
  grpc_status_code plaintext_status = s2a_max_plaintext_size(
      *crypter,
      get_total_length(protected_vec, protected_vec_size) +
          SSL3_RT_HEADER_LENGTH,
      &max_plaintext_size, error_details);
  if (plaintext_status != GRPC_STATUS_OK) {
    return S2ADecryptStatus::INTERNAL_ERROR;
  }
  GPR_ASSERT(unprotected_vec.iov_len >= max_plaintext_size);
  uint8_t* header = reinterpret_cast<uint8_t*>(record_header.iov_base);
  const uint16_t wire_version = static_cast<uint16_t>(TLS1_2_VERSION);
  size_t payload_size = get_total_length(protected_vec, protected_vec_size);
  size_t tag_size;
  grpc_status_code tag_status = s2a_tag_size(crypter->ciphersuite, &tag_size, error_details);
  if (tag_status != GRPC_STATUS_OK) {
    return INTERNAL_ERROR;
  }
  if (payload_size >
      SSL3_RT_MAX_PLAIN_LENGTH + tag_size + /** record type **/ 1) {
    /** If the plaintext size exceeds the max allowed, the TLS 1.3 RFC demands
     *  that the record protocol returns a "record overflow" alert and that the
     *  connection be terminated; for more details, see
     *  https://tools.ietf.org/html/rfc8446#section-5.2 . **/
    *error_details = gpr_strdup(kS2ARecordExceedMaxSize);
    return S2ADecryptStatus::ALERT_RECORD_OVERFLOW;
  }
  size_t expected_payload_size = (header[3] << 8) + header[4];
  if (record_header.iov_len != SSL3_RT_HEADER_LENGTH ||
      header[0] != SSL3_RT_APPLICATION_DATA ||
      header[1] != (wire_version >> 8) || header[2] != (wire_version & 0xff) ||
      payload_size != expected_payload_size) {
    *error_details = gpr_strdup(kS2AHeaderIncorrectFormat);
    return S2ADecryptStatus::INVALID_RECORD;
  }

  S2ADecryptStatus decrypt_status = s2a_decrypt_payload(
      crypter, record_header, protected_vec, protected_vec_size,
      unprotected_vec, plaintext_bytes_written, error_details);
  if (decrypt_status != S2ADecryptStatus::OK) {
    return decrypt_status;
  }

  grpc_status_code increment_status =
      increment_sequence(crypter->in_connection);
  if (increment_status != GRPC_STATUS_OK) {
    return S2ADecryptStatus::INTERNAL_ERROR;
  }

  uint8_t* plaintext = reinterpret_cast<uint8_t*>(unprotected_vec.iov_base);
  /** At this point, the |s2a_decrypt_payload| method has written
   *  |*plaintext_bytes_written| bytes to |plaintext|, and these bytes are of
   *  the form (plaintext) + (record type byte) + (trailing zeros). These
   *  trailing zeros should be ignored, so we will search from one end of the
   *  |plaintext| buffer until we find the first nonzero trailing byte, which
   *  must be the record type.
   *
   *  Note that this TLS 1.3 implementation does not add padding by zeros when
   *  constructing a TLS 1.3 record; nonetheless, |s2a_decrypt_payload| must be
   *  able to parse a TLS 1.3 record that does have padding by zeros. **/
  size_t i;
  for (i = *plaintext_bytes_written - 1; i < *plaintext_bytes_written; i--) {
    if (plaintext[i] != 0) {
      break;
    }
  }
  if (i >= *plaintext_bytes_written) {
    *error_details = gpr_strdup(kS2ARecordInvalidFormat);
    return S2ADecryptStatus::INVALID_RECORD;
  }
  uint8_t record_type = plaintext[i];
  /** The plaintext only occupies the first i bytes of the |plaintext| buffer,
   *  so |plaintext_bytes_written| must be updated accordingly. **/
  *plaintext_bytes_written = i;

  switch (record_type) {
    case SSL3_RT_ALERT:
      if (*plaintext_bytes_written < 2) {
        *error_details = gpr_strdup(kS2ARecordSmallAlert);
        return S2ADecryptStatus::INVALID_RECORD;
      }
      if (plaintext[1] == SSL3_AD_CLOSE_NOTIFY) {
        return S2ADecryptStatus::ALERT_CLOSE_NOTIFY;
      } else {
        // TODO(mattstev): add finer parsing of other alert types.
        return S2ADecryptStatus::ALERT_OTHER;
      }
    case SSL3_RT_HANDSHAKE:
      /** Check whether the plaintext is a key update message. **/
      if (*plaintext_bytes_written == 5 &&
          memcmp(plaintext, "\x18\x00\x00\x01", 4) == 0 && plaintext[4] < 2) {
        grpc_status_code key_update_status = s2a_key_update(crypter->ciphersuite, crypter->in_connection, &(crypter->in_aead_crypter), error_details);
        if (key_update_status != GRPC_STATUS_OK) {
          return S2ADecryptStatus::INTERNAL_ERROR;
        }
        return S2ADecryptStatus::OK;
      }
      *error_details = gpr_strdup(kS2ARecordInvalidFormat);
      return S2ADecryptStatus::INVALID_RECORD;
    case SSL3_RT_APPLICATION_DATA:
      /** There is nothing more to be done for an application data record. **/
      break;
    default:
      *error_details = gpr_strdup(kS2ARecordInvalidFormat);
      return S2ADecryptStatus::INVALID_RECORD;
  }
  return S2ADecryptStatus::OK;
}

S2ADecryptStatus s2a_decrypt(s2a_crypter* crypter, uint8_t* record,
                             size_t record_size, uint8_t* plaintext,
                             size_t plaintext_allocated_size,
                             size_t* plaintext_size, char** error_details) {
  GPR_ASSERT(error_details != nullptr);
  size_t max_plaintext_size;
  grpc_status_code plaintext_status = s2a_max_plaintext_size(
      *crypter, record_size, &max_plaintext_size, error_details);
  if (plaintext_status != GRPC_STATUS_OK) {
    return S2ADecryptStatus::INTERNAL_ERROR;
  }
  GPR_ASSERT(plaintext_allocated_size >= max_plaintext_size);
  if (record == nullptr && record_size > 0) {
    *error_details = gpr_strdup(kS2ARecordNullptr);
    return S2ADecryptStatus::FAILED_PRECONDITION;
  }
  iovec plaintext_vec = {reinterpret_cast<void*>(plaintext),
                         plaintext_allocated_size};
  iovec record_header = {reinterpret_cast<void*>(record),
                         SSL3_RT_HEADER_LENGTH};
  GPR_ASSERT(record_size >= SSL3_RT_HEADER_LENGTH);
  iovec payload_vec = {reinterpret_cast<void*>(record + SSL3_RT_HEADER_LENGTH),
                       record_size - SSL3_RT_HEADER_LENGTH};
  return s2a_decrypt_record(crypter, record_header, &payload_vec,
                            /* payload_vec length=*/1, plaintext_vec,
                            plaintext_size, error_details);
}
