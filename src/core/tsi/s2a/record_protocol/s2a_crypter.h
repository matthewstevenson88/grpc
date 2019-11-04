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

#ifndef GRPC_CORE_TSI_S2A_RECORD_PROTOCOL_S2A_CRYPTER_H
#define GRPC_CORE_TSI_S2A_RECORD_PROTOCOL_S2A_CRYPTER_H

#include <grpc/grpc.h>
#include <cstdint>
#include "src/core/ext/upb-generated/src/proto/grpc/gcp/s2a.upb.h"
#include "src/core/lib/gprpp/memory.h"
#include "src/core/tsi/alts/crypt/gsec.h"
#include "src/core/tsi/grpc_shadow_boringssl.h"

#include <grpc/byte_buffer_reader.h>

#include "src/core/lib/slice/slice_internal.h"

/** The uint16_t's for the implemented TLS 1.3 ciphersuite. **/
#define TLS_AES_128_GCM_SHA256 0x009c
#define TLS_AES_256_GCM_SHA384 0x1302
#define TLS_CHACHA20_POLY1305_SHA256 0xcca8

/** The S2A record protocol interface. It provides encrypt and decrypt
 *  functionality. The interface is thread-compatible. **/
typedef struct s2a_crypter s2a_crypter;

/** This function returns the max number of bytes that |crypter| requires to
 *  create a TLS 1.3 record, beyond the size of the plaintext. If |crypter| is
 *  nullptr or was not properly initialized, then this function returns zero.
 *  - crypter: an instance of s2a_crypter. **/
size_t s2a_max_record_overhead(const s2a_crypter* crypter);

/** Assume that the S2A record protocol is using one of the above ciphersuites.
 *  The structure of a TLS 1.3 record is described below:
 *    | 5 bytes of record header | + | TLS payload |.
 *  The record header encodes the following information:
 *  - first byte: a byte that indicates the record type is "application data"
 *    (this is the case even when the record type is handshake, alert, or
 *    change_cipher_spec, in order to be compatible with previous TLS versions).
 *  - second and third bytes: the TLS version,
 *  - fourth and fifth bytes: the size of the TLS payload.
 *  For more details, see https://tools.ietf.org/html/rfc8446#section-5.2 .
 *
 *  The structure of the TLS payload is described below:
 *  | ciphertext | + | (encrypted) record type | + | authentication tag |.
 *  A description of each component of the payload is given below:
 *  - ciphertext: the text obtained by encrypting the plaintext, possibly with
 *    padding and terminated by a single, non-zero byte that encodes the record
 *    type.
 *  - (encrypted) record type: a single byte that consists of the ciphertext
 *    obtained by encrypted the record type.
 *  - authentication tag: a byte buffer that follows the ciphertext and is used
 *    to verify the authenticity of the message; it is exactly 16 bytes for
 *    all 3 supported ciphersuites. **/

/**
 *  This function writes a TLS 1.3 record to |record| of type application data,
 *  and with a payload containing the ciphertext obtained by encrypting |input|
 *  using the outgoing_aead_crypter of |crypter|. The arguments of the encrypt
 *  function are detailed below:
 *  - crypter: an instance of s2a_crypter.
 *  - plaintext: the start of the data to be placed in the TLS payload.
 *  - plaintext_size: the size (in bytes) of the data to be placed in the TLS
 *    payload; the caller must ensure that
 *      |plaintext_size| <= SSL3_RT_MAX_PLAIN_LENGTH = 16384,
 *    otherwise the method returns GRPC_STATUS_INVALID_ARGUMENT.
 *  - record: the start of the memory allocated for the TLS record; this
 *    memory is owned by the caller.
 *  - record_allocated_size: the size (in bytes) of the memory allocated for the
 *    TLS record; the caller must ensure that
 *      |record_allocated_size| >=
 *        |plaintext_size| + s2a_max_record_overhead(crypter),
 *    otherwise the method returns GRPC_STATUS_INVALID_ARGUMENT.
 *  - record_size: the size (in bytes) of the memory occupied by the TLS record
 *    after the function executes successfully; the caller must not pass in
 *    nullptr for this argument.
 *  - error_details: the error details generated when the execution of the
 *    function fails; it is legal (and expected) for the caller to have
 *    |error_details| point to a nullptr.
 *
 *  On success, the function returns GRPC_STATUS_OK; otherwise, |error_details|
 *  is populated with an error message, and it must be freed with gpr_free. **/
grpc_status_code s2a_encrypt(s2a_crypter* crypter, unsigned char* plaintext,
                             size_t plaintext_size, unsigned char* record,
                             size_t record_allocated_size, size_t* record_size,
                             char** error_details);

/** This function decrypts (in place) and verifies the TLS 1.3 record |record|
 *  using the incoming_aead_crypter of |crypter|, sets |plaintext| to the start
 *  of the verified plaintext, and sets |plaintext_size| to the size of the
 *  plaintext. The arguments of the decrypt function are detailed below:
 *  - crypter: an instance of s2a_crypter.
 *  - record: the start of the TLS record.
 *  - record_size: the size (in bytes) of the TLS record; this memory is owned
 *    by the caller.
 *  - plaintext: the start of the plaintext obtained from the TLS record; this
 *    points to a part of memory that is a part of |record| and, in particular,
 *    it is owned by the caller.
 *  - plaintext_size: the size (in btes) of the memory occupied by the
 *    plaintext after the function executes successfully; the caller must not
 *    pass in nullptr for this argument.
 *  - error_details: the error details generated when the execution of the
 *    function fails; it is legal (and expected) for the caller to set
 *    |error_details| to point to a nullptr.
 *
 *  On success, the function returns GRPC_STATUS_OK; otherwise, |error_details|
 *  is populated with an error message, and it must be freed with gpr_free. **/
grpc_status_code s2a_decrypt(s2a_crypter* crypter, unsigned char* record,
                             size_t record_size, unsigned char* plaintext,
                             size_t* plaintext_size, char** error_details);

/** This method populates an s2a_crypter instance.
 *  - tls_version: the TLS version; the s2a_crypter only supports TLS 1.3.
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
 *  - channel: an open channel to the S2A; the s2a_crypter does not take
 *    ownership of the channel.
 *  - crypter: a pointer to an s2a_crypter, which will be populated by the
 *    s2a_crypter created by the method. It is legal (and expected) to pass in
 *    nullptr as an argument.
 *  - error_details: an error message for when the creation fails. It is legal
 *    (and expected) to have |error_details| point to a nullptr; otherwise,
 *    the argument should be freed with gpr_free.
 *
 *  When creation succeeds, the method return GRPC_STATUS_OK. Otherwise,
 *  it returns an error status code and details can be found in |error_details|.
 *  If |error_details| is not nullptr, it must be freed with gpr_free. **/
grpc_status_code s2a_crypter_create(
    uint16_t tls_version, uint16_t tls_ciphersuite, uint8_t* derived_in_key,
    uint8_t* derived_out_key, size_t key_size, uint8_t* derived_in_nonce,
    uint8_t* derived_out_nocne, size_t nonce_size, grpc_channel* channel,
    s2a_crypter** crypter, char** error_details);

/** This method destroys an s2a_crypter instance, deallocating all memory.
 *  The caller must call this method after any use of s2a_crypter_create,
 *  even if s2a_crypter_create outputs a status other than GRPC_STATUS_OK.
 *  However, this method does not close (or modify in any way) the grpc_channel
 *  to the S2A.
 *  - crypter: an s2a_crypter instance created by s2a_crypter_create(). **/
void s2a_crypter_destroy(s2a_crypter* crypter);

/** These functions are exposed for testing purposes only. **/
gsec_aead_crypter* s2a_in_aead_crypter(s2a_crypter* crypter);

gsec_aead_crypter* s2a_out_aead_crypter(s2a_crypter* crypter);

void check_half_connection(s2a_crypter* crypter, bool in_half_connection,
                           uint64_t expected_sequence,
                           uint8_t expected_fixed_nonce_size,
                           uint8_t* expected_fixed_nonce,
                           uint8_t expected_additional_data_size);

/** This function writes a TLS 1.3 record to |protected_record| of type
 *  |record_type|, and with a payload containing the ciphertext obtained by
 *  encrypting |unprotected_vec| using the outgoing_aead_crypter of |crypter|.
 *  The arguments of the encrypt function are detailed below:
 *  - crypter: an instance of s2a_crypter, which must have been initialized
 *    using the s2a_crypter_create method.
 *  - record_type: a single byte that indicates the TLS record type, i.e. one
 *    of handshake, application data, alert, or change cipher spec.
 *  - unprotected_vec: a pointer to the start of an iovec array, which consists
 *    of the slices that make up the plaintext; this data is owned by the
 *    caller. The caller must ensure that the total size of the plaintext is at
 *    most SSL3_RT_MAX_PLAIN_LENGTH = 16384, otherwise the method returns
 *    GRPC_STATUS_FAILED_PRECONDITION.
 *  - unprotected_vec_size: the length of the iovec array that |unprotected_vec|
 *    points to; the caller must ensure that |unprotected_vec_size| = 0 iff
 *    unprotected_vec is nullptr.
 *  - protected_record: an iovec consisting of a pointer to the memory allocated
 *    for the TLS record and the size of the memory allocated to this record;
 *    the caller must ensure that the size allocated to the record is at least
 *        |plaintext_size| + s2a_max_record_overhead(crypter),
 *    otherwise the method returns GRPC_STATUS_FAILED_PRECONDITION.
 *  - bytes_written: the number of bytes written to |protected_record| after the
 *    function executes successfully; the caller must not pass in
 *    nullptr for this argument.
 *  - error_details: the error details generated when the execution of the
 *    function fails; it is legal (and expected) for |error_details| to point to
 *    nullptr.
 *
 *  On success, the function returns GRPC_STATUS_OK; otherwise, |error_details|
 *  is populated with an error message, and it must be freed with gpr_free. If
 *  the function returns the error code GRPC_STATUS_OUT_OF_RANGE, the caller
 *  must close the connection. **/
grpc_status_code s2a_write_tls13_record(
    s2a_crypter* crypter, uint8_t record_type, const iovec* unprotected_vec,
    size_t unprotected_vec_size, iovec protected_record, size_t* bytes_written,
    char** error_details);

#endif  //  GRPC_CORE_TSI_S2A_RECORD_PROTOCOL_S2A_CRYPTER_H
