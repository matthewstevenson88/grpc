/*
 *
 * Copyright 2021 gRPC authors.
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

#ifndef GRPC_CORE_TSI_S2A_S2A_SECURITY_H_
#define GRPC_CORE_TSI_S2A_S2A_SECURITY_H_

#include <cstdlib>

#include <grpc/grpc_security.h>

#include "s2a/include/s2a_constants.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The constants used for the TSI peer properties. The S2A TSI peer properties
 *  are: TSI certificate type, TSI security level, and TSI S2A service account.
 * **/
constexpr char kGrpcS2ATransportSecurityType[] = "S2A";
constexpr std::size_t kTsiS2ANumOfPeerProperties = 4;
constexpr char kTsiS2ACertificateType[] = "S2A";
constexpr char kTsiS2AContext[] = "s2a_context";
constexpr char kTsiS2APeerIdentityPeerProperty[] = "peer_identity";

/** The URL of the S2A handshaker service for testing purposes. **/
constexpr char kS2AHandshakerServiceUrlForTesting[] =
    "s2a_handshaker_service_url_for_testing";

/** The main interface for the S2A credentials options. The options will contain
 *  information that will be passed from gRPC to the TSI layer, such an ordered
 *  list of supported ciphersuites or target service accounts. The S2A client
 *  (channel) and server credentials will have their own implementation of this
 *  interface. The APIs listed in this header are thread-compatible. It is used
 *  for experimental purpose for now and subject to change. **/
typedef struct grpc_s2a_credentials_options grpc_s2a_credentials_options;

/** This method creates a grpc S2A credentials options instance.
 *  It is used for experimental purpose for now and subject to change. **/
grpc_s2a_credentials_options *grpc_s2a_credentials_options_create();

/** Sets the S2A address field of |options|. It does not take
 *  ownership of |s2a_address|. Both parameters should not be NULL.
 *  It is used for experimental purposes for now and subject to change. **/
void grpc_s2a_credentials_options_set_s2a_address(
    grpc_s2a_credentials_options *options, const char *s2a_address);

/** Sets the spiffe id field of |options|. It does not take ownership of
 *  |spiffe_id|. Both parameters should not be NULL. It is used for experimental
 *  purposes for now and subject to change. **/
void grpc_s2a_credentials_options_add_local_spiffe_id(
    grpc_s2a_credentials_options *options, const char *spiffe_id);

/** Sets the hostname field of |options|. It does not take ownership of
 *  |hostname|. If the SPIFFE ID has already been set, then this method is a
 *  no-op. Both parameters should not be NULL. It is used for experimental
 *  purposes for now and subject to change. **/
void grpc_s2a_credentials_options_add_local_hostname(
    grpc_s2a_credentials_options *options, const char *hostname);

/** Add |ciphersuite| to the (ordered) list of supported ciphersuites in
 *  |options|. The |options| argument should not be NULL. It is used for
 *  experimental purposes for now and subject to change. **/
void grpc_s2a_credentials_options_add_supported_ciphersuite(
    grpc_s2a_credentials_options *options, int ciphersuite);

/** Adds |target_spiffe_id| to the list of target identities held by |options|.
 *  Both parameters should not be NULL. It is used for experimental purposes for
 *  now and subject to change. **/
void grpc_s2a_credentials_options_add_target_spiffe_id(
    grpc_s2a_credentials_options *options, const char *spiffe_id);

/** Adds |target_hostname| to the list of target identities held by |options|.
 *  Both parameters should not be NULL. It is used for experimental purposes for
 *  now and subject to change. **/
void grpc_s2a_credentials_options_add_target_hostname(
    grpc_s2a_credentials_options *options, const char *hostname);

/** This method destroys a grpc_s2a_credentials_options instance by
 *  de-allocating all of its occupied memory. It is used for experimental
 *  purpose for now and subject to change. **/
void grpc_s2a_credentials_options_destroy(
    grpc_s2a_credentials_options *options);

/** This method creates an S2A channel credential object. It is used for
 *  experimental purpose for now and subject to change. On success, it returns
 *  the created S2A channel credential object and otherwise returns nullptr. **/
grpc_channel_credentials *grpc_s2a_credentials_create(
    const grpc_s2a_credentials_options *options);

/** This method creates an S2A server credential object. It is used for
 *  experimental purpose for now and subject to change. On success, it returns
 *  the created S2A server credential object and otherwise returns nullptr. **/
grpc_server_credentials *grpc_s2a_server_credentials_create(
    const grpc_s2a_credentials_options *options);

/** S2A error messages. **/
constexpr char kS2AUnsupportedTlsVersion[] =
    "S2A does not support the desired TLS version.";
constexpr char kS2AUnsupportedCiphersuite[] =
    "S2A does not support the desired TLS ciphersuite.";
constexpr char kS2ACreateNullptr[] =
    "There is an unexpected nullptr argument to |s2a_crypter_create|.";
constexpr char kS2ACrypterEmptyHandshakerURL[] =
    "The handshaker service URL passed to |s2a_crypter_create| is empty.";
constexpr char kS2ATrafficSecretSizeMismatch[] =
    "The size of the provisioned traffic secret does not match the ciphersuite "
    "traffic secret size.";
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
constexpr char kS2AHeaderSizeMismatch[] =
    "The header size does not match the size of a TLS 1.3 record header.";
constexpr char kS2AInvalidUnprotectedVec[] =
    "Ensure |unprotected_vec| is nullptr iff |unprotected_vec_size| = 0.";
constexpr char kS2ATsiHandshakerNullptrArguments[] =
    "There is an unexpected nullptr argument to |s2a_tsi_handshaker_create|.";
constexpr char kS2ATsiHandshakerResultNullptrArguments[] =
    "There is an unexpected nullptr argument to "
    "|s2a_tsi_handshaker_result_create|.";
constexpr char kS2ATsiHandshakerResultEmpty[] =
    "The result field of |resp| is nullptr.";
constexpr char kS2ATsiHandshakerResultInvalidPeerIdentity[] =
    "The peer_identity field of |resp| is nullptr.";
constexpr char kS2ATsiHandshakerResultInvalidLocalIdentity[] =
    "The local_identity field of |resp| is nullptr.";
constexpr char kS2ATsiHandshakerResultInvalidSessionState[] =
    "The session_state field of |resp| is nullptr.";
constexpr char kS2ATsiHandshakerResultUnusedBytesNullptr[] =
    "There is an unexpected nullptr argument to "
    "|s2a_handshaker_result_get_unused_bytes|.";
constexpr char kS2ANonzeroSequenceNumber[] =
    "There is an unexpected nonzero sequence number.";
constexpr char kS2AHandshakerClientNullptrArguments[] =
    "There is an unexpected nullptr argument to "
    "|s2a_grpc_handshaker_client_create|.";
constexpr char kS2AGetSerializedStartClientFailed[] =
    "The |s2a_get_serialized_start_client| method failed.";
constexpr char kS2AGetSerializedStartServerFailed[] =
    "The |s2a_get_serialized_start_server| method failed.";
constexpr char kS2AGetSerializedNextFailed[] =
    "The |s2a_get_serialized_next| method failed.";
constexpr char kS2AMakeGrpcCallFailed[] =
    "The |make_grpc_call| member function failed.";
constexpr char kS2ARecordExceedMaxSize[] =
    "The TLS 1.3 payload exceeds the maximum size.";
constexpr char kS2AHeaderIncorrectFormat[] =
    "The TLS 1.3 record header does not have the correct format.";
constexpr char kS2ARecordInvalidFormat[] =
    "The format of the TLS 1.3 record is invalid.";
constexpr char kS2ARecordSmallAlert[] =
    "The TLS 1.3 alert record is too small.";
constexpr char kS2ARecordNullptr[] =
    "If |record| is nullptr, then |record_size| must be set to zero.";
constexpr char kS2ARecordIncomplete[] = "The TLS 1.3 record is incomplete.";
constexpr char kS2AFrameExceededMaxSize[] =
    "The frame size is larger than the maximum frame size.";
constexpr char kS2AUnprotectNullptr[] =
    "There is an unexpected nullptr argument to "
    "|s2a_zero_copy_grpc_protector_unprotect|.";
constexpr char kS2AProtectNullptr[] =
    "There is an unexpected nullptr argument to "
    "|s2a_zero_copy_grpc_protector_protect|.";
constexpr char kS2AUnexpectedBytesWritten[] =
    "There were an unexpected number of bytes written to the TLS 1.3 record.";
constexpr char kS2AProtectorCreateNullptr[] =
    "There is an unexpected nullptr argument to "
    "|s2a_zero_copy_grpc_protector_create|.";
constexpr char kS2AProtectorEmptyHandshakerURL[] =
    "The handshaker service URL passed to "
    "|s2a_zero_copy_grpc_protector_create| is empty.";
constexpr char kS2AEndOfData[] = "No more data can be received from the peer.";
constexpr char kS2ASessionTicketReceived[] =
    "Received a session ticket from the peer. It is being ignored.";
constexpr char kS2AExpectingHandshakeMessage[] =
    "Received a non-handshake message while expecting one.";

#ifdef __cplusplus
}
#endif

#endif  // GRPC_CORE_TSI_S2A_S2A_SECURITY_H_
