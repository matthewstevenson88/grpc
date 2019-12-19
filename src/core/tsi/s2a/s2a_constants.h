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

/** The constants used for the TSI peer properties. **/
constexpr char kGrpcS2ATransportSecurityType[] = "S2A";
constexpr size_t kTsiS2ANumOfPeerProperties = 3;
constexpr char kTsiS2ACertificateType[] = "S2A";
constexpr char kTsiS2AContext[] = "s2a_context";
constexpr char kTsiS2AServiceAccountPeerProperty[] = "service_account";

/** The following constants are ciphersuite-specific data. **/
constexpr size_t kEvpAeadAesGcmTagLength = 16;
constexpr size_t kEvpAeadMaxKeyLength = 80;
constexpr size_t kEvpAeadMaxNonceLength = 24;
constexpr size_t kPoly1305TagLength = 16;
constexpr size_t kSha256DigestLength = 32;
constexpr size_t kSha384DigestLength = 48;

/** The uint16_t's for the supported TLS 1.3 ciphersuites. The values are
 *  specified here: https://tools.ietf.org/html/rfc8446#appendix-B.4. **/
constexpr uint16_t kTlsAes128GcmSha256 = 0x1301;
constexpr uint16_t kTlsAes256GcmSha384 = 0x1302;
constexpr uint16_t kTlsChacha20Poly1305Sha256 = 0x1303;

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
constexpr size_t kTlsAdditionalDataBytesSize = 5;

/** The initial size (in bytes) of the buffer owned by an S2A handshaker client.
 * **/
constexpr size_t kS2AInitialBufferSize = 256;

/** The extension for the interaction with the S2A service. **/
constexpr char kS2AServiceMethod[] = "/s2a.S2AService/SetUpSession";

/** The application protocol used by S2A. **/
constexpr char kS2AApplicationProtocol[] = "grpc";

/** The size (in bytes) of the sequence buffer used for parsing TLS 1.3 records.
 * **/
constexpr size_t kTlsSequenceSize = 8;

/** The maximum size of a frame expected by the S2A frame protector. **/
constexpr size_t kS2AMaxFrameSize =
    /*record_header=*/5 + /*max_plaintext_size=*/16 * 1024 + /*tag=*/16;

/** The URL of the S2A handshaker service for testing purposes. **/
constexpr char kS2AHandshakerServiceUrlForTesting[] = "testing";

/** S2A error messages. **/
constexpr char kS2AUnsupportedTlsVersion[] =
    "S2A does not support the desired TLS version.";
constexpr char kS2AUnsupportedCiphersuite[] =
    "S2A does not support the desired TLS ciphersuite.";
constexpr char kS2ACreateNullptr[] =
    "There is an unexpected nullptr argument to |s2a_crypter_create|.";
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
constexpr char kS2ATsiHandshakerResultInvalidSessionState[] =
    "The session_state field of |resp| is nullptr.";
constexpr char kS2ATsiHandshakerResultUnusedBytesNullptr[] =
    "There is an unexpected nullptr argument to "
    "|s2a_handshaker_result_get_unused_bytes|.";
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

#endif  // GRPC_CORE_TSI_S2A_S2A_CONSTANTS_H
