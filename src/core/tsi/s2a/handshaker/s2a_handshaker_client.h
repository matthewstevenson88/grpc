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

#ifndef GRPC_CORE_TSI_S2A_HANDSHAKER_S2A_HANDSHAKER_CLIENT_H
#define GRPC_CORE_TSI_S2A_HANDSHAKER_S2A_HANDSHAKER_CLIENT_H

#include <grpc/support/port_platform.h>

#include <grpc/byte_buffer.h>
#include <grpc/byte_buffer_reader.h>
#include <grpc/grpc.h>

#include "src/core/lib/iomgr/closure.h"
#include "src/core/lib/iomgr/pollset_set.h"
#include "src/core/lib/security/credentials/s2a/grpc_s2a_credentials_options.h"
#include "src/core/tsi/transport_security_interface.h"

using ::experimental::grpc_s2a_credentials_options;

namespace grpc_core {
namespace experimental {

struct s2a_tsi_handshaker;

/** A function that makes a gRPC call to the S2A. The default caller option
 *  is the grpc_call_start_batch_and_execute caller. **/
typedef grpc_call_error (*s2a_grpc_caller)(grpc_call* call, const grpc_op* ops,
                                           size_t nops, grpc_closure* tag);

/** The following 3 functions are used for testing purposes only. **/
typedef tsi_result (*s2a_mock_client_start)(void* client);
typedef tsi_result (*s2a_mock_server_start)(void* client, grpc_slice* bytes_received);
typedef tsi_result (*s2a_mock_next)(void* client, grpc_slice* bytes_received);

/** A struct that stores the handshake result sent by the S2A service. **/
struct s2a_recv_message_result {
  tsi_result status;
  const uint8_t* bytes_to_send;
  size_t bytes_to_send_size;
  tsi_handshaker_result* result;
};

/** The Secure Session Agent (S2A) handshaker client interface. It facilitates
 *  establishing a secure channel with the peer by interacting with the
 *  S2A's handshaker service. More precisely, it schedules
 *  a handshaker request that could be one of client_start, server_start,
 *  and next handshaker requests. The interface and all API's are
 *  thread-compatible. **/
class S2AHandshakerClient {
 public:
  /** A caller should employ the API's |s2a_handshaker_client_create| and
   *  |s2a_handshaker_client_destroy| rather than the constructor and destructor
   *  of this class. See the comments above for these API's for details on the
   *  arguments. **/
  S2AHandshakerClient(s2a_tsi_handshaker* handshaker, grpc_channel* channel,
                      grpc_pollset_set* interested_parties,
                      const grpc_s2a_credentials_options* options,
                      const grpc_slice& target_name, grpc_iomgr_cb_func grpc_cb,
                      tsi_handshaker_on_next_done_cb cb, void* user_data,
                      bool is_client, bool is_test);

  ~S2AHandshakerClient();

  /** This method schedules a client_start handshaker request with the S2A's
   *  handshaker service. It returns TSI_OK on success and an error code on
   *  failure. More precisely, the request has the following data:
   *  - |application_protocol| is set to |kS2AApplicationProtocol|.
   *  - |tls_versions| is a length-1 list { TLS 1.3 }.
   *  - |tls_ciphersuites| is the ordered list of ciphersuites specified by
   *    |options_->SupportedCiphersuites()|.
   *  - |target_identities| is the ordered list of target service accounts with
   *    SPIFFE ID's specified by |options_->TargetServiceAccountList()|.
   *  - |target_name| is set to |target_name_|. **/
  tsi_result ClientStart();

  /** This method schedules a server_start handshaker request with the S2A's
   *  handshaker service. It returns TSI_OK on success and an error code on
   *  failure.
   *  - bytes_received: the bytes from the out_bytes field of the message
   *    received from the peer; the caller must ensure that this argument is not
   *    nullptr.
   *  More precisely, the request has the following data:
   *  - |application_protocol| is set to |kS2AApplicationProtocol|.
   *  - |tls_versions| is a length-1 list { TLS 1.3 }.
   *  - |tls_ciphersuites| is the ordered list of ciphersuites specified by
   *    |options_->SupportedCiphersuites()|.
   *  - |in_bytes| is set to |bytes_received|. **/
  tsi_result ServerStart(grpc_slice* bytes_received);

  /** This method schedules a next handshaker request with the S2A's handshaker
   *  service. It returns TSI_OK on success and an error code on failure.
   *  - bytes_received: the bytes from the out_bytes field of the SessionResp
   *    message that the client peer received from its S2A; the caller must
   *    ensure that this argument is not nullptr.
   *  More precisely, the request has the following data:
   *  - |in_bytes| is set to |bytes_received|. **/
  tsi_result Next(grpc_slice* bytes_received);

  /** This method cancels previously scheduled, but not yet executed, handshaker
   *  requests to the S2A's handshaker service. After this operation completes,
   *  no further handshaker requests will be scheduled with the S2A. **/
  void Shutdown();

  /** This method parses a response from the S2A service. **/
  void HandleResponse(bool is_ok);

  /** If this handshaker client has the final result of the handshake or if an
   *  error has occurred, then:
   *  - if |receive_status_finished| is true, then this method invokes |cb_|;
   *  - if |receive_status_finished| is false, then this method does nothing.
   *  On the other hand, if the final result of the handshake has not yet been
   *  received and no error has occured, then this method invokes |cb_|. **/
  void MaybeCompleteTsiNext(
      bool receive_status_finished,
      s2a_recv_message_result* pending_recv_message_result);

  /** When the refcount (given by |refs_|) of this S2A handshaker client
   *  instance is positive, this method dereferences all of the data owned by
   *  this S2A handshaker client instance. Otherwise, this method does
   *  nothing. **/
  void Unref();

  /** These methods are exposed for use in the |on_status_received| callback
   *  function. **/
  grpc_status_code handshake_status_code() { return handshake_status_code_; }
  const grpc_slice handshake_status_details() {
    return handshake_status_details_;
  }

  /** These methods are exposed for testing purposes only. If |is_test_| is set
   *  to true, then the method accesses the appropriate private member variable.
   *  If |is_test_| is set to false, then:
   *  - if the method has a void return type, then the method does nothing;
   *  - if the method returns a pointer, then the method does nothing and
   *    returns nullptr. **/
  void set_grpc_caller_for_testing(s2a_grpc_caller caller);
  grpc_metadata_array* initial_metadata_for_testing();
  grpc_byte_buffer** recv_buffer_addr_for_testing();
  grpc_byte_buffer* send_buffer_for_testing();
  grpc_closure* closure_for_testing();
  void on_status_received_for_testing(grpc_status_code status,
                                      grpc_error* error);
  void ref_for_testing();

  /** If |is_test_| is set to true, then this method populates the private
   *  member fields of this handshaker client instance usnig the arguments. If
   *  |is_test_| is false, then this method does nothing. **/
  void SetFieldsForTesting(s2a_tsi_handshaker* handshaker,
                           tsi_handshaker_on_next_done_cb cb, void* user_data,
                           grpc_byte_buffer* recv_buffer,
                           grpc_status_code status);

  void set_mock_client_start_for_testing(s2a_mock_client_start client_start);
  void set_mock_server_start_for_testing(s2a_mock_server_start server_start);
  void set_mock_next_for_testing(s2a_mock_next next);

 protected:
  /** If |is_test_| is set to true, then this method verifies that the arguments
   *  match the corresponding private member fields of this handshaker client
   *  instance. If |is_test_| is false, then this method does nothing. **/
  void CheckFieldsForTesting(tsi_handshaker_on_next_done_cb cb, void* user_data,
                             bool has_sent_start_message,
                             grpc_slice* recv_bytes);

  /** These methods are exposed for testing purposes only. If |is_test_| is set
   *  to true, then the method accesses the appropriate private member variable.
   *  If |is_test_| is set to false, then:
   *  - if the method has a void return type, then the method does nothing;
   *  - if the method has a boolean return type, then the method returns false;
   *  - if the method returns a pointer, then the method does nothing and
   *    returns nullptr. **/
  s2a_tsi_handshaker* handshaker_for_testing();
  bool is_client_for_testing();
  void set_cb_for_testing(tsi_handshaker_on_next_done_cb cb);
  /** The caller must not pass in nullptr for |recv_bytes|. **/
  void set_recv_bytes_for_testing(grpc_slice* recv_bytes);

 private:
  /** This method makes a call to the S2A service. **/
  tsi_result MakeGrpcCall(bool is_start);

  /** This method makes a call to the S2A service, and logs any errors that
   *  occur. **/
  tsi_result MakeGrpcCallUtil(bool is_start);

  /** This method populates a |s2a_recv_message_result| instance using the
   *  arguments to the method, and passes this instance to the
   *  |MaybeCompleteTsiNext| method. This method should be called whenever
   *  the |HandleResponse| method is ready to return. **/
  void HandleResponseDone(tsi_result status, const uint8_t* bytes_to_send,
                          size_t bytes_to_send_size,
                          tsi_handshaker_result* result);

  /** This method prepares a serialized version of a client start message. **/
  grpc_byte_buffer* SerializedStartClient();

  /** This method prepares a serialized version of a server start message. The
   *  caller must ensure that |bytes_received| is not nullptr. **/
  grpc_byte_buffer* SerializedStartServer(grpc_slice* bytes_received);

  /** This method prepares a serialized version of a next message. The caller
   *  must ensure that |bytes_received| is not nullptr. **/
  grpc_byte_buffer* SerializedNext(grpc_slice* bytes_received);

  /** One ref is held by the entity that created this handshaker_client, and
   *  another ref is held by the pending RECEIVE_STATUS_ON_CLIENT op. **/
  gpr_refcount* refs_ = nullptr;
  /** The S2A TSI handshaker that instantiates this S2A handshaker client. **/
  s2a_tsi_handshaker* handshaker_ = nullptr;
  grpc_channel* channel_ = nullptr;
  grpc_call* call_ = nullptr;
  s2a_grpc_caller grpc_caller_ = nullptr;
  /** A gRPC closure to be scheduled when the response from handshaker service
   *  is received. It will be initialized with the injected grpc RPC callback.
   **/
  grpc_closure on_handshaker_service_resp_recv_;
  /** Buffers containing information to be sent (or received) to (or from) the
   *  handshaker service. **/
  grpc_byte_buffer* send_buffer_ = nullptr;
  grpc_byte_buffer* recv_buffer_ = nullptr;
  /** This status indicates to the |handle_response_done| method whether or not
   *  an error occurred during a previous portion of the handshake. **/
  grpc_status_code status_ = GRPC_STATUS_OK;
  /** Initial metadata to be received from handshaker service. **/
  grpc_metadata_array recv_initial_metadata_;
  /** A callback function provided by an application to be invoked when response
   *  is received from handshaker service. **/
  tsi_handshaker_on_next_done_cb cb_ = nullptr;
  void* user_data_ = nullptr;
  /** The S2A credential options passed in from the caller. **/
  const grpc_s2a_credentials_options* options_;
  /** The target name information to be passed to handshaker service for server
   *  authorization check. **/
  grpc_slice target_name_;
  /** A boolean flag indicating if the handshaker client is used at client or
   *  the server side. **/
  bool is_client_;
  /** A temporary store for data received from handshaker service used to
   *  extract unused data. **/
  grpc_slice recv_bytes_;
  /** A buffer containing data to be sent to the grpc client or server's peer.
   * **/
  uint8_t* buffer_;
  size_t buffer_size_;
  /** A callback for receiving handshake call status. **/
  grpc_closure on_status_received_;
  /** A gRPC status code of handshake call. **/
  grpc_status_code handshake_status_code_;
  /** A gRPC status details of handshake call. **/
  grpc_slice handshake_status_details_;
  /** The mutex |mu_| synchronizes all fields below including their internal
   *  fields. **/
  gpr_mu mu_;
  /** This status indicates whether the handshaker call's RECV_STATUS_ON_CLIENT
   *  op is done. **/
  bool receive_status_finished_ = false;
  /** If this field is not nullptr, then it contains arguments needed to
   *  complete a TSI next callback. **/
  s2a_recv_message_result* pending_recv_message_result_ = nullptr;
  /** This variable should be set to true iff the S2A handshaker client instance
   *  is instantiated as part of a test. **/
  bool is_test_ = false;
  /** The 3 functions pointers below are used to call the handshake operations
   *  implemented by a mock handshaker client. **/
  s2a_mock_client_start client_start_ = nullptr;
  s2a_mock_server_start server_start_ = nullptr;
  s2a_mock_next next_ = nullptr;
};

/** This method populates |client| with an instance of the
 *  S2AHandshakerClient, which is configured using the other arguments. The
 *  additional arguments are specified below.
 *  - handshaker: the s2a_tsi_handshaker that owns |client|.
 *  - channel: the gRPC channel used to connect with the S2A.
 *  - handshaker_service_url: the address of the S2A handshaker service; it
 *    follows the format "host:port".
 *  - interested_parties: the set of pollsets that are interested in this gRPC
 *    connection.
 *  - options: S2A-specific options used to configure the s2a_handshaker_client.
 *    This method does not take ownership of |options|, and the caller must
 *    ensure that |options| survives as long as |client|.
 *  - target_name: the name of the endpoint to which the channel connects; this
 *    data will be used for a secure naming check.
 *  - grpc_cb: a gRPC-provided callback function that is owned by |handshaker|.
 *  - cb: a callback function to be called when the tsi_handshaker_next API
 *    completes.
 *  - user_data: the argument passed to |cb|.
 *  - is_client: a boolean that is true if |client| is used at the client side,
 *    and false if |client| is used at the server side.
 *  - is_test: a boolean that is true if |client| is instantiated as part of a
 *    test.
 *  - client: a pointer to the address of an s2a_handshaker_client instance,
 *    which will be populated by the method. It is legal (and expected) for
 *    |client| to point to a nullptr.
 *
 *  On success, this method returns TSI_OK, and an error code otherwise. **/
tsi_result S2AHandshakerClientCreate(
    s2a_tsi_handshaker* handshaker, grpc_channel* channel,
    grpc_pollset_set* interested_parties,
    const grpc_s2a_credentials_options* options, const grpc_slice& target_name,
    grpc_iomgr_cb_func grpc_cb, tsi_handshaker_on_next_done_cb cb,
    void* user_data, bool is_client, bool is_test,
    S2AHandshakerClient** client);

/** This method destroys a S2AHandshakerClient instance. The caller must call
 *  this method after any use of S2AHandshakerClientCreate, even if it outputs
 *  a status other thand TSI_OK.  **/
void S2AHandshakerClientDestroy(S2AHandshakerClient* client);

/** This method is exposed for testing purposes only. **/
void s2a_handshaker_client_on_status_received_for_testing(
    S2AHandshakerClient* client, grpc_status_code status, grpc_error* error);

}  // namespace experimental
}  // namespace grpc_core

#endif  // GRPC_CORE_TSI_S2A_HANDSHAKER_S2A_HANDSHAKER_CLIENT_H
