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

#ifndef GRPC_CORE_LIB_SECURITY_SECURITY_CONNECTOR_S2A_S2A_SECURITY_CONNECTOR_H
#define GRPC_CORE_LIB_SECURITY_SECURITY_CONNECTOR_S2A_S2A_SECURITY_CONNECTOR_H

#include <grpc/support/port_platform.h>
#include "src/core/lib/security/security_connector/security_connector.h"

namespace experimental {

#define GRPC_S2A_TRANSPORT_SECURITY_TYPE "s2a"

/** This method creates an S2A channel security connector on success; otherwise,
 *  the method returns nullptr.
 *  - channel_creds: an instance of channel credentials; the caller must not
 *    pass in nullptr for this argument.
 *  - request_metadata_creds: a credential object that is sent with each
 *    request; the caller may pass in nullptr for this argument.
 *  - target_name: the name of the endpoint to which the channel connects; this
 *    data will be used for a secure naming check. **/
grpc_core::RefCountedPtr<grpc_channel_security_connector>
grpc_s2a_channel_security_connector_create(
    grpc_core::RefCountedPtr<grpc_channel_credentials> channel_creds,
    grpc_core::RefCountedPtr<grpc_call_credentials> request_metadata_creds,
    const char* target_name);

/** This method creates an S2A server security connector on success; otherwise,
 *  the method returns nullptr.
 *  - server_creds: an instance of server credentials; the caller must not
 *    pass in nullptr for this argument. **/
grpc_core::RefCountedPtr<grpc_server_security_connector>
grpc_s2a_server_security_connector_create(
    grpc_core::RefCountedPtr<grpc_server_credentials> server_creds);

}  // namespace experimental

#endif  // GRPC_CORE_LIB_SECURITY_SECURITY_CONNECTOR_S2A_S2A_SECURITY_CONNECTOR_H
