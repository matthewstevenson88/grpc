# Copyright 2019 The gRPC Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Test of RPCs made using S2A credentials."""

import unittest
import os
from concurrent.futures import ThreadPoolExecutor
import grpc


class _GenericHandler(grpc.GenericRpcHandler):

    def service(self, handler_call_details):
        return grpc.unary_unary_rpc_method_handler(
            lambda request, unused_context: request)


class S2ACredentialsTest(unittest.TestCase):

    def _create_server(self):
        server = grpc.server(ThreadPoolExecutor())
        server.add_generic_rpc_handlers((_GenericHandler(),))
        return server

    @unittest.skipIf(os.name == 'nt',
                     'TODO(https://github.com/grpc/grpc/issues/20078)')
    def test_s2a_connection(self):
        server_addr = 'localhost:{}'
        handshaker_service_url = 'lame'
        supported_ciphersuites = [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305]
        target_service_accounts = ['target_service_account']
        channel_creds = grpc.s2a_channel_credentials(handshaker_service_url, supported_ciphersuites, target_service_accounts)
        server_creds = grpc.local_server_credentials(handshaker_service_url, supported_ciphersuites, target_service_accounts)

        server = self._create_server()
        port = server.add_secure_port(server_addr.format(0), server_creds)
        server.start()
        with grpc.secure_channel(server_addr.format(port),
                                 channel_creds) as channel:
            self.assertEqual(b'abc',
                             channel.unary_unary('/test/method')(
                                 b'abc', wait_for_ready=True))
        server.stop(None)

if __name__ == '__main__':
    unittest.main()

