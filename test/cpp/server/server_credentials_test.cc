/*
 *
 * Copyright 2020 gRPC authors.
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

#include <gmock/gmock.h>
#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/security/tls_credentials_options.h>
#include <gtest/gtest.h>

#include <memory>

namespace {

TEST(ServerCredentialsTest, LoadAltsServerCredentials) {
  ::grpc_impl::experimental::AltsServerCredentialsOptions options;
  std::shared_ptr<::grpc_impl::ServerCredentials> server_credentials =
      grpc::experimental::AltsServerCredentials(options);
  EXPECT_NE(server_credentials.get(), nullptr);
}

TEST(ServerCredentialsTest, LoadLocalServerCredentials) {
  std::shared_ptr<::grpc_impl::ServerCredentials> server_credentials =
      grpc::experimental::LocalServerCredentials(LOCAL_TCP);
  EXPECT_NE(server_credentials.get(), nullptr);
}

TEST(ServerCredentialsTest, LoadSslServerCredentials) {
  grpc::SslServerCredentialsOptions options;
  std::shared_ptr<::grpc_impl::ServerCredentials> server_credentials =
      grpc::SslServerCredentials(options);
  EXPECT_NE(server_credentials.get(), nullptr);
}

TEST(ServerCredentialsTest, LoadTlsServerCredentials) {
  std::shared_ptr<grpc_impl::experimental::TlsKeyMaterialsConfig> config(
      new grpc_impl::experimental::TlsKeyMaterialsConfig());
  grpc_impl::experimental::TlsCredentialsOptions options =
      grpc_impl::experimental::TlsCredentialsOptions(
          GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_AND_VERIFY,
          GRPC_TLS_SERVER_VERIFICATION, config, nullptr, nullptr);
  std::shared_ptr<::grpc_impl::ServerCredentials> server_credentials =
      grpc::experimental::TlsServerCredentials(options);
  EXPECT_NE(server_credentials.get(), nullptr);
}

}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  int ret = RUN_ALL_TESTS();
  return ret;
}
