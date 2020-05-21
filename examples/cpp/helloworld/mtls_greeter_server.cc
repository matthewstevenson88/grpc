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

#include <iostream>
#include <fstream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>

#ifdef BAZEL_BUILD
#include "examples/protos/helloworld.grpc.pb.h"
#else
#include "helloworld.grpc.pb.h"
#endif

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using helloworld::HelloRequest;
using helloworld::HelloReply;
using helloworld::Greeter;

ABSL_FLAG(std::string, port, "50051", "port number to use for connection");
ABSL_FLAG(std::string, client_root_cert_pem_path, "ca.cert",
  "path to root X509 certificate");
ABSL_FLAG(std::string, server_cert_pem_path, "service.pem",
  "path to server's X509 certificate");
ABSL_FLAG(std::string, server_key_pem_path, "service.key",
  "path to server's private key");

// Logic and data behind the server's behavior.
class GreeterServiceImpl final : public Greeter::Service {
  Status SayHello(ServerContext* context, const HelloRequest* request,
                  HelloReply* reply) override {
    std::string prefix("Hello ");
    reply->set_message(prefix + request->name());
	std::cout << "Received message: " << request->name() << std::endl;
    return Status::OK;
  }
};

std::string readFile(const std::string filePath) {
  std::ifstream ifs(filePath);
  return std::string((std::istreambuf_iterator<char>(ifs)),
                     (std::istreambuf_iterator<char>()));
}

void RunServer() {
  std::string port = absl::GetFlag(FLAGS_port);
  std::string rootCertPath = absl::GetFlag(FLAGS_client_root_cert_pem_path);
  std::string serverCertPath = absl::GetFlag(FLAGS_server_cert_pem_path);
  std::string serverKeyPath = absl::GetFlag(FLAGS_server_key_pem_path);

  GreeterServiceImpl service;

  // Read keys and certs.
  std::string serverKey = readFile("service.key");
  std::string serverCert = readFile("service.pem");
  std::string rootCert = readFile("ca.cert");

  // Setup SSL credentials.
  grpc::SslServerCredentialsOptions sslOpts{};
  sslOpts.client_certificate_request =
    GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;
  sslOpts.pem_key_cert_pairs.push_back(
  grpc::SslServerCredentialsOptions::PemKeyCertPair{serverKey,
    serverCert});
  sslOpts.pem_root_certs = rootCert;
  auto creds = grpc::SslServerCredentials(sslOpts);

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();

  ServerBuilder builder;
  // Listen on the given address without any authentication mechanism.
  std::string serverAddr = "localhost:" + port;
  builder.AddListeningPort(serverAddr, creds);
  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(&service);
  // Finally assemble the server.
  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << serverAddr << std::endl;

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
}

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  RunServer();

  return 0;
}
