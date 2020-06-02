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

#include <fstream>
#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "examples/protos/helloworld.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using helloworld::Greeter;
using helloworld::HelloReply;
using helloworld::HelloRequest;

ABSL_FLAG(std::string, port, "50051",
          "The port number to use for the gRPC connection.");
ABSL_FLAG(std::string, client_root_cert_pem_path, "ca.cert",
          "The path to the root X509 certificate.");
ABSL_FLAG(std::string, server_cert_pem_path, "service.pem",
          "The path to the server's X509 certificate.");
ABSL_FLAG(std::string, server_key_pem_path, "service.key",
          "The path to the server's private key.");

// Logic and data behind the server's behavior.
class GreeterServiceImpl final : public Greeter::Service {
  Status SayHello(ServerContext* context, const HelloRequest* request,
                  HelloReply* reply) override {
    if ((!reply) || (!request)) {
      return Status::CANCELLED;
    }
    std::string prefix("Hello ");
    reply->set_message(prefix + request->name());
    std::cout << "Received message: " << request->name() << std::endl;
    return Status::OK;
  }
};

static std::string readFile(const std::string& filePath) {
  std::ifstream ifs(filePath);
  return std::string((std::istreambuf_iterator<char>(ifs)),
                     (std::istreambuf_iterator<char>()));
}

void RunServer() {
  GreeterServiceImpl service;

  // Setup SSL credentials.
  grpc::SslServerCredentialsOptions sslOpts{};
  sslOpts.client_certificate_request =
      GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;
  sslOpts.pem_key_cert_pairs.push_back(
      grpc::SslServerCredentialsOptions::PemKeyCertPair{
          readFile(absl::GetFlag(FLAGS_server_key_pem_path)),
          readFile(absl::GetFlag(FLAGS_server_cert_pem_path))});
  sslOpts.pem_root_certs =
      readFile(absl::GetFlag(FLAGS_client_root_cert_pem_path));

  ServerBuilder builder;
  // Listen on the given address without any authentication mechanism.
  std::string server_address = "localhost:" + absl::GetFlag(FLAGS_port);
  builder.AddListeningPort(server_address, grpc::SslServerCredentials(sslOpts));
  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(&service);
  // Finally assemble the server.
  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << std::endl;

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
}

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  RunServer();
  return 0;
}
