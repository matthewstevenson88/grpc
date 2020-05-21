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

#ifdef BAZEL_BUILD
#include "examples/protos/helloworld.grpc.pb.h"
#else
#include "helloworld.grpc.pb.h"
#endif

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using helloworld::HelloRequest;
using helloworld::HelloReply;
using helloworld::Greeter;

ABSL_FLAG(std::string, server_address, "localhost:50051",
  "address of the server");
ABSL_FLAG(std::string, server_root_cert_pem_path, "ca.cert",
  "path to root X509 certificate");
ABSL_FLAG(std::string, client_cert_pem_path, "client.pem",
  "path to client's X509 certificate");
ABSL_FLAG(std::string, client_key_pem_path, "client.key",
  "path to client's private key");

class GreeterClient {
 public:
  GreeterClient(std::shared_ptr<Channel> channel)
      : stub_(Greeter::NewStub(channel)) {}

  // Assembles the client's payload, sends it and presents the response back
  // from the server.
  std::string SayHello(const std::string& user) {
    // Data we are sending to the server.
    HelloRequest request;
    request.set_name(user);

    // Container for the data we expect from the server.
    HelloReply reply;

    // Context for the client. It could be used to convey extra information to
    // the server and/or tweak certain RPC behaviors.
    ClientContext context;

    // The actual RPC.
    Status status = stub_->SayHello(&context, request, &reply);

    // Act upon its status.
    if (status.ok()) {
      return reply.message();
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return "RPC failed";
    }
  }

 private:
  std::unique_ptr<Greeter::Stub> stub_;
};

std::string readFile(const std::string& filePath) {
  std::ifstream ifs(filePath);
  return std::string((std::istreambuf_iterator<char>(ifs)),
                     (std::istreambuf_iterator<char>()));
}

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  std::string serverAddr = absl::GetFlag(FLAGS_server_address);
  std::string rootCertPath = absl::GetFlag(FLAGS_server_root_cert_pem_path);
  std::string clientCertPath = absl::GetFlag(FLAGS_client_cert_pem_path);
  std::string clientKeyPath = absl::GetFlag(FLAGS_client_key_pem_path);

  // Read keys and certs.
  std::string rootCert = readFile(rootCertPath);
  std::string clientCert = readFile(clientCertPath);
  std::string clientKey = readFile(clientKeyPath);

  // Setup SSL credentials.
  grpc::SslCredentialsOptions sslOpts;
  sslOpts.pem_root_certs = rootCert;
  sslOpts.pem_private_key = clientKey;
  sslOpts.pem_cert_chain = clientCert;
  auto creds = grpc::SslCredentials(sslOpts);

  GreeterClient greeter(grpc::CreateChannel(
    serverAddr, creds));
  std::string user("world");
  std::string reply = greeter.SayHello(user);
  std::cout << "Greeter received: " << reply << std::endl;

  return 0;
}
