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

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using helloworld::Greeter;
using helloworld::HelloReply;
using helloworld::HelloRequest;

ABSL_FLAG(std::string, server_address, "localhost:50051",
          "The address of the gRPC greeter server.");
ABSL_FLAG(std::string, server_root_cert_pem_path, "ca.cert",
          "The path to the root X509 certificate.");
ABSL_FLAG(std::string, client_cert_pem_path, "client.pem",
          "The path to the client's X509 certificate.");
ABSL_FLAG(std::string, client_key_pem_path, "client.key",
          "The path to the client's private key.");

class GreeterClient {
 public:
  GreeterClient(const std::shared_ptr<Channel>& channel)
      : stub_(Greeter::NewStub(channel)) {}

  // Assembles the client's payload, sends it and presents the response back
  // from the server.
  std::string SayHello(const std::string& user) {
    HelloRequest request;
    request.set_name(user);
    HelloReply reply;
    ClientContext context;

    Status status = stub_->SayHello(&context, request, &reply);
    if (status.ok()) {
      return reply.message();
    } else {
      std::cerr << status.error_code() << ": " << status.error_message()
                << std::endl;
      return "RPC failed";
    }
  }

 private:
  std::unique_ptr<Greeter::Stub> stub_;
};

static std::string readFile(const std::string& filePath) {
  std::ifstream ifs(filePath);
  return std::string((std::istreambuf_iterator<char>(ifs)),
                     (std::istreambuf_iterator<char>()));
}

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  // Setup SSL credentials.
  grpc::SslCredentialsOptions sslOpts;
  sslOpts.pem_root_certs =
      readFile(absl::GetFlag(FLAGS_server_root_cert_pem_path));
  sslOpts.pem_private_key = readFile(absl::GetFlag(FLAGS_client_key_pem_path));
  sslOpts.pem_cert_chain = readFile(absl::GetFlag(FLAGS_client_cert_pem_path));

  GreeterClient greeter(grpc::CreateChannel(absl::GetFlag(FLAGS_server_address),
                                            grpc::SslCredentials(sslOpts)));
  std::string user("world");
  std::string reply = greeter.SayHello(user);
  std::cout << "Greeter received: " << reply << std::endl;

  if (reply != "Hello world") {
    return 1;
  }
  return 0;
}
