# Copyright 2019 gRPC authors.
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

load("//bazel:grpc_build_system.bzl", "grpc_cc_library", "grpc_cc_test", "grpc_package")

licenses(["notice"])  # Apache v2

grpc_package(name = "test/core/tsi/s2a")

grpc_cc_library(
    name = "s2a_test_util",
    srcs = [
        "s2a_test_util.cc",
        ],
    hdrs = [
        "s2a_test_util.h",
        "s2a_test_data.h",
        ],
    external_deps = [
        "libssl",
    ],
    deps = [
        "//:s2a_constants",
        "//:s2a_record_protocol",
    ],
)

grpc_cc_test(
    name = "s2a_record_protocol_test",
    srcs = ["s2a_record_protocol_test.cc"],
    external_deps = [
        "libssl",
    ],
    language = "C++",
    deps = [
        "//:s2a_constants",
        "//:s2a_record_protocol",
        ":s2a_test_util",
        "//:gpr",
        "//:grpc",
    ],
)

grpc_cc_test(
    name = "s2a_tsi_handshaker_test",
    srcs = ["s2a_tsi_handshaker_test.cc"],
    language = "C++",
    deps = [
        "//:s2a_constants",
        ":s2a_test_util",
        "//:gpr",
        "//:grpc",
        "//:tsi",
    ],
)
