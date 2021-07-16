# Copyright 2021 gRPC authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("//bazel:grpc_build_system.bzl", "grpc_cc_test")

licenses(["notice"])  # Apache v2

grpc_cc_test(
    name = "grpc_s2a_credentials_options_test",
    srcs = ["grpc_s2a_credentials_options_test.cc"],
    external_deps = [
        "gtest",
        "s2a_core",
    ],
    language = "c++",
    uses_polling = False,
    deps = [
        "//:gpr",
        "//:grpc",
        "//:s2a_tsi",
    ],
)

grpc_cc_test(
    name = "s2a_handshaker_client_test",
    srcs = ["s2a_handshaker_client_test.cc"],
    external_deps = [
        "gtest",
        "s2a_core",
        "s2a_core_common_upb",
        "upb_lib",
    ],
    language = "c++",
    uses_polling = False,
    deps = [
        "//:gpr",
        "//:grpc",
        "//:s2a_tsi",
    ],
)

grpc_cc_test(
    name = "s2a_mock_handshake_test",
    srcs = ["s2a_mock_handshake_test.cc"],
    external_deps = [
        "gtest",
        "s2a_core",
        "s2a_core_common_upb",
        "s2a_core_s2a_upb",
        "s2a_core_test_data",
        "upb_lib",
    ],
    language = "c++",
    uses_polling = False,
    deps = [
        "//:gpr",
        "//:grpc",
        "//:s2a_tsi",
    ],
)

grpc_cc_test(
    name = "s2a_tsi_handshaker_test",
    srcs = ["s2a_tsi_handshaker_test.cc"],
    external_deps = [
        "gtest",
        "s2a_core",
        "s2a_core_test_data",
        "s2a_core_proxy_test_util",
        "upb_lib",
    ],
    language = "c++",
    uses_polling = False,
    deps = [
        "//:gpr",
        "//:grpc",
        "//:s2a_tsi",
    ],
)

grpc_cc_test(
    name = "s2a_zero_copy_grpc_protector_test",
    srcs = ["s2a_zero_copy_grpc_protector_test.cc"],
    external_deps = [
        "absl/status",
        "absl/status:statusor",
        "absl/types:variant",
        "gtest",
        "s2a_core",
        "s2a_core_test_data",
    ],
    language = "c++",
    uses_polling = False,
    deps = [
        "//:gpr",
        "//:grpc",
        "//:s2a_tsi",
    ],
)
