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

#ifndef GRPC_TEST_CORE_TSI_S2A_S2A_TEST_DATA_H
#define GRPC_TEST_CORE_TSI_S2A_S2A_TEST_DATA_H

#include <cstdint>
#include <vector>

namespace s2a_test_data {

std::vector<uint8_t> key_update_message = {24, 0, 0, 1, 0};

std::vector<uint8_t> test_message_1 = {};

std::vector<uint8_t> test_message_2 = {8};

std::vector<uint8_t> test_message_3 = {46,  98, 101, 255, 213, 156, 15,  100,
                                       126, 45, 130, 239, 209, 13,  156, 89};

std::vector<uint8_t> test_message_4(1500, 'm');

std::vector<uint8_t> test_message_5(16384, 's');

}  // namespace s2a_test_data

#endif  // GRPC_TEST_CORE_TSI_S2A_S2A_TEST_DATA_H
