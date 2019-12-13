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

std::vector<uint8_t> message_encrypted_with_padded_zeros = {'1', '2', '3',
                                                            '4', '5', '6'};

std::vector<uint8_t> aes_128_gcm_padded_zeros_record = {
    23,  3,   3,   0,   33,  242, 228, 228, 17,  172, 103, 96,  232,
    71,  38,  228, 136, 109, 116, 50,  227, 155, 52,  240, 252, 207,
    193, 244, 85,  131, 3,   198, 138, 25,  83,  92,  15,  245};
std::vector<uint8_t> aes_256_gcm_padded_zeros_record = {
    23,  3,   3,   0,   33,  36,  239, 238, 90,  241, 166, 33,  232,
    164, 209, 242, 105, 147, 14,  120, 53,  207, 221, 5,   226, 208,
    190, 197, 176, 26,  103, 222, 207, 166, 55,  44,  42,  247};
std::vector<uint8_t> chacha_poly_padded_zeros_record = {
    23, 3,   3,   0,   33,  201, 71,  255, 164, 112, 48,  67,  240,
    99, 231, 182, 160, 81,  159, 189, 9,   86,  207, 58,  124, 151,
    48, 193, 53,  151, 238, 193, 126, 199, 231, 0,   241, 64};

}  // namespace s2a_test_data

#endif  // GRPC_TEST_CORE_TSI_S2A_S2A_TEST_DATA_H
