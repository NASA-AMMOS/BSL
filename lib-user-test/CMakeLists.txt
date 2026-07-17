#[[
Copyright (c) 2025-2026 The Johns Hopkins University Applied Physics
Laboratory LLC.

This file is part of the Bundle Protocol Security Library (BSL).

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This work was performed for the Jet Propulsion Laboratory, California
Institute of Technology, sponsored by the United States Government under
the prime contract 80NM0018D0004 between the Caltech and NASA under
subcontract 1700763.
]]
cmake_minimum_required(VERSION 3.23)
# may not be needed for system install, but add anyway
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/../testroot/${CMAKE_ROOT}/Modules")

project(lib-user-test LANGUAGES C)

find_package(bsl REQUIRED)
message(STATUS "Found BSL ${bsl_VERSION}")
find_package(MLIB REQUIRED)
find_package(qcbor REQUIRED)

add_executable(example)
target_sources(example PRIVATE main.c)
target_link_libraries(example PUBLIC bsl::bsl_sample_pp bsl::bsl_dynamic)
