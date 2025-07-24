#[[
Copyright (c) 2025 The Johns Hopkins University Applied Physics
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
add_library(bsl_mock_bpa)

target_compile_options(bsl_mock_bpa PRIVATE -Wshadow -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes -Wredundant-decls)

target_sources(
  bsl_mock_bpa PUBLIC 
  ${CMAKE_CURRENT_SOURCE_DIR}/bsl_mock_bpa.h
  ${CMAKE_CURRENT_SOURCE_DIR}/bsl_mock_bpa_crc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/bsl_mock_bpa_eid.h
  ${CMAKE_CURRENT_SOURCE_DIR}/bsl_mock_bpa_eidpat.h
  ${CMAKE_CURRENT_SOURCE_DIR}/bsl_mock_bpa_encode.h
  ${CMAKE_CURRENT_SOURCE_DIR}/bsl_mock_bpa_decode.h
  ${CMAKE_CURRENT_SOURCE_DIR}/bsl_mock_bpa_policy_config.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa_ctr.h
  ${CMAKE_CURRENT_SOURCE_DIR}/BPSecLib_MockBPA.h
)
target_sources(
  bsl_mock_bpa PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/bsl_mock_bpa.c
  ${CMAKE_CURRENT_SOURCE_DIR}/bsl_mock_bpa_crc.c
  ${CMAKE_CURRENT_SOURCE_DIR}/bsl_mock_bpa_eid.c
  ${CMAKE_CURRENT_SOURCE_DIR}/bsl_mock_bpa_eidpat.c
  ${CMAKE_CURRENT_SOURCE_DIR}/bsl_mock_bpa_encode.c
  ${CMAKE_CURRENT_SOURCE_DIR}/bsl_mock_bpa_decode.c
  ${CMAKE_CURRENT_SOURCE_DIR}/bsl_mock_bpa_policy_config.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa_ctr.c
)
target_include_directories(
  bsl_mock_bpa PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<INSTALL_INTERFACE:$<INSTALL_PREFIX>/include/bsl>
)
set_target_properties(bsl_mock_bpa
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_link_libraries(bsl_mock_bpa PUBLIC bsl_front QCBOR::qcbor MLIB::mlib)

add_executable(bsl-mock-bpa)
target_sources(bsl-mock-bpa PRIVATE mock_bpa.c)
target_link_libraries(bsl-mock-bpa PUBLIC bsl_mock_bpa bsl_dynamic)
target_link_libraries(bsl-mock-bpa PUBLIC Threads::Threads)

# Installation config
install(
  TARGETS bsl_mock_bpa bsl-mock-bpa
  PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/bsl"
    RUNTIME
        COMPONENT test
    LIBRARY
        COMPONENT test
        NAMELINK_COMPONENT devel
    ARCHIVE
        COMPONENT devel
)
