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
  ${CMAKE_CURRENT_SOURCE_DIR}/agent.h
  ${CMAKE_CURRENT_SOURCE_DIR}/bundle.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/eid.h
  ${CMAKE_CURRENT_SOURCE_DIR}/eidpat.h
  ${CMAKE_CURRENT_SOURCE_DIR}/encode.h
  ${CMAKE_CURRENT_SOURCE_DIR}/decode.h
  ${CMAKE_CURRENT_SOURCE_DIR}/text_util.h
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_config.h
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_params.h
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_registry.h
  ${CMAKE_CURRENT_SOURCE_DIR}/ctr.h
  ${CMAKE_CURRENT_SOURCE_DIR}/MockBPA.h
)
target_sources(
  bsl_mock_bpa PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/agent.c
  ${CMAKE_CURRENT_SOURCE_DIR}/bundle.c
  ${CMAKE_CURRENT_SOURCE_DIR}/crc.c
  ${CMAKE_CURRENT_SOURCE_DIR}/eid.c
  ${CMAKE_CURRENT_SOURCE_DIR}/eidpat.c
  ${CMAKE_CURRENT_SOURCE_DIR}/encode.c
  ${CMAKE_CURRENT_SOURCE_DIR}/decode.c
  ${CMAKE_CURRENT_SOURCE_DIR}/text_util.c
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_config.c
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_params.c
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_registry.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ctr.c
)
set_target_properties(bsl_mock_bpa
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_link_libraries(bsl_mock_bpa PUBLIC MLIB::mlib)
target_link_libraries(bsl_mock_bpa PUBLIC QCBOR::qcbor)
target_link_libraries(bsl_mock_bpa PUBLIC Jansson::Jansson)
target_link_libraries(bsl_mock_bpa PUBLIC bsl_front bsl_dynamic bsl_default_sc bsl_sample_pp)
# Installation config
install(
  TARGETS bsl_mock_bpa
  PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/bsl"
    RUNTIME
        COMPONENT test
    LIBRARY
        COMPONENT test
        NAMELINK_COMPONENT devel
    ARCHIVE
        COMPONENT devel
)

if(BUILD_MOCK_BPA AND NOT BUILD_FUZZING)
  add_executable(bsl-mock-bpa)
  target_sources(bsl-mock-bpa PRIVATE mock_bpa.c)
  target_link_libraries(bsl-mock-bpa PUBLIC bsl_mock_bpa bsl_crypto)
  target_link_libraries(bsl-mock-bpa PUBLIC Threads::Threads)

  # Installation config
  install(
    TARGETS bsl-mock-bpa
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/bsl"
      RUNTIME
          COMPONENT test
  )
endif(BUILD_MOCK_BPA AND NOT BUILD_FUZZING)
