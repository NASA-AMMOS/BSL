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

configure_file(BSLConfig.h.in BSLConfig.h @ONLY)
configure_file(BSLConfig.c.in BSLConfig.c @ONLY)

# Frontend library
add_library(bsl_front)
target_sources(bsl_front PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}/BSLConfig.h
    ${CMAKE_CURRENT_SOURCE_DIR}/BPSecLib_Private.h
    ${CMAKE_CURRENT_SOURCE_DIR}/BPSecLib_Public.h
    ${CMAKE_CURRENT_SOURCE_DIR}/Data.h
    ${CMAKE_CURRENT_SOURCE_DIR}/TextUtil.h
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface.h
)
target_sources(bsl_front PRIVATE 
    ${CMAKE_CURRENT_BINARY_DIR}/BSLConfig.c
    ${CMAKE_CURRENT_SOURCE_DIR}/Data.c
)

set_target_properties(bsl_front
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_include_directories(
  bsl_front PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
  $<INSTALL_INTERFACE:$<INSTALL_PREFIX>/include/bsl>
)

# Crypto Library
set(BSL_CRYPTO_C
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/CryptoInterface.c
)

add_library(bsl_crypto)
target_sources(bsl_crypto PRIVATE ${BSL_CRYPTO_C})
set_target_properties(bsl_crypto
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_link_libraries(bsl_crypto PUBLIC bsl_front bsl_dynamic)
target_link_libraries(bsl_crypto PRIVATE MLIB::mlib)
target_link_libraries(bsl_crypto PRIVATE OpenSSL::Crypto)
if(TARGET valgrind::valgrind)
  find_path(VALGRIND_INCLUDE_DIR NAMES valgrind/memcheck.h)
  if(VALGRIND_INCLUDE_DIR)
    target_compile_definitions(bsl_crypto PRIVATE HAVE_VALGRIND)
    target_include_directories(bsl_crypto PRIVATE "${VALGRIND_INCLUDE_DIR}")
  endif()
endif(TARGET valgrind::valgrind)

# Default Security Context library
set(BSL_DEFAULT_SC_H
  ${CMAKE_CURRENT_SOURCE_DIR}/default_sc/DefaultSecContext.h
  ${CMAKE_CURRENT_SOURCE_DIR}/default_sc/DefaultSecContext_Private.h
)

set(BSL_DEFAULT_SC_C
  ${CMAKE_CURRENT_SOURCE_DIR}/default_sc/DefaultSecContext.c
  ${CMAKE_CURRENT_SOURCE_DIR}/default_sc/BCB_AES_GCM.c
  ${CMAKE_CURRENT_SOURCE_DIR}/default_sc/BIB_HMAC_SHA2.c
)

add_library(bsl_default_sc)
target_sources(bsl_default_sc PUBLIC ${BSL_DEFAULT_SC_H})
target_sources(bsl_default_sc PRIVATE ${BSL_DEFAULT_SC_C})
set_target_properties(bsl_default_sc
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_link_libraries(bsl_default_sc PUBLIC bsl_front)
target_link_libraries(bsl_default_sc PUBLIC bsl_crypto)
target_link_libraries(bsl_default_sc PUBLIC qcbor::qcbor)

# COSE Security Context library
set(BSL_COSE_SC_H
)

add_library(bsl_cose_sc)
target_sources(bsl_cose_sc PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/cose_sc/CoseContext.h
    ${CMAKE_CURRENT_SOURCE_DIR}/cose_sc/CoseMsg.h
)
target_sources(bsl_cose_sc PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/cose_sc/CoseContext.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cose_sc/CoseMsg.c
)
set_target_properties(bsl_cose_sc
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_link_libraries(bsl_cose_sc PUBLIC bsl_front)
target_link_libraries(bsl_cose_sc PUBLIC bsl_crypto)
target_link_libraries(bsl_cose_sc PUBLIC MLIB::mlib)
target_link_libraries(bsl_cose_sc PUBLIC qcbor::qcbor)

# Example Policy Provider library
set(BSL_SAMPLE_PP_H
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_provider/SamplePolicyProvider.h
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_provider/PolicyParser.h
)

set(BSL_SAMPLE_PP_C
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_provider/SamplePolicyProvider.c
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_provider/PolicyParser.c
)

add_library(bsl_sample_pp)
target_sources(bsl_sample_pp PUBLIC ${BSL_SAMPLE_PP_H})
target_sources(bsl_sample_pp PRIVATE ${BSL_SAMPLE_PP_C})
set_target_properties(bsl_sample_pp
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_link_libraries(bsl_sample_pp PUBLIC bsl_front bsl_dynamic)
# contexts for config options
target_link_libraries(bsl_sample_pp PUBLIC bsl_default_sc bsl_cose_sc)
target_link_libraries(bsl_sample_pp PUBLIC MLIB::mlib)
target_link_libraries(bsl_sample_pp PUBLIC Jansson::Jansson)

# Dynamic backend library
set(BSL_DYNAMIC_H
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/AbsSecBlock.h
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/CBOR.h
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/IdValPair.h
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/PublicInterfaceImpl.h
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecOperation.h
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecurityResultSet.h   
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/UtilDefs_SeqReadWrite.h
)

set(BSL_DYNAMIC_C
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/AbsSecBlock.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/CBOR.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/HostInterface.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/IdValPair.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/PublicInterfaceImpl.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/PolicyProvider.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/TelemetryCounters.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecOperation.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecOutcome.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecurityAction.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecurityActionSet.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecurityContext.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecurityResultSet.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/TextUtil.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/UtilDefs_SeqReadWrite.c
)

add_library(bsl_dynamic)
target_sources(bsl_dynamic PUBLIC ${BSL_DYNAMIC_H})
target_sources(bsl_dynamic PRIVATE ${BSL_DYNAMIC_C})
set_target_properties(bsl_dynamic
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_link_libraries(bsl_dynamic PUBLIC bsl_front)
target_link_libraries(bsl_dynamic PUBLIC MLIB::mlib)
target_link_libraries(bsl_dynamic PUBLIC qcbor::qcbor)

add_library(bsl_mock_bpa)
#target_compile_options(bsl_mock_bpa PRIVATE -Wshadow -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes -Wredundant-decls)
target_sources(
  bsl_mock_bpa PUBLIC 
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/log.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/agent.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/bundle.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/crc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/eid.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/eidpat.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/encode.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/decode.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/key_registry.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/ctr.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/MockBPA.h
)
target_sources(
  bsl_mock_bpa PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/log.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/agent.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/bundle.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/crc.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/eid.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/eidpat.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/encode.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/decode.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/key_registry.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mock_bpa/ctr.c
)
set_target_properties(bsl_mock_bpa
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_link_libraries(bsl_mock_bpa PUBLIC MLIB::mlib)
target_link_libraries(bsl_mock_bpa PUBLIC qcbor::qcbor)
target_link_libraries(bsl_mock_bpa PUBLIC Jansson::Jansson)
target_link_libraries(bsl_mock_bpa PUBLIC bsl_front bsl_dynamic bsl_default_sc bsl_cose_sc bsl_sample_pp)
target_link_libraries(bsl_mock_bpa PUBLIC Threads::Threads)

if(BUILD_MOCK_BPA AND NOT BUILD_FUZZING)
  add_executable(bsl-mock-bpa)
  target_sources(bsl-mock-bpa PRIVATE mock_bpa/mock_bpa.c)
  target_link_libraries(bsl-mock-bpa PUBLIC bsl_mock_bpa bsl_crypto)

  # Installation config
  install(
      TARGETS bsl-mock-bpa
      RUNTIME
          COMPONENT test
  )
endif(BUILD_MOCK_BPA AND NOT BUILD_FUZZING)

find_program(CLANG_FORMAT "clang-format")
if(CLANG_FORMAT)
    # Define which files to format
    file(GLOB_RECURSE ALL_SOURCE_FILES 
        ${CMAKE_CURRENT_SOURCE_DIR}/**/*.c
        ${CMAKE_CURRENT_SOURCE_DIR}/**/*.h
    )

    add_custom_target(format-check
        COMMAND ${CLANG_FORMAT} --dry-run -Werror ${ALL_SOURCE_FILES}
        COMMENT "Formatting source code..."
    )
endif()

# Installation config
install(
    TARGETS
        bsl_front bsl_dynamic
        bsl_default_sc bsl_cose_sc
        bsl_crypto
        bsl_sample_pp
        bsl_mock_bpa
    RUNTIME
        COMPONENT runtime
    LIBRARY
        COMPONENT runtime
        NAMELINK_COMPONENT devel
    ARCHIVE
        COMPONENT devel
)
install(
    DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/bsl"
    COMPONENT devel
    FILE_PERMISSIONS OWNER_READ GROUP_READ WORLD_READ
    FILES_MATCHING PATTERN "*.h"
)
install(
    FILES "${CMAKE_CURRENT_BINARY_DIR}/BSLConfig.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/bsl"
    COMPONENT devel
    PERMISSIONS OWNER_READ GROUP_READ WORLD_READ
)
