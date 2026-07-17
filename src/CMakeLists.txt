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

configure_file(bsl/BSLConfig.h.in bsl/BSLConfig.h @ONLY)
configure_file(bsl/BSLConfig.c.in bsl/BSLConfig.c @ONLY)

# Frontend library
add_library(bsl_front)
target_sources(bsl_front
    PUBLIC
        FILE_SET public_headers
            TYPE HEADERS
            BASE_DIRS
                ${CMAKE_CURRENT_BINARY_DIR}
                ${CMAKE_CURRENT_SOURCE_DIR}
            FILES
                ${CMAKE_CURRENT_BINARY_DIR}/bsl/BSLConfig.h
                bsl/BPSecLib_Private.h
                bsl/BPSecLib_Public.h
                bsl/front/BSLMemory.h
                bsl/front/Data.h
                bsl/front/SeqReader.h
                bsl/front/SeqWriter.h
                bsl/front/TextUtil.h
    PRIVATE 
        bsl/BSLConfig.c
        bsl/front/Data.c
)

set_target_properties(bsl_front
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_include_directories(bsl_front PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    $<INSTALL_INTERFACE:$<INSTALL_PREFIX>/${CMAKE_INSTALL_INCLUDEDIR}>
)

# Crypto and Keystore library
add_library(bsl_crypto)
target_sources(bsl_crypto
    PUBLIC
        FILE_SET public_headers
            TYPE HEADERS
            FILES
                bsl/crypto/CryptoInterface.h
    PRIVATE
        bsl/crypto/CryptoInterface.c
)
set_target_properties(bsl_crypto
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_link_libraries(bsl_crypto PUBLIC bsl_front bsl_dynamic)
target_link_libraries(bsl_crypto PRIVATE MLIB::mlib)
target_link_libraries(bsl_crypto PRIVATE qcbor::qcbor)
target_link_libraries(bsl_crypto PRIVATE OpenSSL::Crypto)
if(TARGET valgrind::valgrind)
  find_path(VALGRIND_INCLUDE_DIR NAMES valgrind/memcheck.h)
  if(VALGRIND_INCLUDE_DIR)
    target_compile_definitions(bsl_crypto PRIVATE HAVE_VALGRIND)
    target_include_directories(bsl_crypto PRIVATE "${VALGRIND_INCLUDE_DIR}")
  endif()
endif(TARGET valgrind::valgrind)

# Default Security Context library
add_library(bsl_default_sc)
target_sources(bsl_default_sc
    PUBLIC
        FILE_SET public_headers
            TYPE HEADERS
            FILES
                bsl/default_sc/DefaultSecContext.h
                bsl/default_sc/rfc9173.h
    PRIVATE
        FILE_SET private_headers
            TYPE HEADERS
            FILES
                bsl/default_sc/DefaultSecContext_Private.h
    PRIVATE
        bsl/default_sc/DefaultSecContext.c
        bsl/default_sc/BCB_AES_GCM.c
        bsl/default_sc/BIB_HMAC_SHA2.c
)
set_target_properties(bsl_default_sc
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_link_libraries(bsl_default_sc PUBLIC bsl_front)
target_link_libraries(bsl_default_sc PRIVATE bsl_crypto)

# COSE Security Context library
add_library(bsl_cose_sc)
target_sources(bsl_cose_sc
    PUBLIC
        FILE_SET public_headers
            TYPE HEADERS
            FILES
                bsl/cose_sc/CoseContext.h
    PRIVATE
        FILE_SET private_headers
            TYPE HEADERS
            FILES
                bsl/cose_sc/CoseMsg.h
    PRIVATE
        bsl/cose_sc/CoseContext.c
        bsl/cose_sc/CoseMsg.c
)
set_target_properties(bsl_cose_sc
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_link_libraries(bsl_cose_sc PUBLIC bsl_front)
target_link_libraries(bsl_cose_sc PUBLIC bsl_dynamic) # for CBOR API
target_link_libraries(bsl_cose_sc PRIVATE bsl_crypto)
target_link_libraries(bsl_cose_sc PRIVATE MLIB::mlib)
target_link_libraries(bsl_cose_sc PRIVATE qcbor::qcbor)

# Example Policy Provider library
add_library(bsl_sample_pp)
target_sources(bsl_sample_pp
    PUBLIC
        FILE_SET public_headers
            TYPE HEADERS
            FILES
                bsl/sample_pp/PolicyParser.h
                bsl/sample_pp/SamplePolicyProvider.h
    PRIVATE
        bsl/sample_pp/PolicyParser.c
        bsl/sample_pp/SamplePolicyProvider.c
)
set_target_properties(bsl_sample_pp
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_link_libraries(bsl_sample_pp PUBLIC bsl_front bsl_dynamic)
# contexts linked-to for config options
target_link_libraries(bsl_sample_pp PRIVATE bsl_default_sc bsl_cose_sc)
target_link_libraries(bsl_sample_pp PUBLIC MLIB::mlib)
target_link_libraries(bsl_sample_pp PRIVATE Jansson::Jansson)

# Dynamic backend library
add_library(bsl_dynamic)
target_sources(bsl_dynamic
    PUBLIC
        FILE_SET public_headers
            TYPE HEADERS
            FILES
                bsl/dynamic/AbsSecBlock.h
                bsl/dynamic/CBOR.h
                bsl/dynamic/IdValPair.h
                bsl/dynamic/SecOperation.h
                bsl/dynamic/SecurityAction.h
                bsl/dynamic/SecurityActionSet.h
                bsl/dynamic/SeqReadWrite.h
    PRIVATE
        FILE_SET private_headers
            TYPE HEADERS
            FILES
                bsl/dynamic/PublicInterfaceImpl.h
    PRIVATE
        bsl/dynamic/AbsSecBlock.c
        bsl/dynamic/CBOR.c
        bsl/dynamic/HostInterface.c
        bsl/dynamic/IdValPair.c
        bsl/dynamic/PublicInterfaceImpl.c
        bsl/dynamic/PolicyProvider.c
        bsl/dynamic/SecOperation.c
        bsl/dynamic/SecurityAction.c
        bsl/dynamic/SecurityActionSet.c
        bsl/dynamic/SecurityContext.c
        bsl/dynamic/TelemetryCounters.c
        bsl/dynamic/TextUtil.c
        bsl/dynamic/SeqReadWrite.c
)
set_target_properties(bsl_dynamic
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_link_libraries(bsl_dynamic PUBLIC bsl_front)
# remaining libraries for internal BSL use, not BPA use
target_link_libraries(bsl_dynamic PUBLIC MLIB::mlib)
target_link_libraries(bsl_dynamic PUBLIC qcbor::qcbor)

add_library(bsl_mock_bpa)
target_sources(bsl_mock_bpa
    PUBLIC
        FILE_SET public_headers
            TYPE HEADERS
            FILES
                bsl/mock_bpa/agent.h
                bsl/mock_bpa/bundle.h
                bsl/mock_bpa/crc.h
                bsl/mock_bpa/ctr.h
                bsl/mock_bpa/decode.h
                bsl/mock_bpa/eid.h
                bsl/mock_bpa/eidpat.h
                bsl/mock_bpa/encode.h
                bsl/mock_bpa/key_registry.h
                bsl/mock_bpa/log.h
                bsl/mock_bpa/MockBPA.h
    PRIVATE
        bsl/mock_bpa/log.c
        bsl/mock_bpa/agent.c
        bsl/mock_bpa/bundle.c
        bsl/mock_bpa/crc.c
        bsl/mock_bpa/eid.c
        bsl/mock_bpa/eidpat.c
        bsl/mock_bpa/encode.c
        bsl/mock_bpa/decode.c
        bsl/mock_bpa/key_registry.c
        bsl/mock_bpa/ctr.c
)
set_target_properties(bsl_mock_bpa
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_link_libraries(bsl_mock_bpa PUBLIC bsl_sample_pp bsl_default_sc bsl_cose_sc)
target_link_libraries(bsl_mock_bpa PUBLIC MLIB::mlib)
target_link_libraries(bsl_mock_bpa PUBLIC qcbor::qcbor)
target_link_libraries(bsl_mock_bpa PRIVATE Jansson::Jansson)
target_link_libraries(bsl_mock_bpa PUBLIC Threads::Threads)

if(BUILD_MOCK_BPA AND NOT BUILD_FUZZING)
  add_executable(bsl-mock-bpa)
  target_sources(bsl-mock-bpa PRIVATE bsl/mock_bpa/mock_bpa.c)
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
    EXPORT ${PROJECT_NAME}Targets
        COMPONENT devel
    RUNTIME
        COMPONENT runtime
    LIBRARY
        COMPONENT runtime
        NAMELINK_COMPONENT devel
    ARCHIVE
        COMPONENT devel
    FILE_SET public_headers
        COMPONENT devel
)
