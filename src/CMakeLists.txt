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

configure_file(BSLConfig.h.in BSLConfig.h @ONLY)
configure_file(BSLConfig.c.in BSLConfig.c @ONLY)

# Frontend library
set(BSL_FRONT_H
  ${CMAKE_CURRENT_BINARY_DIR}/BSLConfig.h
  ${CMAKE_CURRENT_SOURCE_DIR}/Data.h
  ${CMAKE_CURRENT_SOURCE_DIR}/BPSecLib_Private.h
  ${CMAKE_CURRENT_SOURCE_DIR}/BPSecLib_Public.h
  ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface.h
)

set(BSL_FRONT_C
  ${CMAKE_CURRENT_BINARY_DIR}/BSLConfig.c
  ${CMAKE_CURRENT_SOURCE_DIR}/Data.c
)

add_library(bsl_front)
target_sources(bsl_front PUBLIC ${BSL_FRONT_H})
target_sources(bsl_front PRIVATE ${BSL_FRONT_C})

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
target_link_libraries(bsl_crypto PUBLIC bsl_front)
target_link_libraries(bsl_crypto PUBLIC MLIB::mlib)
target_link_libraries(bsl_crypto INTERFACE OpenSSL::Crypto)

# Default Security Context library
set(BSL_DEFAULT_SC_H
  ${CMAKE_CURRENT_SOURCE_DIR}/security_context/DefaultSecContext.h
  ${CMAKE_CURRENT_SOURCE_DIR}/security_context/DefaultSecContext_Private.h
)

set(BSL_DEFAULT_SC_C
  ${CMAKE_CURRENT_SOURCE_DIR}/security_context/DefaultSecContext.c
  ${CMAKE_CURRENT_SOURCE_DIR}/security_context/BCB_AES_GCM.c
  ${CMAKE_CURRENT_SOURCE_DIR}/security_context/BIB_HMAC_SHA2.c
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
target_link_libraries(bsl_default_sc PUBLIC QCBOR::qcbor)

# Example Policy Provider library
set(BSL_SAMPLE_PP_H
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_provider/SamplePolicyProvider.h
)

set(BSL_SAMPLE_PP_C
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_provider/SamplePolicyProvider.c
)

add_library(bsl_sample_pp)
target_sources(bsl_sample_pp PUBLIC ${BSL_SAMPLE_PP_H})
target_sources(bsl_sample_pp PRIVATE ${BSL_SAMPLE_PP_C})
set_target_properties(bsl_sample_pp
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_link_libraries(bsl_sample_pp PUBLIC bsl_front)
target_link_libraries(bsl_sample_pp PUBLIC MLIB::mlib)

# Dynamic backend library
set(BSL_DYNAMIC_H
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/PublicInterfaceImpl.h
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/UtilDefs_SeqReadWrite.h
)

set(BSL_DYNAMIC_C
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/AbsSecBlock.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/HostInterface.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/PublicInterfaceImpl.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/LoggingStderr.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/PolicyProvider.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/TelemetryCounters.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecOperation.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecOutcome.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecParam.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecResult.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecurityAction.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecurityActionSet.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecurityContext.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecurityResultSet.c
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
target_link_libraries(bsl_dynamic PUBLIC QCBOR::qcbor)

add_subdirectory(mock_bpa)

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
    TARGETS bsl_front bsl_dynamic bsl_default_sc bsl_sample_pp bsl_crypto
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
