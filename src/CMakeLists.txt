#[[
Copyright (c) 2024 The Johns Hopkins University Applied Physics
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
  ${CMAKE_CURRENT_SOURCE_DIR}/Logging.h
  ${CMAKE_CURRENT_SOURCE_DIR}/UtilHelpers.h
  ${CMAKE_CURRENT_SOURCE_DIR}/DataContainers.h
  ${CMAKE_CURRENT_SOURCE_DIR}/BundleContext.h
  ${CMAKE_CURRENT_SOURCE_DIR}/LibContext.h
  ${CMAKE_CURRENT_SOURCE_DIR}/SeqReadWrite.h
  ${CMAKE_CURRENT_SOURCE_DIR}/BPSecTypes.h
  ${CMAKE_CURRENT_SOURCE_DIR}/AbsSecBlock.h
  ${CMAKE_CURRENT_SOURCE_DIR}/PolicyProvider.h
  ${CMAKE_CURRENT_SOURCE_DIR}/AdapterTypes.h
  ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface.h
)

set(BSL_FRONT_C
  ${CMAKE_CURRENT_BINARY_DIR}/BSLConfig.c
)

add_library(bsl_front)
target_sources(bsl_front PUBLIC ${BSL_FRONT_H})
target_sources(bsl_front PRIVATE ${BSL_FRONT_C})
add_compile_options(-include ${CMAKE_CURRENT_BINARY_DIR}/BSLConfig.h)
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
target_link_libraries(bsl_front PUBLIC MLIB::mlib)

# Dynamic backend library
set(BSL_DYNAMIC_H
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/DynHostBPA.h
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/DeprecatedLibContext.h
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/DynBundleContext.h
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/DynSeqReadWrite.h
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/DynCrypto.h
  ${CMAKE_CURRENT_SOURCE_DIR}/security_context/DefaultSecContext.h
  ${CMAKE_CURRENT_SOURCE_DIR}/security_context/DefaultSecContext_Private.h
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_provider/SamplePolicyProvider.h
)
set(BSL_DYNAMIC_C
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/LoggingStderr.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/BPSecTypes.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/AbsSecBlock.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/HostBPA.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/LibContext.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/BundleContext.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SeqReadWrite.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/DeprecatedPolicy.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecurityContext.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/Crypto.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/DataContainers.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/util.c
  ${CMAKE_CURRENT_SOURCE_DIR}/security_context/DefaultSecContext.c
  ${CMAKE_CURRENT_SOURCE_DIR}/security_context/DefaultSecContextBIB.c
  ${CMAKE_CURRENT_SOURCE_DIR}/security_context/DefaultSecContextBCB.c
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_provider/SamplePolicyProvider.c
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_provider/PolicyProvider_Impl.c
)

add_library(bsl_dynamic)
add_compile_options(-include ${CMAKE_CURRENT_BINARY_DIR}/BSLConfig.h)
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
target_link_libraries(bsl_dynamic PUBLIC OpenSSL::SSL)
target_link_libraries(bsl_dynamic PUBLIC Threads::Threads)


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
    TARGETS bsl_front bsl_dynamic
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
