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
  ${CMAKE_CURRENT_SOURCE_DIR}/BPSecLib_Private.h
  ${CMAKE_CURRENT_SOURCE_DIR}/BPSecLib_Public.h
  ${CMAKE_CURRENT_BINARY_DIR}/BSLConfig.h
  ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface.h
)

set(BSL_FRONT_C
  ${CMAKE_CURRENT_BINARY_DIR}/BSLConfig.c
)

add_library(bsl_front)
target_sources(bsl_front PUBLIC ${BSL_FRONT_H})
target_sources(bsl_front PUBLIC ${BSL_FRONT_C})
add_compile_options(-include ${CMAKE_CURRENT_BINARY_DIR}/BSLConfig.h)
target_compile_options(bsl_front PRIVATE -Wshadow -Wpointer-arith -Wstrict-prototypes
                       -Wmissing-prototypes -Wredundant-decls -Wcast-align
                       -Wformat=2 -Wswitch-enum -Wlogical-op -Wduplicated-branches
                       -fno-strict-aliasing -Werror=format-security -fno-common
                       -Wstrict-aliasing=2)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")

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
#target_link_libraries(bsl_front PUBLIC MLIB::mlib)

# Dynamic backend library
set(BSL_DYNAMIC_H
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/PublicInterfaceImpl.h
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/UtilDefs_SeqReadWrite.h
  ${CMAKE_CURRENT_SOURCE_DIR}/security_context/DefaultSecContext.h
  ${CMAKE_CURRENT_SOURCE_DIR}/security_context/DefaultSecContext_Private.h
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_provider/SamplePolicyProvider.h
)

set(BSL_DYNAMIC_C
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/AbsSecBlock.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/CryptoInterface.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/UtilDefs_Data.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/HostInterface.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/PublicInterfaceImpl.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/LoggingStderr.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/PolicyProvider.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecOperation.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecOutcome.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecParam.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecResult.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecurityActionSet.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecurityContext.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/SecurityResultSet.c
  ${CMAKE_CURRENT_SOURCE_DIR}/backend/UtilDefs_SeqReadWrite.c
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_provider/SamplePolicyProvider.c
  ${CMAKE_CURRENT_SOURCE_DIR}/security_context/DefaultSecContext.c
  ${CMAKE_CURRENT_SOURCE_DIR}/security_context/BCB_AES_GCM.c
  ${CMAKE_CURRENT_SOURCE_DIR}/security_context/BIB_HMAC_SHA2.c
)

add_library(bsl_dynamic)
add_compile_options(-include ${CMAKE_CURRENT_BINARY_DIR}/BSLConfig.h)
target_sources(bsl_dynamic PUBLIC ${BSL_DYNAMIC_H})
target_sources(bsl_dynamic PUBLIC ${BSL_DYNAMIC_C})
target_compile_options(bsl_dynamic PRIVATE -Wshadow -Wpointer-arith -Wstrict-prototypes
                       -Wmissing-prototypes -Wredundant-decls -Wcast-align
                       -Wformat=2 -Wswitch-enum -Wlogical-op -Wduplicated-branches
                       -fno-strict-aliasing -Werror=format-security -fno-common
                       -Wstrict-aliasing=2)
                       # -Wconversion
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
