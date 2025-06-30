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
cmake_minimum_required(VERSION 3.10)

option(RTEMS_BSP "Board Support Package for RTEMS" OFF)
option(BUILD_LIB "Build the library itself" ON)
option(BUILD_SHARED_LIBS "Build using shared libraries" ON)
option(BUILD_DOCS_API "Enable API documentation building" OFF)
option(BUILD_DOCS_MAN "Enable manpage building" OFF)
option(BUILD_TESTING "Enable building unit tests" OFF)
option(TEST_MEMCHECK "Enable test runtime memory checking" OFF)
option(TEST_COVERAGE "Enable test runtime coverage logging" OFF)
option(BUILD_PACKAGE "Enable building package outputs" OFF)


# Use RTEMS platform downloaded from
# https://raw.githubusercontent.com/nasa/PSP/main/cmake/Modules/Platform/RTEMS.cmake
# Along with CMake option -DCMAKE_TOOLCHAIN_FILE=TC-RTEMS.cmake
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Ingest the git tag as project version name
find_package(Git)
execute_process(
    COMMAND ${GIT_EXECUTABLE} describe --tags --long --dirty
    RESULT_VARIABLE GIT_TAG_EXIT
    OUTPUT_VARIABLE GIT_TAG_REV
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT GIT_TAG_EXIT EQUAL 0)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --always --dirty
        OUTPUT_VARIABLE GIT_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(GIT_TAG_REV "v0.0.0-0-g${GIT_COMMIT}")
    message(WARNING "No git tag found, marking as ${GIT_TAG_REV}")
endif()
# Make version compatible with CMake and RPM needs
STRING(REGEX REPLACE [[^v([0-9]+\.[0-9]+\.[0-9]+).*]] [[\1]] GIT_TAG_VERS ${GIT_TAG_REV})
STRING(REGEX REPLACE [[^v[0-9\.]*-(.+)]] [[\1]] GIT_TAG_MOD ${GIT_TAG_REV})
STRING(REPLACE "-" "." GIT_TAG_MOD ${GIT_TAG_MOD})
message(STATUS "Using version marking ${GIT_TAG_VERS} - ${GIT_TAG_MOD}")

project(bsl
    LANGUAGES C
    VERSION ${GIT_TAG_VERS}
)

# Language options
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
# Force specific POSIX compatibility version
add_definitions(
  -D_XOPEN_SOURCE
  -D_POSIX_C_SOURCE=200809L
)
# Generic warn/error options
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Werror
)
# LEON safe options
add_compile_options(
    -ffunction-sections
    -fdata-sections
    -fno-omit-frame-pointer
    $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-enforce-eh-specs>
    $<$<COMPILE_LANGUAGE:CXX>:-fnothrow-opt>
)
if(CMAKE_C_COMPILER_ID MATCHES "GNU")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")
elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -gdwarf-4")
endif()


# Force specific POSIX compatibility version
add_definitions(
  "-D_POSIX_C_SOURCE=200809L"
)

if(BUILD_LIB)
    find_package(MLIB REQUIRED)
    find_package(QCBOR REQUIRED)
    find_package(OpenSSL REQUIRED)
    find_package(Threads REQUIRED)
endif(BUILD_LIB)

include(CheckSymbolExists)
set(CMAKE_REQUIRED_DEFINITIONS "-D_POSIX_C_SOURCE=200809L")
check_symbol_exists(timespec_get "time.h" HAVE_TIMESPEC_GET)
check_symbol_exists(clock_gettime "time.h" HAVE_CLOCK_GETTIME)

include(CheckTypeSize)
check_type_size("int" SIZE_INT LANGUAGE C)
check_type_size("size_t" SIZE_SIZET LANGUAGE C)

add_compile_options(-include ${CMAKE_CURRENT_BINARY_DIR}/src/BSLConfig.h)

if(BUILD_TESTING)
  if(TEST_MEMCHECK)
    find_program(MEMCHECK_CMD valgrind)
    message(STATUS "Using valgrind memcheck for tests: ${MEMCHECK_CMD}")
    set(MEMCHECK_OPTIONS
      "--tool=memcheck"
      "--trace-children=yes"
      "--track-origins=yes"
      "--leak-check=full" "--show-leak-kinds=all"
      "--suppressions=${CMAKE_CURRENT_SOURCE_DIR}/memcheck.supp"
      "--error-exitcode=2"
    )
    # Arguments as list into global scope for Findunitytools.cmake
    set(TEST_EXEC_PREFIX "${MEMCHECK_CMD}" ${MEMCHECK_OPTIONS})
  endif(TEST_MEMCHECK)
  if(TEST_COVERAGE)
    include(CodeCoverage)
    append_coverage_compiler_flags()

    set(COVERAGE_EXCLUDES
      "${CMAKE_CURRENT_SOURCE_DIR}/deps/*"
      "${CMAKE_CURRENT_SOURCE_DIR}/testroot/*"
      "${CMAKE_CURRENT_BINARY_DIR}/test/*"
    )
    set(GCOVR_ADDITIONAL_ARGS
    )
    setup_target_for_coverage_gcovr_xml(
      NAME coverage-xml
      BASE_DIRECTORY "${PROJECT_SOURCE_DIR}"
    )
    setup_target_for_coverage_gcovr_html(
      NAME coverage-html
      BASE_DIRECTORY "${PROJECT_SOURCE_DIR}"
    )
  endif(TEST_COVERAGE)

  include(CTest)
  set(CMAKE_CTEST_ARGUMENTS
    --output-junit testresults.xml
    --output-on-failure
  )
endif(BUILD_TESTING)

# Install config used by tall targets
include(GNUInstallDirs)

if(BUILD_LIB)
    add_subdirectory(src)
endif(BUILD_LIB)
if(BUILD_TESTING)
    message(STATUS "Building tests")
    set(TEST_INSTALL_PREFIX "${CMAKE_INSTALL_LIBEXECDIR}/${PROJECT_NAME}")
    add_subdirectory(test)
endif(BUILD_TESTING)
add_subdirectory(docs)

if(BUILD_PACKAGE)
    # Source packaging as tarball build with target package_source
    set(CPACK_SOURCE_GENERATOR "TGZ")
    set(CPACK_SOURCE_IGNORE_FILES
        \\.git/
        \\.pytest_cache/
        __pycache__/
        build/
        testroot/
        ".*~$"
    )
    set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${CMAKE_PROJECT_VERSION}")
    set(CPACK_VERBATIM_VARIABLES YES)
    include(CPack)

    add_subdirectory(pkg)
endif(BUILD_PACKAGE)


if(RTEMS_BSP)
    set(GRMON_CONFIG "${CMAKE_CURRENT_SOURCE_DIR}/grmon-ut700.cfg")
    set(GRMON_RUN_IN "${CMAKE_CURRENT_SOURCE_DIR}/grmon-run.cfg.in")
    set(GRMON_RUN "${CMAKE_CURRENT_BINARY_DIR}/grmon-run.cfg")
#    file(GENERATE OUTPUT ${GRMON_RUN} INPUT ${GRMON_RUN_IN})
#    add_custom_target(run
#      DEPENDS main ${GRMON_CONFIG} ${GRMON_RUN}
#      COMMAND ${GRMON_BIN} -xilusb -jtagdevice 1 -nb -c ${GRMON_CONFIG} -c ${GRMON_RUN} -gdb 2223 -u
#      USES_TERMINAL
#    )

    set(GRMON_TEST_IN "${CMAKE_CURRENT_SOURCE_DIR}/grmon-test.cfg.in")
    set(GRMON_TEST "${CMAKE_CURRENT_BINARY_DIR}/grmon-test.cfg")
#    file(GENERATE OUTPUT ${GRMON_TEST} INPUT ${GRMON_TEST_IN})
#    add_custom_target(check
#      DEPENDS test_bsl ${GRMON_CONFIG} ${GRMON_TEST}
#      COMMAND ${GRMON_BIN} -xilusb -jtagdevice 1 -nb -c ${GRMON_CONFIG} -c ${GRMON_TEST} -gdb 2223 -u
#      USES_TERMINAL
#    )

    find_program(GDB_BIN
      sparc-gaisler-rtems5-gdb
      REQUIRED
      PATHS "${RTEMS_TOOLS_PREFIX}/bin/"
    )
    set(GDB_CMDS "${CMAKE_CURRENT_SOURCE_DIR}/gdb-connect.txt")
#    add_custom_target(gdb
#      DEPENDS main ${GDB_CMDS}
#      COMMAND ${GDB_BIN} $<TARGET_FILE:main> -x ${GDB_CMDS}
#      USES_TERMINAL
#    )
endif(RTEMS_BSP)
