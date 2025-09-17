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
find_program(CPACK_EXECUTABLE cpack REQUIRED)
find_program(RPMBUILD_EXECUTABLE rpmbuild REQUIRED)

configure_file(bsl.spec.in bsl.spec @ONLY)
set(RPMBUILD_TOPDIR ${CMAKE_CURRENT_BINARY_DIR}/rpmbuild)
set(RPMBUILD_OPTS "--define=_topdir ${RPMBUILD_TOPDIR}")
list(APPEND RPMBUILD_OPTS "--with=apidoc")

# invoke cpack as a command, not as a target, to avoid duplicate runs
add_custom_command(
    OUTPUT "${CPACK_SOURCE_PACKAGE_FILE_NAME}.tar.gz"
    DEPENDS ${CMAKE_BINARY_DIR}/CPackSourceConfig.cmake
    COMMAND ${CPACK_EXECUTABLE} -G TGZ --config ${CMAKE_BINARY_DIR}/CPackSourceConfig.cmake
    COMMENT "CPack generating ${CPACK_SOURCE_PACKAGE_FILE_NAME}.tar.gz"
)

# stage files following rpmbuild conventions
add_custom_command(
    OUTPUT "${RPMBUILD_TOPDIR}/SOURCES/${CPACK_SOURCE_PACKAGE_FILE_NAME}.tar.gz"
    DEPENDS "${CPACK_SOURCE_PACKAGE_FILE_NAME}.tar.gz"
    COMMAND ${CMAKE_COMMAND} -E make_directory ${RPMBUILD_TOPDIR}/SOURCES
    COMMAND ${CMAKE_COMMAND} -E create_hardlink "${CPACK_SOURCE_PACKAGE_FILE_NAME}.tar.gz" "${RPMBUILD_TOPDIR}/SOURCES/${CPACK_SOURCE_PACKAGE_FILE_NAME}.tar.gz"
    COMMENT "Placing ${PROJECT_NAME} source"
)
add_custom_command(
    OUTPUT "${RPMBUILD_TOPDIR}/SPECS/bsl.spec"
    DEPENDS bsl.spec
    COMMAND ${CMAKE_COMMAND} -E make_directory ${RPMBUILD_TOPDIR}/SPECS
    COMMAND ${CMAKE_COMMAND} -E create_hardlink ${CMAKE_CURRENT_BINARY_DIR}/bsl.spec ${RPMBUILD_TOPDIR}/SPECS/bsl.spec
    COMMENT "Placing ${PROJECT_NAME} spec"
)

add_custom_target(
    package_srpm
    DEPENDS ${RPMBUILD_TOPDIR}/SPECS/bsl.spec "rpmbuild/SOURCES/${CPACK_SOURCE_PACKAGE_FILE_NAME}.tar.gz"
    WORKING_DIRECTORY ${RPMBUILD_TOPDIR}
    COMMAND ${RPMBUILD_EXECUTABLE} ${RPMBUILD_OPTS} --bs SPECS/bsl.spec 
    COMMENT "Build SRPM"
    VERBATIM
    USES_TERMINAL
)
add_custom_target(
    package_rpm
    DEPENDS ${RPMBUILD_TOPDIR}/SPECS/bsl.spec "rpmbuild/SOURCES/${CPACK_SOURCE_PACKAGE_FILE_NAME}.tar.gz"
    WORKING_DIRECTORY ${RPMBUILD_TOPDIR}
    COMMAND ${RPMBUILD_EXECUTABLE} ${RPMBUILD_OPTS} --clean --bb SPECS/bsl.spec 
    COMMENT "Build RPMS"
    VERBATIM
    USES_TERMINAL
)
