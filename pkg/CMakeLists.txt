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
    COMMAND mkdir -p ${RPMBUILD_TOPDIR}/SOURCES
    COMMAND ${CMAKE_COMMAND} -E create_hardlink "${CPACK_SOURCE_PACKAGE_FILE_NAME}.tar.gz" "${RPMBUILD_TOPDIR}/SOURCES/${CPACK_SOURCE_PACKAGE_FILE_NAME}.tar.gz"
    COMMENT "Placing ${PROJECT_NAME} source"
)
add_custom_command(
    OUTPUT "${RPMBUILD_TOPDIR}/SPECS/bsl.spec"
    DEPENDS bsl.spec
    COMMAND mkdir -p ${RPMBUILD_TOPDIR}/SPECS
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
