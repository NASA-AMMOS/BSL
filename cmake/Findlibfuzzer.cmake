# Defines the function add_fuzz_test() for generating libFuzzer executables.
#
# The variable TEST_INSTALL_PREFIX can be set to have the unit tests installed
# by cmake under that executable prefix path.
#

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang"
   OR NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL "Can only fuzz with clang compiler")
endif()

function(add_fuzz_test)
  set(options OPTIONAL )
  set(oneValueArgs TARGET MAIN_NAME RUNS_COUNT)
  set(multiValueArgs SOURCE)
  cmake_parse_arguments(
    FUZZTEST "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN}
  )

  list(GET FUZZTEST_SOURCE 0 MAIN_SOURCE)
  get_filename_component(BASENAME ${MAIN_SOURCE} NAME_WE)
  get_filename_component(ABSOLUTE_SOURCE ${MAIN_SOURCE} ABSOLUTE)

  if(NOT FUZZTEST_TARGET)
    set(FUZZTEST_TARGET "${BASENAME}")
  endif()
  if(NOT FUZZTEST_RUNS_COUNT)
    set(FUZZTEST_RUNS_COUNT "1000000")
  endif()

  message(STATUS "Adding fuzz test ${FUZZTEST_TARGET} from ${ABSOLUTE_SOURCE}")

  add_executable(${BASENAME} ${FUZZTEST_SOURCE})
  target_compile_options(
    ${BASENAME}
    PRIVATE
      -g
      -fsanitize=fuzzer,address
  )
  target_link_options(
    ${BASENAME}
    PRIVATE
      -fsanitize=fuzzer,address
  )

  add_test(
    NAME ${BASENAME}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND
      "${CMAKE_CURRENT_BINARY_DIR}/${BASENAME}"
      "${BASENAME}-corpus"
      -runs=${FUZZTEST_RUNS_COUNT}
      -detect_leaks=1
  )

  if(TEST_INSTALL_PREFIX)
    install(
      TARGETS ${BASENAME}
      RUNTIME
        DESTINATION ${TEST_INSTALL_PREFIX}
        COMPONENT test
    )
  endif(TEST_INSTALL_PREFIX)
endfunction()
