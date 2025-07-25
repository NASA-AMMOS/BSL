# Defines the function add_unity_test() for generating test executables.
# This requires the cmake variable UNITY_ROOT to point to the source tree.
# The variable TEST_EXEC_PREFIX can be set to cause the test executables to be
# run under another tool (e.g. valgrind).
# The variable TEST_INSTALL_PREFIX can be set to have the unit tests installed
# by cmake under that executable prefix path.
#
message(STATUS "Searching for Unity tools in ${UNITY_ROOT}")

find_program(RUBY_BIN ruby REQUIRED)
if(NOT RUBY_BIN)
  message(FATAL_ERROR "Missing ruby")
endif()
set(RUBY_BIN ${RUBY_BIN} PARENT_SCOPE)

# Test runner source generator
find_file(UNITY_GENERATOR_BIN "generate_test_runner.rb" 
  PATHS "${UNITY_ROOT}/auto" 
  NO_DEFAULT_PATH
  REQUIRED
)
set(UNITY_GENERATOR_BIN ${UNITY_GENERATOR_BIN} PARENT_SCOPE)

find_file(UNITY_PARSER_BIN "parse_output.rb" 
  PATHS "${UNITY_ROOT}/auto" 
  NO_DEFAULT_PATH
  REQUIRED
)

# Compile time package
find_package(unity REQUIRED CONFIG)
message(STATUS "Found unity at ${unity_DIR}")

function(add_unity_test)
  set(options OPTIONAL )
  set(oneValueArgs TARGET MAIN_NAME)
  set(multiValueArgs SOURCE)
  cmake_parse_arguments(
    UNITYTEST "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN}
  )
  list(GET UNITYTEST_SOURCE 0 MAIN_SOURCE)
  get_filename_component(BASENAME ${MAIN_SOURCE} NAME_WE)
  get_filename_component(ABSOLUTE_SOURCE ${MAIN_SOURCE} ABSOLUTE)

  if(NOT UNITYTEST_TARGET)
    set(UNITYTEST_TARGET "${BASENAME}")
  endif()
  
  set(GEN_PARAMS "--use_param_tests=1")
  if(UNITYTEST_MAIN_NAME)
      list(APPEND GEN_PARAMS "--main_name=${MAIN_NAME}")
  endif()
  
  message(STATUS "Adding unit test ${UNITYTEST_TARGET} from ${ABSOLUTE_SOURCE}")
  
  set(RUNNER_FILE "${CMAKE_CURRENT_BINARY_DIR}/${BASENAME}_Runner.c")
  add_custom_command(
    OUTPUT "${RUNNER_FILE}"
    DEPENDS "${ABSOLUTE_SOURCE}"
    COMMAND ${RUBY_BIN} ${UNITY_GENERATOR_BIN} "${ABSOLUTE_SOURCE}" "${RUNNER_FILE}" ${GEN_PARAMS}
  )
  add_executable(${BASENAME} ${UNITYTEST_SOURCE} ${RUNNER_FILE})
  target_compile_definitions(${BASENAME} PRIVATE 
    UNITY_INCLUDE_PRINT_FORMATTED
    UNITY_INCLUDE_FLOAT
    UNITY_INCLUDE_DOUBLE
  )
  target_compile_options(${BASENAME} PRIVATE -Wno-redundant-decls -Wno-missing-prototypes -Wno-shadow)
  target_link_libraries(${BASENAME} PUBLIC unity::framework)

  add_test(
    NAME ${BASENAME}
    COMMAND ${TEST_EXEC_PREFIX} "${CMAKE_CURRENT_BINARY_DIR}/${BASENAME}"
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
