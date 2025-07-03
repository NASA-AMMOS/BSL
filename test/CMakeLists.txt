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


set(UNITY_ROOT "${CMAKE_SOURCE_DIR}/deps/unity")
find_package(unitytools)

add_library(bsl_test_utils)
target_sources(bsl_test_utils PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/bsl_test_utils.h)
target_sources(bsl_test_utils PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/bsl_test_utils.c)
set_target_properties(bsl_test_utils
    PROPERTIES
        VERSION ${CMAKE_PROJECT_VERSION}
        SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_link_libraries(bsl_test_utils PUBLIC bsl_front)
target_link_libraries(bsl_test_utils PUBLIC bsl_dynamic)
target_link_libraries(bsl_test_utils PUBLIC bsl_mock_bpa)
target_include_directories(bsl_test_utils PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

install(
    TARGETS bsl_test_utils
    RUNTIME
        COMPONENT runtime
    LIBRARY
        COMPONENT runtime
        NAMELINK_COMPONENT devel
    ARCHIVE
        COMPONENT devel
)


set(LIB_ORDERED bsl_mock_bpa bsl_dynamic bsl_front bsl_test_utils)

# add_unity_test(SOURCE test_bsl_text_util.c)
# target_link_libraries(test_bsl_text_util PUBLIC ${LIB_ORDERED})

# add_unity_test(SOURCE test_bundle_ctx_dyn.c)
# target_link_libraries(test_bundle_ctx_dyn PUBLIC ${LIB_ORDERED})

# add_unity_test(SOURCE test_pp_reg_dyn.c)
# target_link_libraries(test_pp_reg_dyn PUBLIC ${LIB_ORDERED})

# add_unity_test(SOURCE test_mock_bpa_encode.c)
# target_link_libraries(test_mock_bpa_encode PUBLIC ${LIB_ORDERED})

# add_unity_test(SOURCE test_mock_bpa_decode.c)
# target_link_libraries(test_mock_bpa_decode PUBLIC ${LIB_ORDERED})

# add_unity_test(SOURCE test_mock_bpa_eid.c)
# target_link_libraries(test_mock_bpa_eid PUBLIC ${LIB_ORDERED})

# add_unity_test(SOURCE test_mock_bpa_eidpat.c)
# target_link_libraries(test_mock_bpa_eidpat PUBLIC ${LIB_ORDERED})

# add_unity_test(SOURCE test_mock_bpa_label.c)
# target_link_libraries(test_mock_bpa_label PUBLIC ${LIB_ORDERED})

# add_unity_test(SOURCE test_mock_bpa_codec_loopback.c)
# target_link_libraries(test_mock_bpa_codec_loopback PUBLIC ${LIB_ORDERED})

# add_unity_test(SOURCE test_crypto.c)
# target_link_libraries(test_crypto PUBLIC bsl_dynamic)

# # Tests the security context via front-end interface.
# add_unity_test(SOURCE test_SecurityContext.c)
# target_link_libraries(test_SecurityContext PUBLIC ${LIB_ORDERED})

# Specific test for default security context implementation primitives.
add_unity_test(SOURCE test_security_context/test_DefaultSecContext.c)
target_link_libraries(test_DefaultSecContext PUBLIC ${LIB_ORDERED})

# add_unity_test(SOURCE test_PolicyProvider.c)
# target_link_libraries(test_PolicyProvider PUBLIC ${LIB_ORDERED})

# add_unity_test(SOURCE test_policy_provider/test_DefaultPolicyProvider.c)
# target_link_libraries(test_DefaultPolicyProvider PUBLIC ${LIB_ORDERED})
