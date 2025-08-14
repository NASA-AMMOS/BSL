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

if(BUILD_UNITTEST OR BUILD_FUZZING)
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
endif(BUILD_UNITTEST OR BUILD_FUZZING)

set(LIB_ORDERED bsl_front bsl_dynamic bsl_mock_bpa bsl_test_utils)

if(BUILD_UNITTEST)
  set(UNITY_ROOT "${CMAKE_SOURCE_DIR}/deps/unity")
  find_package(unitytools)

#   add_unity_test(SOURCE test_MockBPA_text_util.c)
#   target_link_libraries(test_MockBPA_text_util PUBLIC bsl_mock_bpa)
  
#   add_unity_test(SOURCE test_MockBPA_EID.c)
#   target_link_libraries(test_MockBPA_EID PUBLIC ${LIB_ORDERED})
  
#   add_unity_test(SOURCE test_MockBPA_Codecs.c)
#   target_link_libraries(test_MockBPA_Codecs PUBLIC ${LIB_ORDERED})
  
#   add_unity_test(SOURCE test_mock_bpa_ctr.c)
#   target_link_libraries(test_mock_bpa_ctr PUBLIC ${LIB_ORDERED})
  
#   add_unity_test(SOURCE test_CryptoInterface.c)
#   target_link_libraries(test_CryptoInterface PUBLIC ${LIB_ORDERED})
  
#   add_unity_test(SOURCE test_SecurityTypes.c)
#   target_link_libraries(test_SecurityTypes PUBLIC ${LIB_ORDERED})
  
#   # Exercises the portion of the backend that interacts with the policy providers
#   add_unity_test(SOURCE test_BackendSecurityContext.c)
#   target_link_libraries(test_BackendSecurityContext PUBLIC ${LIB_ORDERED})
  
#   # Exercises the portion of the backend that interacts with the security contexts
#   add_unity_test(SOURCE test_BackendPolicyProvider.c)
#   target_link_libraries(test_BackendPolicyProvider PUBLIC ${LIB_ORDERED})
  
#   # Specific unit tests for ONLY the "Sample Policy Provider" module (Offered as example provider)
#   add_unity_test(SOURCE test_SamplePolicyProvider.c)
#   target_link_libraries(test_SamplePolicyProvider PUBLIC ${LIB_ORDERED})
  
#   # Specific tests for ONLY the "Default Security Context" module (Implementation of RFC9173)
#   add_unity_test(SOURCE test_DefaultSecurityContext.c)
#   target_link_libraries(test_DefaultSecurityContext PUBLIC ${LIB_ORDERED})
  
  # Exercises the MockBPA using the publicly exposed BSL front end
  add_unity_test(SOURCE test_PublicInterfaceImpl.c)
  target_link_libraries(test_PublicInterfaceImpl PUBLIC ${LIB_ORDERED})
endif(BUILD_UNITTEST)

if(BUILD_FUZZING)
  add_fuzz_test(SOURCE fuzz_mock_bpa_eid_cbor.cpp)
  target_link_libraries(fuzz_mock_bpa_eid_cbor PUBLIC ${LIB_ORDERED})

  add_fuzz_test(SOURCE fuzz_mock_bpa_bpv7_cbor.cpp)
  target_link_libraries(fuzz_mock_bpa_bpv7_cbor PUBLIC ${LIB_ORDERED})
endif(BUILD_FUZZING)