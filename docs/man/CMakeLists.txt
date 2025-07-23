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
find_program(ASCIIDOCTOR_EXECUTABLE asciidoctor REQUIRED)
message(STATUS "Found asciidoctor at ${ASCIIDOCTOR_EXECUTABLE}")
include(GNUInstallDirs)

set(OUT_MAN_FILES "")
file(GLOB IN_MAN_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/" "man?")
foreach(IN_DIR ${IN_MAN_DIRS})
    string(REGEX REPLACE ".*man([0-9])\$" "\\1" SECNUM ${IN_DIR})

    file(GLOB IN_ADOC_FILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "man${SECNUM}/*.adoc")
    foreach(IN_FILE ${IN_ADOC_FILES})
        get_filename_component(BASENAME ${IN_FILE} NAME_WE)
        set(OUT_FILE "${BASENAME}.${SECNUM}")
        set(IN_PATH "${CMAKE_CURRENT_SOURCE_DIR}/${IN_FILE}")
        set(OUT_PATH "${CMAKE_CURRENT_BINARY_DIR}/man${SECNUM}/${OUT_FILE}")
        message(STATUS "Manpage ${OUT_FILE} from ${IN_PATH}")

        add_custom_command(
            OUTPUT ${OUT_PATH}
            DEPENDS ${IN_PATH}
            COMMAND
                ${ASCIIDOCTOR_EXECUTABLE} -b manpage
                --source-dir=${CMAKE_CURRENT_SOURCE_DIR}
                --destination-dir=${CMAKE_CURRENT_BINARY_DIR}
                -a "revnumber=v${CMAKE_PROJECT_VERSION}"
                --out-file=${OUT_PATH}
                ${IN_PATH}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMENT "Generating manpage ${OUT_FILE}"
            USES_TERMINAL
        )
        list(APPEND OUT_MAN_FILES "${OUT_PATH}")
        install(
            FILES ${OUT_PATH}
            DESTINATION "${CMAKE_INSTALL_MANDIR}/man${SECNUM}"
            COMPONENT docs-man
        )
    endforeach()
endforeach()

add_custom_target(
    docs-man
    DEPENDS ${OUT_MAN_FILES}
)
