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

include(GNUInstallDirs)

find_package(Doxygen REQUIRED)

find_program(XMLSTARLET_EXECUTABLE xmlstarlet)
find_program(ASPELL_EXECUTABLE aspell)

find_program(MAKE_EXECUTABLE make)
message(STATUS "Found make at ${MAKE_EXECUTABLE}")
find_program(DBLATEX_EXECUTABLE dblatex)
message(STATUS "Found dblatex at ${DBLATEX_EXECUTABLE}")
find_file(
  PLANTUML_JAR
  NAMES plantuml.jar
  PATH_SUFFIXES "share/java" "share/plantuml"
)
if(PLANTUML_JAR)
    message(STATUS "Found plantuml at ${PLANTUML_JAR}")
endif(PLANTUML_JAR)

configure_file(Doxyfile.in Doxyfile @ONLY)

set(XML_COMBINE ${CMAKE_CURRENT_BINARY_DIR}/xml/combine.xslt)
set(XML_INDEX ${CMAKE_CURRENT_BINARY_DIR}/xml/index.xml)
add_custom_target(
    docs-api-html
    BYPRODUCTS
        ${CMAKE_CURRENT_BINARY_DIR}/html/index.html
        ${CMAKE_CURRENT_BINARY_DIR}/latex/refman.tex
        ${CMAKE_CURRENT_BINARY_DIR}/latex/Makefile
        ${XML_COMBINE} ${XML_INDEX}
    DEPENDS
        ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        ${CMAKE_CURRENT_SOURCE_DIR}/footer.html
        ${CMAKE_CURRENT_SOURCE_DIR}/header.tex
    COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Generating API documentation with Doxygen"
    USES_TERMINAL
)
install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/index.html
    TYPE DOC
    COMPONENT docs-api
)
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html
    TYPE DOC
    COMPONENT docs-api
)

if(XMLSTARLET_EXECUTABLE AND ASPELL_EXECUTABLE)
    # spellcheck on combined XML output
    set(DICTIONARY_TXT "${CMAKE_CURRENT_SOURCE_DIR}/dictionary.txt")
    set(SPELLCHECK_XSL "${CMAKE_CURRENT_SOURCE_DIR}/spellcheck.xsl")
    set(MISSPELLING_TXT "misspelling.txt")
    add_custom_command(
        OUTPUT "dictionary.cwl"
        DEPENDS ${DICTIONARY_TXT}
        COMMAND cat "${DICTIONARY_TXT}" |
            ${ASPELL_EXECUTABLE} --lang=en create master "./dictionary.cwl"
    )
    add_custom_command(
        OUTPUT ${MISSPELLING_TXT}
        DEPENDS
            ${XML_COMBINE} ${XML_INDEX}
            ${SPELLCHECK_XSL} "dictionary.cwl"
        COMMAND
            ${XMLSTARLET_EXECUTABLE} tr "${XML_COMBINE}" "${XML_INDEX}" |
            ${XMLSTARLET_EXECUTABLE} tr "${SPELLCHECK_XSL}" |
            ${ASPELL_EXECUTABLE} --mode=html --lang=EN_US --extra-dicts=./dictionary.cwl list |
            sort | uniq > "${MISSPELLING_TXT}"
    )
    add_custom_target(
        docs-api-misspelling ALL
        DEPENDS "${MISSPELLING_TXT}"
        COMMAND cat "${MISSPELLING_TXT}"
        # success means file is present and empty
        COMMAND test -f "${MISSPELLING_TXT}" -a ! -s "${MISSPELLING_TXT}"
        COMMENT "Checking ${MISSPELLING_TXT}"
    )
endif(XMLSTARLET_EXECUTABLE AND ASPELL_EXECUTABLE)

if(MAKE_EXECUTABLE AND DBLATEX_EXECUTABLE)
    add_custom_target(
        docs-api-pdf
        BYPRODUCTS
            ${CMAKE_CURRENT_BINARY_DIR}/latex/refman.pdf
        DEPENDS
            ${CMAKE_CURRENT_BINARY_DIR}/latex/Makefile
            ${CMAKE_CURRENT_BINARY_DIR}/latex/refman.tex
        COMMAND ${MAKE_EXECUTABLE}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/latex
        COMMENT "Generating API documentation PDF"
    )
    install(
        FILES
            ${CMAKE_CURRENT_BINARY_DIR}/latex/refman.pdf
        TYPE DOC
        RENAME "${PROJECT_NAME}-api.pdf"
        COMPONENT docs-api
    )
endif(MAKE_EXECUTABLE AND DBLATEX_EXECUTABLE)
