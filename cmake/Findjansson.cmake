
# Try pkg-config first
pkg_search_module(JANSSON jansson IMPORTED_TARGET)
if(JANSSON_FOUND)
    add_library(Jansson::Jansson ALIAS PkgConfig::JANSSON)
endif(JANSSON_FOUND)

# Fall-back to manual
if(NOT JANSSON_FOUND)
    find_path(JANSSON_HEADER NAMES jansson.h REQUIRED)
    find_library(JANSSON_LIB NAMES jansson REQUIRED)

    add_library(Jansson::Jansson SHARED IMPORTED)
    set_target_properties(Jansson::Jansson PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${JANSSON_HEADER}"
        IMPORTED_LOCATION "${JANSSON_LIB}"
    )
endif(NOT JANSSON_FOUND)
