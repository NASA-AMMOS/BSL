find_path(JANSSON_HEADER NAMES jansson.h REQUIRED)
find_library(JANSSON_LIB NAMES jansson REQUIRED)

add_library(Jansson::Jansson INTERFACE IMPORTED)
set_target_properties(Jansson::Jansson PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${JANSSON_HEADER}"
    IMPORTED_LOCATION "${JANSSON_LIB}"
)
