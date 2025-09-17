
# Try pkg-config first
pkg_search_module(VALGRIND valgrind IMPORTED_TARGET)
if(VALGRIND_FOUND)
    add_library(valgrind::valgrind ALIAS PkgConfig::VALGRIND)
endif(VALGRIND_FOUND)
