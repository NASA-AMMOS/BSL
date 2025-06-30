# Imports targets for using M*LIB libraries:
#  MLIB::mlib
#
find_path(
  MLIB_INCLUDE_DIR
  "m-core.h"
  PATH_SUFFIXES "m-lib"
  REQUIRED
)
add_library(MLIB::mlib INTERFACE IMPORTED)
target_include_directories(MLIB::mlib INTERFACE ${MLIB_INCLUDE_DIR})
