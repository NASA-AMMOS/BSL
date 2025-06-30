option(RTEMS_TOOLS_PREFIX "Path to RCC tools" "/opt/rcc-1.3.0-gcc")

# the name of the target operating system
set(CMAKE_SYSTEM_NAME RTEMS)

# which compilers to use for C and C++
set(RTEMS_BSP_PREFIX "${RTEMS_TOOLS_PREFIX}/sparc-gaisler-rtems5")
set(RTEMS_BSP "ut700")
set(RTEMS_BSP_C_FLAGS "-mcpu=leon3 -mfix-ut700 -qbsp=${RTEMS_BSP}")
set(RTEMS_BSP_CXX_FLAGS ${RTEMS_BSP_C_FLAGS})
set(CMAKE_C_COMPILER   "${RTEMS_TOOLS_PREFIX}/bin/sparc-gaisler-rtems5-gcc")
set(CMAKE_CXX_COMPILER "${RTEMS_TOOLS_PREFIX}/bin/sparc-gaisler-rtems5-g++")

# where is the target environment located
set(CMAKE_FIND_ROOT_PATH "${RTEMS_TOOLS_PREFIX}/bin")

# adjust the default behavior of the FIND_XXX() commands:
# search programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# search headers and libraries in the target environment
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
