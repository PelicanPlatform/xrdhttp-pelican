
cmake_minimum_required( VERSION 3.16 )
project( xrdhttp-pelican )

find_package( XRootD REQUIRED )

set (CMAKE_CXX_STANDARD 17)

find_package( Threads REQUIRED )

if( CMAKE_COMPILER_IS_GNUCXX )
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror" )
endif()
if(NOT APPLE)
  SET( CMAKE_SHARED_LINKER_FLAGS "-Wl,--no-undefined")
  SET( CMAKE_MODULE_LINKER_FLAGS "-Wl,--no-undefined")
endif()

include_directories(${XRootD_INCLUDE_DIR})

add_library(XrdHttpPelicanObj OBJECT src/XrdHttpPelican.cc)
target_link_libraries(XrdHttpPelicanObj ${XRootD_HTTP_LIBRARIES} ${XRootD_UTILS_LIBRARIES} Threads::Threads)
set_target_properties(XrdHttpPelicanObj PROPERTIES POSITION_INDEPENDENT_CODE ON)

# The test executables cannot link against the normal library on Linux as we hide the exported symbols
if (ENABLE_TESTS)
  add_library(XrdHttpPelicanTesting SHARED "$<TARGET_OBJECTS:XrdHttpPelicanObj>")
  target_link_libraries(XrdHttpPelicanTesting XrdHttpPelicanObj)
endif()
add_library(XrdHttpPelican MODULE "$<TARGET_OBJECTS:XrdHttpPelicanObj>")
target_link_libraries(XrdHttpPelican XrdHttpPelicanObj)

if(APPLE)
  SET(LIBRARY_SUFFIX ".dylib")
  set_target_properties(XrdHttpPelican PROPERTIES OUTPUT_NAME "XrdHttpPelican-${XRootD_VERSION_MAJOR}" SUFFIX ${LIBRARY_SUFFIX})
else()
  SET(LIBRARY_SUFFIX ".so")
  set_target_properties(XrdHttpPelican PROPERTIES OUTPUT_NAME "XrdHttpPelican-${XRootD_VERSION_MAJOR}" SUFFIX ${LIBRARY_SUFFIX} LINK_FLAGS "-Wl,--version-script=${CMAKE_SOURCE_DIR}/configs/export-lib-symbols")
endif()

SET(LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH "Install path for libraries")

install(
  TARGETS XrdHttpPelican
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
)
