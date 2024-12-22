
if (NOT BUILD_TESTS)
  return()
endif()

include(GoogleTest)

include_directories(${XRootD_INCLUDE_DIR})
add_executable(xrdhttp-pelican-test xrdhttp_pelican_test.cc)
target_link_libraries(xrdhttp-pelican-test XrdHttpPelicanTesting GTest::GTest GTest::Main)

gtest_discover_tests(xrdhttp-pelican-test)
