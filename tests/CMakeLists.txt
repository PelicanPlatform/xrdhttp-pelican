
if (NOT BUILD_TESTS)
  return()
endif()

include(GoogleTest)

include_directories(${XRootD_INCLUDE_DIR})
add_executable(xrdhttp-pelican-test xrdhttp_pelican_test.cc)
target_link_libraries(xrdhttp-pelican-test XrdHttpPelicanTesting GTest::GTest GTest::Main)

gtest_discover_tests(xrdhttp-pelican-test)

add_test(NAME HTTP::pelican::setup
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/xrdhttp-setup.sh" pelican)

set_tests_properties(HTTP::pelican::setup
  PROPERTIES
    FIXTURES_SETUP HTTP::pelican
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR};SOURCE_DIR=${CMAKE_SOURCE_DIR};XROOTD_BINDIR=${XRootD_DATA_DIR}/../bin"
)

add_test(NAME HTTP::pelican::teardown
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/xrdhttp-teardown.sh" pelican)

set_tests_properties(HTTP::pelican::teardown
  PROPERTIES
    FIXTURES_CLEANUP HTTP::pelican
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR}"
)

add_test(NAME HTTP::pelican::test
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/xrdhttp-test.sh" pelican)

list(APPEND BASIC_TEST_LOGS ${CMAKE_CURRENT_BINARY_DIR}/tests/pelican/server.log)
list(APPEND BASIC_TEST_LOGS ${CMAKE_CURRENT_BINARY_DIR}/tests/pelican/client.log)

set_tests_properties(HTTP::pelican::test
  PROPERTIES
    FIXTURES_REQUIRED HTTP::pelican
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR}"
    ATTACHED_FILES_ON_FAIL "${BASIC_TEST_LOGS}"
)
