
if (NOT BUILD_TESTS)
  return()
endif()

include(GoogleTest)

include_directories(${XRootD_INCLUDE_DIR})
add_executable(xrdhttp-pelican-test xrdhttp_pelican_test.cc)
target_link_libraries(xrdhttp-pelican-test XrdHttpPelicanTesting GTest::GTest GTest::Main)

add_executable(xrdhttp-reexec-test xrdhttp_reexec_test.cc)
target_link_libraries(xrdhttp-reexec-test GTest::GTest GTest::Main)

# Stack trace unit tests (HexUtils, GetModuleForAddress)
add_executable(xrdhttp-stacktrace-unit-test xrdhttp_stacktrace_unit_test.cc)
target_link_libraries(xrdhttp-stacktrace-unit-test XrdHttpPelicanObj GTest::GTest GTest::Main)

# Stack trace integration tests (StackTraceTest) - requires fixture to run
add_executable(xrdhttp-stacktrace-integration-test xrdhttp_stacktrace_integration_test.cc)
target_link_libraries(xrdhttp-stacktrace-integration-test XrdHttpPelicanObj GTest::GTest GTest::Main)

add_library( XrdOssSlowOpen MODULE xrdoss_slowopen.cc )
target_include_directories( XrdOssSlowOpen PRIVATE ${XRootD_INCLUDE_DIRS} )
target_link_libraries( XrdOssSlowOpen ${XRootD_UTILS_LIBRARIES} ${XRootD_SERVER_LIBRARIES} )
set_target_properties( XrdOssSlowOpen PROPERTIES OUTPUT_NAME "XrdOssSlowOpen-${XRootD_PLUGIN_VERSION}" SUFFIX ".so" )

# SciTokens utilities for testing
find_package(OpenSSL REQUIRED)
find_package(SciTokensCpp REQUIRED)

add_executable(xrdscitokens-create-jwks xrdscitokens-create-jwks.cc)
target_link_libraries(xrdscitokens-create-jwks OpenSSL::SSL OpenSSL::Crypto)

add_executable(xrdscitokens-create-token xrdscitokens-create-token.cc)
target_include_directories(xrdscitokens-create-token PRIVATE ${SCITOKENS_CPP_INCLUDE_DIR})
target_link_libraries(xrdscitokens-create-token ${SCITOKENS_CPP_LIBRARIES})

gtest_discover_tests(xrdhttp-pelican-test)

# Discover stack trace unit tests - no fixture dependency
gtest_discover_tests(xrdhttp-stacktrace-unit-test)

# Discover stack trace integration tests - with fixture dependency
gtest_discover_tests(xrdhttp-stacktrace-integration-test
  PROPERTIES
    FIXTURES_REQUIRED HTTP::pelican
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR};LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}:$ENV{LD_LIBRARY_PATH};DYLD_LIBRARY_PATH=${CMAKE_BINARY_DIR}:$ENV{DYLD_LIBRARY_PATH}"
    LABELS "integration"
)

# Add re-exec integration test
add_test(NAME HTTP::pelican::reexec
  COMMAND xrdhttp-reexec-test)

set_tests_properties(HTTP::pelican::reexec
  PROPERTIES
    FIXTURES_REQUIRED HTTP::pelican
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR};LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}:$ENV{LD_LIBRARY_PATH};DYLD_LIBRARY_PATH=${CMAKE_BINARY_DIR}:$ENV{DYLD_LIBRARY_PATH}"
    LABELS "integration"
)

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
