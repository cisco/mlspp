set(TEST_APP_NAME "${CURRENT_LIB_NAME}_test")

# Dependencies
find_package(doctest REQUIRED)

# Test Binary
file(GLOB TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_executable(${TEST_APP_NAME} ${TEST_SOURCES})
add_dependencies(${TEST_APP_NAME} ${CURRENT_LIB_NAME} bytes tls_syntax)
target_link_libraries(${TEST_APP_NAME} ${CURRENT_LIB_NAME} doctest::doctest)

# Note that other modules enable CTest at this stage.  We do not enable CTest
# for the test vector logic because these tests take quite a bit of time to run,
# and are better run as part of interop testing.
