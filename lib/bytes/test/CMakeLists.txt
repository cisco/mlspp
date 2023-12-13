set(TEST_APP_NAME "${CURRENT_LIB_NAME}_test")

# Dependencies
find_package(doctest REQUIRED)

# Test Binary
file(GLOB TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_executable(${TEST_APP_NAME} ${TEST_SOURCES})
add_dependencies(${TEST_APP_NAME} ${CURRENT_LIB_NAME})
target_link_libraries(${TEST_APP_NAME} ${CURRENT_LIB_NAME} doctest::doctest)

# Enable CTest
include(doctest)
enable_testing()
doctest_discover_tests(${TEST_APP_NAME} ADD_LABELS 0)
