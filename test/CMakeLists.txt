set(TEST_APP_NAME "${LIB_NAME}_test")

# Test Binary
file(GLOB TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_executable(${TEST_APP_NAME} ${TEST_SOURCES})
add_dependencies(${TEST_APP_NAME} ${LIB_NAME} bytes tls_syntax mls_vectors mls_ds)
target_include_directories(${TEST_APP_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(${TEST_APP_NAME} PRIVATE mls_vectors mls_ds Catch2::Catch2WithMain)

# Enable CTest
catch_discover_tests(${TEST_APP_NAME})
