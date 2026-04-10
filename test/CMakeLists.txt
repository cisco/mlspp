set(TEST_APP_NAME "${LIB_NAME}_test")

# Test Binary
file(GLOB TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_executable(${TEST_APP_NAME} ${TEST_SOURCES})
add_dependencies(${TEST_APP_NAME} ${LIB_NAME} bytes tls_syntax mls_vectors mls_ds)
target_include_directories(${TEST_APP_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(${TEST_APP_NAME} PRIVATE mls_vectors mls_ds Catch2::Catch2WithMain)

# Link Security.framework on macOS for Keychain tests
if(APPLE)
  find_library(SECURITY_FRAMEWORK Security)
  find_library(COREFOUNDATION_FRAMEWORK CoreFoundation)
  if(SECURITY_FRAMEWORK AND COREFOUNDATION_FRAMEWORK)
    target_link_libraries(${TEST_APP_NAME} PRIVATE ${SECURITY_FRAMEWORK} ${COREFOUNDATION_FRAMEWORK})
    target_compile_definitions(${TEST_APP_NAME} PRIVATE HAVE_SECURITY_FRAMEWORK)
  endif()
endif()

# Enable CTest
catch_discover_tests(${TEST_APP_NAME})
