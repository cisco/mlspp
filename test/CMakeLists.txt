include(GoogleTest)

set(GTEST_APP_NAME "${LIB_NAME}_gtest")
set(GTEST_SRC_PATH "${PROJECT_SOURCE_DIR}/test")
set(GTEST_RUN_PATH "${CMAKE_CURRENT_BINARY_DIR}/vectors")

# Fetch and install GTest at configure time
# See https://github.com/google/googletest/blob/master/googletest/README.md
configure_file(GTest.cmake googletest-download/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  RESULT_VARIABLE GTEST_INSTALL_FAILURE
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
if(GTEST_INSTALL_FAILURE)
  message(FATAL_ERROR "CMake step for googletest failed: ${result}")
endif()
execute_process(COMMAND ${CMAKE_COMMAND} --build .
  RESULT_VARIABLE GTEST_BUILD_FAILIURE
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
if(GTEST_BUILD_FAILURE)
  message(FATAL_ERROR "Build step for googletest failed: ${result}")
endif()

add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/googletest-src
                 ${CMAKE_CURRENT_BINARY_DIR}/googletest-build
                 EXCLUDE_FROM_ALL)

# Add our tests
include_directories(${LIBRARY_INCLUDE_PATH})
include_directories(${LIBRARY_PRIVATE_INCLUDE_PATH})
include_directories(${GTEST_INCLUDE_DIR})

file(GLOB GTEST_SOURCE_FILES "${GTEST_SRC_PATH}/*.cpp")
set(GTEST_SOURCE_FILES ${GTEST_SOURCE_FILES} PARENT_SCOPE)

add_executable(${GTEST_APP_NAME} ${GTEST_SOURCE_FILES})
target_link_libraries(${GTEST_APP_NAME} gtest_main)
target_link_libraries(${GTEST_APP_NAME} ${OPENSSL_LIBRARIES})
target_link_libraries(${GTEST_APP_NAME} ${LIB_NAME})

gtest_discover_tests(${GTEST_APP_NAME}
                     WORKING_DIRECTORY ${GTEST_RUN_PATH})
