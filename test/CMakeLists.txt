include(GoogleTest)

set(GTEST_APP_NAME "${LIB_NAME}_gtest")
set(GTEST_SRC_PATH "${PROJECT_SOURCE_DIR}/test")
set(GTEST_RUN_PATH "${PROJECT_SOURCE_DIR}/third_party/mls-implementations/test_vectors")

include_directories(${LIBRARY_INCLUDE_PATH})
include_directories(${LIBRARY_PRIVATE_INCLUDE_PATH})
include_directories(${GTEST_INCLUDE_DIR})

file(GLOB GTEST_SOURCE_FILES "${GTEST_SRC_PATH}/*.cpp")
set(GTEST_SOURCE_FILES ${GTEST_SOURCE_FILES} PARENT_SCOPE)

add_executable(${GTEST_APP_NAME} ${GTEST_SOURCE_FILES})
target_link_libraries(${GTEST_APP_NAME} ${OPENSSL_LIBRARIES})
target_link_libraries(${GTEST_APP_NAME} ${LIB_NAME})
target_link_libraries(${GTEST_APP_NAME} ${GTEST_LIBRARY})
target_link_libraries(${GTEST_APP_NAME} ${GTEST_MAIN_LIBRARY})

gtest_discover_tests(${GTEST_APP_NAME}
                     WORKING_DIRECTORY ${GTEST_RUN_PATH})
