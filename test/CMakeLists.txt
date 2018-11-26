# Depends on the following variables from the parent:
#   PROJECT_SOURCE_DIR
#   LIB_NAME
#   LIBRARY_INCLUDE_PATH
#   LIBRARY_PRIVATE_INCLUDE_PATH

set(TEST_APP_NAME "${LIB_NAME}_test")
set(TEST_SRC_PATH "${PROJECT_SOURCE_DIR}/test")

include_directories(${LIBRARY_INCLUDE_PATH})
include_directories(${LIBRARY_PRIVATE_INCLUDE_PATH})
include_directories(${TEST_THIRD_PARTY_INCLUDE_PATH})

file(GLOB TEST_SOURCE_FILES "${TEST_SRC_PATH}/*.cpp")
set(TEST_SOURCE_FILES ${TEST_SOURCE_FILES} PARENT_SCOPE)

add_executable(${TEST_APP_NAME} ${TEST_SOURCE_FILES})
target_link_libraries(${TEST_APP_NAME} ${OPENSSL_LIBRARIES})
target_link_libraries(${TEST_APP_NAME} ${LIB_NAME})

enable_testing()
ParseAndAddCatchTests(${TEST_APP_NAME})
