set(APP_NAME "test_gen")
set(APP_SRC_PATH "${PROJECT_SOURCE_DIR}/cmd/test_gen")

set(TEST_INCLUDE_PATH "${PROJECT_SOURCE_DIR}/test")
set(TEST_VECTORS_SRC "${TEST_INCLUDE_PATH}/test_vectors.cpp")

include_directories(${LIBRARY_INCLUDE_PATH})
include_directories(${LIBRARY_PRIVATE_INCLUDE_PATH})
include_directories(${TEST_INCLUDE_PATH})

file(GLOB APP_SOURCE_FILES "${APP_SRC_PATH}/*.cpp")
set(APP_SOURCE_FILES ${APP_SOURCE_FILES} PARENT_SCOPE)

add_executable(${APP_NAME} ${APP_SOURCE_FILES})
target_sources(${APP_NAME} PUBLIC ${TEST_VECTORS_SRC})
target_link_libraries(${APP_NAME} ${OPENSSL_LIBRARIES})
target_link_libraries(${APP_NAME} ${LIB_NAME})
