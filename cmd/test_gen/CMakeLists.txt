set(APP_NAME "test_gen")
set(APP_SRC_PATH "${PROJECT_SOURCE_DIR}/cmd/test_gen")

set(TEST_INCLUDE_PATH "${PROJECT_SOURCE_DIR}/test")
set(TEST_VECTORS_SRC "${TEST_INCLUDE_PATH}/test_vectors.cpp")

file(GLOB APP_SOURCE_FILES "${APP_SRC_PATH}/*.cpp")
set(APP_SOURCE_FILES ${APP_SOURCE_FILES} PARENT_SCOPE)

add_executable(${APP_NAME} ${APP_SOURCE_FILES})
target_sources(${APP_NAME} PRIVATE ${TEST_VECTORS_SRC})
target_include_directories(${APP_NAME} PRIVATE ${LIBRARY_INCLUDE_PATH}
                                       PRIVATE ${OPENSSL_INCLUDE_DIR}
                                       PRIVATE ${TEST_INCLUDE_PATH})
target_link_libraries(${APP_NAME} ${OPENSSL_LIBRARIES})
target_link_libraries(${APP_NAME} ${LIB_NAME})
