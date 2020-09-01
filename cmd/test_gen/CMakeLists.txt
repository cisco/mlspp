set(APP_NAME "test_gen")

set(TEST_INCLUDE_PATH "${PROJECT_SOURCE_DIR}/test")
set(TEST_VECTORS_SRC "${TEST_INCLUDE_PATH}/test_vectors.cpp")
file(GLOB APP_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_executable(${APP_NAME} ${APP_SOURCES})
add_dependencies(${APP_NAME} ${LIB_NAME})
target_sources(${APP_NAME} PRIVATE ${TEST_VECTORS_SRC})
target_include_directories(${APP_NAME} PRIVATE ${TEST_INCLUDE_PATH})
target_link_libraries(${APP_NAME} ${LIB_NAME} OpenSSL::Crypto)
