set(APP_NAME "test_gen")
set(APP_SRC_PATH "${PROJECT_SOURCE_DIR}/cmd/test_gen")

include_directories(${LIBRARY_INCLUDE_PATH})
include_directories(${LIBRARY_PRIVATE_INCLUDE_PATH})

file(GLOB APP_SOURCE_FILES "${APP_SRC_PATH}/*.cpp")
set(APP_SOURCE_FILES ${APP_SOURCE_FILES} PARENT_SCOPE)

add_executable(${APP_NAME} ${APP_SOURCE_FILES})
target_link_libraries(${APP_NAME} ${OPENSSL_LIBRARIES})
target_link_libraries(${APP_NAME} ${LIB_NAME})
