set(APP_NAME "public_api")
set(APP_SRC_PATH "${PROJECT_SOURCE_DIR}/cmd/public_api")

include_directories(${LIBRARY_INCLUDE_PATH})

message("including ${LIBRARY_INCLUDE_PATH}")

file(GLOB APP_SOURCE_FILES "${APP_SRC_PATH}/*.cpp")
set(APP_SOURCE_FILES ${APP_SOURCE_FILES} PARENT_SCOPE)

add_executable(${APP_NAME} ${APP_SOURCE_FILES})
target_link_libraries(${APP_NAME} ${OPENSSL_LIBRARIES})
target_link_libraries(${APP_NAME} ${LIB_NAME})
