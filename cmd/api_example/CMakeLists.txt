set(APP_NAME "api_example")
set(APP_SRC_PATH "${PROJECT_SOURCE_DIR}/cmd/api_example")

file(GLOB APP_SOURCE_FILES "${APP_SRC_PATH}/*.cpp")
set(APP_SOURCE_FILES ${APP_SOURCE_FILES} PARENT_SCOPE)

add_executable(${APP_NAME} ${APP_SOURCE_FILES})
target_include_directories(${APP_NAME} PRIVATE ${LIBRARY_INCLUDE_PATH}
                                       PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(${APP_NAME} ${OPENSSL_LIBRARIES})
target_link_libraries(${APP_NAME} ${LIB_NAME})
