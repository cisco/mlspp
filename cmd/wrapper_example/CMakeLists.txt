set(APP_NAME "wrapper_example")

file(GLOB APP_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.c)
set(WRAPPER_INCLUDE_PATH  "${PROJECT_SOURCE_DIR}/wrapper/include")
set(WRAPPER_NAME "mlspp-c")

add_executable(${APP_NAME} ${APP_SOURCES})

add_dependencies(${APP_NAME} ${WRAPPER_NAME})
target_include_directories(${APP_NAME} PRIVATE ${WRAPPER_INCLUDE_PATH})
target_link_libraries(${APP_NAME} ${WRAPPER_NAME})
