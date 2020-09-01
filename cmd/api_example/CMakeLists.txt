set(APP_NAME "api_example")

file(GLOB APP_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_executable(${APP_NAME} ${APP_SOURCES})
add_dependencies(${APP_NAME} ${LIB_NAME})
target_link_libraries(${APP_NAME} ${LIB_NAME} OpenSSL::Crypto)
