set(CURRENT_LIB_NAME hpke)

###
### Dependencies
###
find_package(OpenSSL 1.1 REQUIRED)

###
### Library Config
###

file(GLOB_RECURSE LIB_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
file(GLOB_RECURSE LIB_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(${CURRENT_LIB_NAME} ${LIB_HEADERS} ${LIB_SOURCES})
add_dependencies(${CURRENT_LIB_NAME} bytes tls_syntax)
target_link_libraries(${CURRENT_LIB_NAME} PRIVATE bytes tls_syntax OpenSSL::Crypto)
target_include_directories(${CURRENT_LIB_NAME}
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

###
### Tests
###

add_subdirectory(test)
