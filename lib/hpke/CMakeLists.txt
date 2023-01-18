set(CURRENT_LIB_NAME hpke)

###
### Dependencies
###
find_package(OpenSSL REQUIRED)
if ( OPENSSL_FOUND )
    if (${OPENSSL_VERSION} VERSION_GREATER 1.1.1)
        add_compile_definitions(WITH_OPENSSL3)
    elseif(${OPENSSL_VERSION} VERSION_LESS 1.1.1)
        message(FATAL_ERROR "OpenSSL 1.1.1 or greater is required")
    endif()
    message(STATUS "OpenSSL Found: ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL Include: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL Libraries: ${OPENSSL_LIBRARIES}")
else()
    message(FATAL_ERROR "No OpenSSL library found")
endif()

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

if (TESTING)
  add_subdirectory(test)
endif()
