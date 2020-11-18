set(CURRENT_LIB_NAME hpke)

###
### Dependencies
###
if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    find_package(OpenSSL)
    IF (${OpenSSL_FOUND})
        MESSAGE(STATUS "Found OpenSSL on Darwin")
    ELSE (${OpenSSL_FOUND})
        MESSAGE(STATUS "Could not locate OpenSSL on Darwin. Setting OPENSSL_ROOT_DIR to /usr/local/opt/openssl")
        set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl")
    ENDIF (${OpenSSL_FOUND})
endif()
find_package(OpenSSL 1.1 REQUIRED)

###
### Library Config
###

file(GLOB_RECURSE LIB_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
file(GLOB_RECURSE LIB_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(${CURRENT_LIB_NAME} ${LIB_HEADERS} ${LIB_SOURCES})
add_dependencies(${CURRENT_LIB_NAME} bytes)
target_link_libraries(${CURRENT_LIB_NAME} PRIVATE bytes OpenSSL::Crypto)
target_include_directories(${CURRENT_LIB_NAME}
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

###
### Tests
###

add_subdirectory(test)
