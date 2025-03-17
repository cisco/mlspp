set(CURRENT_LIB_NAME hpke)

###
### Library Config
###

file(GLOB_RECURSE LIB_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
file(GLOB_RECURSE LIB_GENERATED_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/include/*.h")
file(GLOB_RECURSE LIB_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
add_library(${CURRENT_LIB_NAME} ${LIB_HEADERS} ${LIB_GENERATED_HEADERS} ${LIB_SOURCES})
add_dependencies(${CURRENT_LIB_NAME} bytes tls_syntax)

###
### Dependencies
###

# JSON.
find_package(nlohmann_json REQUIRED)
# https://gitlab.kitware.com/cmake/cmake/-/issues/15415#note_334852
# Warning: this will fail once nlohman_json stops being header-only!
get_target_property(JSON_INCLUDE_INTERFACE nlohmann_json::nlohmann_json INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories(${CURRENT_LIB_NAME} PRIVATE "${JSON_INCLUDE_INTERFACE}")

# OpenSSL.
find_package(OpenSSL REQUIRED)
if ( OPENSSL_FOUND )
    find_path(BORINGSSL_INCLUDE_DIR openssl/is_boringssl.h HINTS ${OPENSSL_INCLUDE_DIR} NO_DEFAULT_PATH)

    if (BORINGSSL_INCLUDE_DIR)
      message(STATUS "Found OpenSSL includes are for BoringSSL")
      target_compile_definitions(${CURRENT_LIB_NAME} PUBLIC WITH_BORINGSSL)

      if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        add_compile_options(-Wno-gnu-anonymous-struct -Wno-nested-anon-types)
      endif ()

      file(STRINGS "${OPENSSL_INCLUDE_DIR}/openssl/crypto.h" boringssl_version_str
           REGEX "^#[\t ]*define[\t ]+OPENSSL_VERSION_TEXT[\t ]+\"OpenSSL ([0-9])+\\.([0-9])+\\.([0-9])+ .+")

      string(REGEX REPLACE "^.*OPENSSL_VERSION_TEXT[\t ]+\"OpenSSL ([0-9]+\\.[0-9]+\\.[0-9])+ .+$"
             "\\1" OPENSSL_VERSION "${boringssl_version_str}")

    elseif (REQUIRE_BORINGSSL)
      message(FATAL_ERROR "BoringSSL required but not found")
    endif ()

    if (${OPENSSL_VERSION} VERSION_GREATER_EQUAL 3)
      target_compile_definitions(${CURRENT_LIB_NAME} PUBLIC WITH_OPENSSL3)
    elseif(${OPENSSL_VERSION} VERSION_LESS 1.1.1)
      message(FATAL_ERROR "OpenSSL 1.1.1 or greater is required")
    endif()
    message(STATUS "OpenSSL Found: ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL Include: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL Libraries: ${OPENSSL_LIBRARIES}")
else()
  message(FATAL_ERROR "No OpenSSL library found")
endif()

target_link_libraries(${CURRENT_LIB_NAME} 
  PUBLIC
    bytes tls_syntax
  PRIVATE
    OpenSSL::Crypto
)

target_include_directories(${CURRENT_LIB_NAME}
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}>
  PRIVATE
    ${OPENSSL_INCLUDE_DIR}
)

###
### Install
###

install(TARGETS ${CURRENT_LIB_NAME} EXPORT mlspp-targets)
install(
  DIRECTORY
    include/
  DESTINATION
    ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
)

###
### Tests
###

if (TESTING)
  add_subdirectory(test)
endif()
