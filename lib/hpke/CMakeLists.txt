set(CURRENT_LIB_NAME hpke)

###
### Dependencies
###
find_package(nlohmann_json REQUIRED)
find_package(OpenSSL 1.1 REQUIRED)

###
### Library Config
###

file(GLOB_RECURSE LIB_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
file(GLOB_RECURSE LIB_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

# https://gitlab.kitware.com/cmake/cmake/-/issues/15415#note_334852
# Warning: this will fail once nlohman_json stops being header-only!
get_target_property(JSON_INCLUDE_INTERFACE nlohmann_json::nlohmann_json INTERFACE_INCLUDE_DIRECTORIES)

add_library(${CURRENT_LIB_NAME} ${LIB_HEADERS} ${LIB_SOURCES})
add_dependencies(${CURRENT_LIB_NAME} bytes tls_syntax)
target_include_directories(${CURRENT_LIB_NAME}
  PRIVATE
    "${JSON_INCLUDE_INTERFACE}")

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
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}>
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
