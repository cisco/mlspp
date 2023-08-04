cmake_minimum_required(VERSION 3.12)

project(mlspp
  VERSION 0.1
  LANGUAGES CXX
)

option(TESTING    "Build tests" OFF)
option(CLANG_TIDY "Perform linting with clang-tidy" OFF)
option(SANITIZERS "Enable sanitizers" OFF)

###
### Global Config
###
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

include(CheckCXXCompilerFlag)
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  add_compile_options(-Wall -pedantic -Wextra -Werror -Wmissing-declarations)
elseif(MSVC)
  add_compile_options(/W4 /WX)

  # MSVC helpfully recommends safer equivalents for things like
  # getenv, but they are not portable.
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)  
endif()

if (SANITIZERS)
  if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    set(SANITIZERS "-fsanitize=address -fsanitize=undefined")
  elseif(MSVC)
    set(SANITIZERS "/fsanitize=address")
  endif()

  set(CMAKE_C_FLAGS              "${CMAKE_C_FLAGS}             ${SANITIZERS}")
  set(CMAKE_CXX_FLAGS            "${CMAKE_CXX_FLAGS}           ${SANITIZERS}")
  set(CMAKE_EXE_LINKER_FLAGS     "${CMAKE_EXE_LINKER_FLAGS}    ${SANITIZERS}")
  set(CMAKE_SHARED_LINKER_FLAGS  "${CMAKE_SHARED_LINKER_FLAGS} ${SANITIZERS}")
  set(CMAKE_MODULE_LINKER_FLAGS  "${CMAKE_MODULE_LINKER_FLAGS} ${SANITIZERS}")
  add_definitions(-DSANITIZERS)
elseif (SANITIZERS AND MSVC)
  message("Enabling sanitizers")
  add_definitions("/fsanitize=address")
endif()

if(CLANG_TIDY)
  find_program(CLANG_TIDY_EXE NAMES "clang-tidy")
  if(CLANG_TIDY_EXE)
    set(CMAKE_CXX_CLANG_TIDY  ${CLANG_TIDY_EXE})
  else()
    message(WARNING "clang-tidy requested, but not found")
  endif()
endif()

if("$ENV{MACOSX_DEPLOYMENT_TARGET}" STREQUAL "10.11")
  add_compile_options(-DVARIANT_COMPAT)
endif()

###
### Enable testing
###
if(TESTING)
  enable_testing()
endif()

###
### Dependencies
###

# External libraries
find_package(OpenSSL REQUIRED)
if ( OPENSSL_FOUND )
    if (${OPENSSL_VERSION} VERSION_GREATER_EQUAL 3)
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

# Internal libraries
add_subdirectory(lib)

# Third-Party libraries in tree
add_subdirectory(third_party)


###
### Library Config
###

set(LIB_NAME "${PROJECT_NAME}")

file(GLOB_RECURSE LIB_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
file(GLOB_RECURSE LIB_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(${LIB_NAME} ${LIB_HEADERS} ${LIB_SOURCES})
add_dependencies(${LIB_NAME} bytes tls_syntax hpke)
target_link_libraries(${LIB_NAME} bytes tls_syntax hpke)
target_include_directories(${LIB_NAME}
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}>
  PRIVATE
    ${OPENSSL_INCLUDE_DIR}
)

###
### Tests
###
if(TESTING)
  add_subdirectory(test)
endif()

###
### Exports
###
set(CMAKE_EXPORT_PACKAGE_REGISTRY ON)
export(EXPORT mlspp-targets 
       NAMESPACE MLSPP::
       FILE ${CMAKE_CURRENT_BINARY_DIR}/mlspp-targets.cmake)
export(PACKAGE MLSPP)

configure_package_config_file(cmake/config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/mlspp-config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_DATADIR}/mlspp
  NO_SET_AND_CHECK_MACRO)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/mlspp-config-version.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

###
### Install
###

install(TARGETS ${LIB_NAME} EXPORT mlspp-targets)

install(
  DIRECTORY
    include/
  DESTINATION
    ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})

install(
  FILES
    ${CMAKE_CURRENT_BINARY_DIR}/mlspp-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/mlspp-config-version.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/mlspp-targets.cmake
  DESTINATION
    ${CMAKE_INSTALL_DATADIR}/mlspp)

