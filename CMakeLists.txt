cmake_minimum_required(VERSION 3.13)

project(mlspp
  VERSION 0.1
  LANGUAGES CXX
)

option(TESTING    "Build tests" OFF)
option(CLANG_TIDY "Perform linting with clang-tidy" OFF)
option(SANITIZERS "Enable sanitizers" OFF)
option(MLS_NAMESPACE_SUFFIX "Namespace Suffix for CXX and CMake Export")
option(DISABLE_GREASE "Disables the inclusion of MLS protocol recommended GREASE values" OFF)
option(REQUIRE_BORINGSSL "Require BoringSSL instead of OpenSSL" OFF)

if(MLS_NAMESPACE_SUFFIX)
    set(MLS_CXX_NAMESPACE "mls_${MLS_NAMESPACE_SUFFIX}" CACHE STRING "Top-level Namespace for CXX")
    set(MLS_EXPORT_NAMESPACE "MLSPP${MLS_NAMESPACE_SUFFIX}" CACHE STRING "Namespace for CMake Export")
else()
    set(MLS_CXX_NAMESPACE "mls" CACHE STRING "Top-level Namespace for CXX")
    set(MLS_EXPORT_NAMESPACE "MLSPP" CACHE STRING "Namespace for CMake Export")
endif()
message(STATUS "CXX Namespace: ${MLS_CXX_NAMESPACE}")
message(STATUS "CMake Export Namespace: ${MLS_EXPORT_NAMESPACE}")


###
### Global Config
###
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/namespace.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/include/namespace.h"
  @ONLY
)

include(CheckCXXCompilerFlag)
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  add_compile_options(-Wall -pedantic -Wextra -Werror -Wmissing-declarations)
elseif(MSVC)
  add_compile_options(/W4 /WX)
  add_definitions(-DWINDOWS)

  # MSVC helpfully recommends safer equivalents for things like
  # getenv, but they are not portable.
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)  
endif()

if (SANITIZERS)
  message(STATUS "Enabling sanitizers")
  add_definitions(-DSANITIZERS)

  if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    add_compile_options(-fsanitize=address -fsanitize=undefined)
    add_link_options(-fsanitize=address -fsanitize=undefined)
  elseif(MSVC)
    # MSVC uses a different flag, and doesn't require passing it to the linker 
    add_compile_options("/fsanitize=address")
  endif()
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

if (DISABLE_GREASE)
  add_compile_options(-DDISABLE_GREASE)
endif ()

###
### Enable testing
###
if(TESTING)
  enable_testing()
  
  find_package(Catch2 3 REQUIRED)
  
  include(CTest)
  include(Catch)
endif()

###
### Dependencies
###

# Configure vcpkg to only build release libraries
set(VCPKG_BUILD_TYPE release)

# Internal libraries
add_subdirectory(lib)

# External libraries
find_package(nlohmann_json REQUIRED)

# Third-Party libraries in tree
add_subdirectory(third_party)


###
### Library Config
###

set(LIB_NAME "${PROJECT_NAME}")

file(GLOB_RECURSE LIB_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
file(GLOB_RECURSE LIB_GENERATED_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/include/*.h")
file(GLOB_RECURSE LIB_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(${LIB_NAME} ${LIB_HEADERS} ${LIB_GENERATED_HEADERS} ${LIB_SOURCES})
add_dependencies(${LIB_NAME} bytes tls_syntax hpke)
target_link_libraries(${LIB_NAME} 
  PRIVATE
    nlohmann_json::nlohmann_json
  PUBLIC
    bytes tls_syntax hpke)
target_include_directories(${LIB_NAME}
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}>
)

install(TARGETS ${LIB_NAME} EXPORT mlspp-targets)

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
export(
  EXPORT
    mlspp-targets
  NAMESPACE
    ${MLS_EXPORT_NAMESPACE}::
  FILE
    ${MLS_EXPORT_NAMESPACE}Targets.cmake)
export(PACKAGE ${MLS_EXPORT_NAMESPACE})

configure_package_config_file(cmake/config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/${MLS_EXPORT_NAMESPACE}Config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_DATADIR}/${MLS_EXPORT_NAMESPACE}
  NO_SET_AND_CHECK_MACRO)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/${MLS_EXPORT_NAMESPACE}ConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

###
### Install
###

install(
  EXPORT
    mlspp-targets
  NAMESPACE
    ${MLS_EXPORT_NAMESPACE}::
  FILE
    ${MLS_EXPORT_NAMESPACE}Targets.cmake
  DESTINATION
    ${CMAKE_INSTALL_DATADIR}/${MLS_EXPORT_NAMESPACE})

install(
  DIRECTORY
    ${CMAKE_CURRENT_SOURCE_DIR}/include/
    ${CMAKE_CURRENT_BINARY_DIR}/include/
  DESTINATION
    ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})

install(
  FILES
    ${CMAKE_CURRENT_BINARY_DIR}/${MLS_EXPORT_NAMESPACE}Config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/${MLS_EXPORT_NAMESPACE}ConfigVersion.cmake
  DESTINATION
    ${CMAKE_INSTALL_DATADIR}/${MLS_EXPORT_NAMESPACE})

install(
  FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE
  DESTINATION
    ${CMAKE_INSTALL_DATADIR}/${PROJECT_NAME}
  RENAME
    copyright)

