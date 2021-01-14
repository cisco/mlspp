cmake_minimum_required(VERSION 3.12)

project(mlspp
  VERSION 0.1
  LANGUAGES CXX
)

option(CLANG_TIDY "Perform linting with clang-tidy" OFF)
option(SANITIZERS "Enable sanitizers" OFF)

###
### Global Config
###
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

include(CheckCXXCompilerFlag)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  add_compile_options(-Wall -pedantic -Wextra -Werror -Wmissing-declarations)
elseif(MSVC)
  add_compile_options(/W4 /WX)
endif()

if (SANITIZERS AND (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU"))
  set (SANITIZERS "-fsanitize=address -fsanitize=undefined")
  set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS}             ${SANITIZERS}")
  set (CMAKE_CXX_FLAGS            "${CMAKE_CXX_FLAGS}           ${SANITIZERS}")
  set (CMAKE_EXE_LINKER_FLAGS     "${CMAKE_EXE_LINKER_FLAGS}    ${SANITIZERS}")
  set (CMAKE_SHARED_LINKER_FLAGS  "${CMAKE_SHARED_LINKER_FLAGS} ${SANITIZERS}")
  set (CMAKE_MODULE_LINKER_FLAGS  "${CMAKE_MODULE_LINKER_FLAGS} ${SANITIZERS}")
endif()

if(CLANG_TIDY)
  find_program(CLANG_TIDY_EXE NAMES "clang-tidy")
  if(CLANG_TIDY_EXE)
    set(CMAKE_CXX_CLANG_TIDY  ${CLANG_TIDY_EXE})
  else()
    message(WARNING "clang-tidy requested, but not found")
  endif()
endif()

###
### Enable testing
###
enable_testing()

###
### Dependencies
###

# Internal libraries
add_subdirectory(lib)

# External libraries
find_package(OpenSSL 1.1 REQUIRED)

# mpark-variant fetched from GitHub
include( ExternalProject )
find_package( Git REQUIRED )
set( MPARK_VARIANT_URL https://github.com/mpark/variant.git )
set_directory_properties( PROPERTIES EP_PREFIX ${CMAKE_BINARY_DIR}/third_party )

ExternalProject_Add(
    mpark-variant-extern
    GIT_REPOSITORY ${MPARK_VARIANT_URL}
    TIMEOUT 10
    UPDATE_COMMAND ${GIT_EXECUTABLE} pull
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    LOG_DOWNLOAD ON
   )

ExternalProject_Get_Property( mpark-variant-extern SOURCE_DIR )
set( MPARK_VARIANT_INCLUDE_DIR ${SOURCE_DIR}/include CACHE INTERNAL "Include folder for mpark-variant" )

add_library( mpark-variant INTERFACE )
add_dependencies(mpark-variant mpark-variant-extern)
target_include_directories( mpark-variant INTERFACE ${MPARK_VARIANT_INCLUDE_DIR} )

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
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}-${PROJECT_VERSION}>
  PRIVATE
    ${OPENSSL_INCLUDE_DIR}
)

###
### Tests
###
add_subdirectory(test)

###
### Applications
###

add_subdirectory(cmd)


###
### Exports
###
set(CMAKE_EXPORT_PACKAGE_REGISTRY ON)
export(TARGETS mlspp tls_syntax hpke bytes mls_vectors mpark-variant NAMESPACE MLSPP:: FILE MLSPPConfig.cmake)
export(PACKAGE MLSPP)
