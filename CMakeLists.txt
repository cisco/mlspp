cmake_minimum_required(VERSION 3.12)
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})


###
###  Semantic versioning
###
include ( GetGitRevisionDescription )
git_describe(VERSION --tags --dirty=-d)
string(REGEX REPLACE "^v([0-9]+)\\..*" "\\1" MLSPP_VERSION_MAJOR "${VERSION}")
string(REGEX REPLACE "^v[0-9]+\\.([0-9]+).*" "\\1" MLSPP_VERSION_MINOR "${VERSION}")
string(REGEX REPLACE "^v[0-9]+\\.[0-9]+\\.([0-9]+).*" "\\1" MLSPP_VERSION_PATCH "${VERSION}")
string(REGEX REPLACE "^v[0-9]+\\.[0-9]+\\.[0-9]+(.*)" "\\1" MLSPP_VERSION_SHA1 "${VERSION}")
mark_as_advanced(MLSPP_VERSION_MAJOR MLSPP_VERSION_MINOR MLSPP_VERSION_PATCH)
set ( MLSPP_VERSION "${MLSPP_VERSION_MAJOR}.${MLSPP_VERSION_MINOR}.${MLSPP_VERSION_PATCH}" )
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.c.in
        ${CMAKE_CURRENT_BINARY_DIR}/version.cpp)
set(version_file "${CMAKE_CURRENT_BINARY_DIR}/version.cpp")

project(mlspp
        VERSION "${MLSPP_VERSION}"
        LANGUAGES CXX
)

option(CLANG_TIDY "Perform linting with clang-tidy" OFF)
option(ADDRESS_SANITIZER "Enable address sanitizer" OFF)

###
### Global Config
###
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

include(CheckCXXCompilerFlag)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  add_compile_options(-Wall -pedantic -Wextra -Werror -Wmissing-declarations)
  check_cxx_compiler_flag(-Wextra-semi COMPILER_SUPPORTS_EXTRA_SEMI_WARNING)
  if (COMPILER_SUPPORTS_EXTRA_SEMI_WARNING)
      add_compile_options("-Wextra-semi")
  endif()
elseif(MSVC)
  add_compile_options(/W4 /WX)
endif()

if (ADDRESS_SANITIZER)
  set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} -fsanitize=address")
  set (CMAKE_CXX_FLAGS            "${CMAKE_CXX_FLAGS} -fsanitize=address")
  set (CMAKE_EXE_LINKER_FLAGS     "${CMAKE_EXE_LINKER_FLAGS}    -fsanitize=address")
  set (CMAKE_SHARED_LINKER_FLAGS  "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=address")
  set (CMAKE_MODULE_LINKER_FLAGS  "${CMAKE_MODULE_LINKER_FLAGS} -fsanitize=address")
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
### Dependencies
###

# Internal libraries
add_subdirectory(lib)

# External libraries
find_package(OpenSSL 1.1 REQUIRED)

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
###  Library packaging and install
###
#include ( CPack )
set ( dist_dir    ${CMAKE_BINARY_DIR}/dist )
set ( prefix      ${CMAKE_INSTALL_PREFIX} )
set ( exec_prefix ${CMAKE_INSTALL_PREFIX}/bin )
set ( libdir      ${CMAKE_INSTALL_PREFIX}/lib )
set ( includedir  ${CMAKE_INSTALL_PREFIX}/include )
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/libmlspp.pc.in
        ${CMAKE_CURRENT_BINARY_DIR}/libmlspp.pc @ONLY)
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/libmlspp.pc DESTINATION lib/pkgconfig )

install ( TARGETS ${LIB_NAME}
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin)


add_subdirectory(include)


###
### Tests
###

add_subdirectory(test)

###
### Applications
###

add_subdirectory(cmd)
