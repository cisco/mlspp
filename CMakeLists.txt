###
### Environment Config
###

cmake_minimum_required(VERSION 3.3)

project(mls)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL
set(OPENSSL_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/third_party/openssl/include")
set(OPENSSL_LIBRARIES "${PROJECT_SOURCE_DIR}/third_party/openssl/libcrypto.a")

MESSAGE( STATUS "OPENSSL_INCLUDE_DIR: " ${OPENSSL_INCLUDE_DIR} )
MESSAGE( STATUS "OPENSSL_LIBRARIES: " ${OPENSSL_LIBRARIES} )

# Find GTest
set(GTEST_DIR "${PROJECT_SOURCE_DIR}/third_party/googletest/googletest")
set(GTEST_INCLUDE_DIR "${GTEST_DIR}/include")
set(GTEST_LIBRARY "${GTEST_DIR}/make/libgtest.a")
set(GTEST_MAIN_LIBRARY "${GTEST_DIR}/make/libgtest_main.a")

MESSAGE( STATUS "GTEST_INCLUDE_DIR: " ${GTEST_INCLUDE_DIR} )
MESSAGE( STATUS "GTEST_LIBRARY: " ${GTEST_LIBRARY} )
MESSAGE( STATUS "GTEST_MAIN_LIBRARY: " ${GTEST_MAIN_LIBRARY} )

option(MLSPP_LINT "Whether to run linters" ON)

if(NOT ${MLSPP_LINT} STREQUAL "OFF")
  # Find clang-tidy
  find_program(
    CLANG_TIDY_EXE
    NAMES "clang-tidy"
    DOC "Path to clang-tidy executable"
    )
  if(NOT CLANG_TIDY_EXE)
    message(STATUS "clang-tidy not found.")
  else()
    set(DO_CLANG_TIDY "${CLANG_TIDY_EXE}" "-checks=*,-clang-analyzer-alpha.*,-fuchsia-overloaded-operator")
  endif()
  
  # Enable pedantic mode
  # XXX(rlb@ipv.sx): I would include -Wextra here, but it fails on
  # gtest.  The right answer is probably just to apply -Werror to the
  # library and not to the tests, since the library is where these
  # things matter most.
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -Werror -Wshadow -pedantic-errors")
  
  # Enable ASan and UBSan (TSan not relevant; MSan Linux-only)
  set(DEBUG_FLAGS "-fPIE -fno-omit-frame-pointer -g")
  set(SANITIZERS "-fno-sanitize-recover=all -fsanitize=undefined -fsanitize=address") 
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${DEBUG_FLAGS} ${SANITIZERS}")
  set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} ${DEBUG_FLAGS} ${SANITIZERS}")
else()
  message(STATUS "Linters disabled!")
endif()

###
### Library Config
###

set(LIB_NAME "${PROJECT_NAME}")

set(LIBRARY_SRC_PATH  "${PROJECT_SOURCE_DIR}/src" )
set(LIBRARY_INCLUDE_PATH  "${PROJECT_SOURCE_DIR}/include/${PROJECT_NAME}")
set(LIBRARY_PRIVATE_INCLUDE_PATH "${PROJECT_SOURCE_DIR}/include/internal")

include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${LIBRARY_INCLUDE_PATH})
include_directories(${LIBRARY_PRIVATE_INCLUDE_PATH})

file(GLOB LIB_HEADER_FILES "${LIBRARY_INCLUDE_PATH}/*.h")
file(GLOB LIB_PRIVATE_HEADER_FILES "${LIBRARY_PRIVATE_INCLUDE_PATH}/*.h")
file(GLOB LIB_SOURCE_FILES "${LIBRARY_SRC_PATH}/*.cpp")

add_library(${LIB_NAME} STATIC ${LIB_SOURCE_FILES} ${LIB_HEADER_FILES})
target_link_libraries(${LIB_NAME} ${OPENSSL_LIBRARIES})

if(CLANG_TIDY_EXE)
  set_target_properties(
    ${LIB_NAME} PROPERTIES
    CXX_CLANG_TIDY "${DO_CLANG_TIDY}"
  )
endif()

###
### Tests
###

enable_testing()
add_subdirectory(test)


###
### Applications
###

add_subdirectory(cmd)
