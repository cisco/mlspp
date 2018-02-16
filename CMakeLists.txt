###
### Environment Config
###

cmake_minimum_required(VERSION 3.3)

project(mls)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(third_party EXCLUDE_FROM_ALL)

find_package(OpenSSL REQUIRED)

MESSAGE( STATUS "OPENSSL_INCLUDE_DIR: " ${OPENSSL_INCLUDE_DIR} )

###
### Library Config
### 

set(LIB_NAME "${PROJECT_NAME}")

set(LIBRARY_SRC_PATH  "${PROJECT_SOURCE_DIR}/src" )
set(LIBRARY_INCLUDE_PATH  "${PROJECT_SOURCE_DIR}/include")
set(LIBRARY_PRIVATE_INCLUDE_PATH "${LIBRARY_SRC_PATH}/include")

include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${LIBRARY_INCLUDE_PATH})
include_directories(${LIBRARY_PRIVATE_INCLUDE_PATH})

file(GLOB LIB_HEADER_FILES "${LIBRARY_INCLUDE_PATH}/*.h")
file(GLOB LIB_SOURCE_FILES "${LIBRARY_SRC_PATH}/*.cpp")

add_library(${LIB_NAME} STATIC ${LIB_SOURCE_FILES} ${LIB_HEADER_FILES})

###
### Test Config
### 

enable_testing()
add_subdirectory(test)
