###
### Environment Config
###

cmake_minimum_required(VERSION 3.3)

project(mls)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(third_party EXCLUDE_FROM_ALL)

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
target_link_libraries(mls ${OPENSSL_LIBRARIES})

###
### Test Config
###

enable_testing()
add_subdirectory(gtest)
