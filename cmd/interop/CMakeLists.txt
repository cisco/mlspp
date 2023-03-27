cmake_minimum_required(VERSION 3.12.1)

project(MLSInterop CXX)

option(SANITIZERS "Enable sanitizers" OFF)

###
### Global Config
###

set(APP_NAME "mlspp_client")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  # XXX(RLB) -Wmissing-declarations causes gRPC generated code not to build
  add_compile_options(-Wall -pedantic -Wextra -Werror)
elseif(MSVC)
  # XXX(RLB) Protobuf and gRPC cannot build with these additional errors enabled
  # add_compile_options(/W4 /WX)
endif()

if (SANITIZERS AND (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU"))
  set (SANITIZERS "-fsanitize=address -fsanitize=undefined")
  set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS}             ${SANITIZERS}")
  set (CMAKE_CXX_FLAGS            "${CMAKE_CXX_FLAGS}           ${SANITIZERS}")
  set (CMAKE_EXE_LINKER_FLAGS     "${CMAKE_EXE_LINKER_FLAGS}    ${SANITIZERS}")
  set (CMAKE_SHARED_LINKER_FLAGS  "${CMAKE_SHARED_LINKER_FLAGS} ${SANITIZERS}")
  set (CMAKE_MODULE_LINKER_FLAGS  "${CMAKE_MODULE_LINKER_FLAGS} ${SANITIZERS}")
endif()

###
### Dependencies
###
find_package(OpenSSL 1.1 REQUIRED)

# gRPC dependencies
find_package(Protobuf REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(gflags REQUIRED)

# mlspp
set(CMAKE_EXPORT_PACKAGE_REGISTRY ON)
find_package(MLSPP REQUIRED)

# JSON
find_package(nlohmann_json 3.2 REQUIRED)

###
### Protobuf generation
###

# Get the proto file from the interop repo 
include( ExternalProject )
find_package( Git REQUIRED )
set( MLS_IMPLEMENTATIONS_REPO_URL https://github.com/mlswg/mls-implementations.git )
set_directory_properties( PROPERTIES EP_PREFIX ${CMAKE_BINARY_DIR}/third_party )

ExternalProject_Add(
    mls-interop-extern
    GIT_REPOSITORY ${MLS_IMPLEMENTATIONS_REPO_URL}
    GIT_TAG origin/main
    TIMEOUT 10
    UPDATE_COMMAND ${GIT_EXECUTABLE} pull origin main
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    LOG_DOWNLOAD ON
   )

ExternalProject_Get_Property(mls-interop-extern SOURCE_DIR)
set(PROTO_PATH ${SOURCE_DIR}/interop/proto CACHE INTERNAL "Folder for .proto data")

# Generate .h and .cc files from the proto file
set(PROTO "mls_client")
get_filename_component(PROTO_FILE "${PROTO_PATH}/${PROTO}.proto" ABSOLUTE)

set(PB_SRC "${CMAKE_CURRENT_BINARY_DIR}/${PROTO}.pb.cc")
set(PB_HDR "${CMAKE_CURRENT_BINARY_DIR}/${PROTO}.pb.h")
set(GRPC_SRC "${CMAKE_CURRENT_BINARY_DIR}/${PROTO}.grpc.pb.cc")
set(GRPC_HDR "${CMAKE_CURRENT_BINARY_DIR}/${PROTO}.grpc.pb.h")
find_program(PROTOBUF_PROTOC protoc)
find_program(GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)

add_custom_command(
      OUTPUT "${PB_SRC}" "${PB_HDR}" "${GRPC_SRC}" "${GRPC_HDR}"
      COMMAND ${PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${PROTO_PATH}"
        --plugin=protoc-gen-grpc="${GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${PROTO_FILE}"
      DEPENDS mls-interop-extern)

###
### GRPC Executable
###
file(GLOB_RECURSE BIN_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
add_executable(${APP_NAME} ${BIN_SOURCES} ${PB_SRC} ${GRPC_SRC})
add_dependencies(${APP_NAME} mls-interop-extern)
target_include_directories(${APP_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(${APP_NAME} 
  gflags 
  gRPC::grpc++ protobuf::libprotobuf 
  MLSPP::mlspp MLSPP::mls_vectors MLSPP::tls_syntax)
