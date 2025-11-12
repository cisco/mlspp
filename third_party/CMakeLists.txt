###
### Build third-party library
###
set(CURRENT_LIB_NAME third_party)

add_library(${CURRENT_LIB_NAME} INTERFACE)
target_include_directories(${CURRENT_LIB_NAME}
  INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}>
)

###
### Install
###

install(TARGETS ${CURRENT_LIB_NAME} EXPORT mlspp-targets)
install(FILES variant.hpp 
        DESTINATION
            ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})

###
### Build liboqs if required
###

if(MLSPP_USING_LIBOQS)
  # TODO(RLB) Configure options so that we don't build everything
  add_subdirectory(liboqs)
endif()
