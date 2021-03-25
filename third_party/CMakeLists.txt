set(CURRENT_LIB_NAME third_party)

add_library(${CURRENT_LIB_NAME} INTERFACE)
target_include_directories(${CURRENT_LIB_NAME}
  INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
)
