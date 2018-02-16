###
### Make Catch visible to the test module
###

set(THIRD_PARTY_MODULE_PATH "${PROJECT_SOURCE_DIR}/third_party")
set(CATCH_MODULE_PATH "${THIRD_PARTY_MODULE_PATH}/Catch")
set(CATCH_INCLUDE_PATH "${CATCH_MODULE_PATH}/single_include")

include("${CATCH_MODULE_PATH}/contrib/ParseAndAddCatchTests.cmake")

set(TEST_THIRD_PARTY_INCLUDE_PATH  ${CATCH_INCLUDE_PATH} PARENT_SCOPE)
