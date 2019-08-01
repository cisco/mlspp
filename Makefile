# This is just a convenience Makefile to avoid having to remember
# all the CMake commands and their arguments.

BUILD_DIR=build
CLANG_FORMAT=clang-format -i -style=mozilla

TEST_VECTOR_DIR=./build/test/vectors
TEST_GEN=./build/cmd/test_gen/test_gen

all: ${BUILD_DIR} format src/* test/*
	cmake --build ${BUILD_DIR}

${BUILD_DIR}: CMakeLists.txt test/CMakeLists.txt cmd/CMakeLists.txt
	cmake -H. -B${BUILD_DIR} -DMLSPP_LINT=${MLSPP_LINT} -DCMAKE_BUILD_TYPE=Debug

test: all
	cd ${BUILD_DIR} && ctest

gen: all
	mkdir -p ${TEST_VECTOR_DIR}
	cd ${TEST_VECTOR_DIR} && ../../../${TEST_GEN}

clean:
	rm -rf ${BUILD_DIR}

format:
	find src -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find test -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find cmd -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
