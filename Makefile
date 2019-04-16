# This is just a convenience Makefile to avoid having to remember
# all the CMake commands and their arguments.

BUILD_DIR=build
CLANG_FORMAT=clang-format -i -style=mozilla

TEST_VECTOR_DIR=third_party/mls-implementations/test_vectors
TEST_GEN=./build/cmd/test_gen/test_gen

all: ${BUILD_DIR} format src/* test/*
	cmake --build ${BUILD_DIR}

${BUILD_DIR}: CMakeLists.txt test/CMakeLists.txt cmd/CMakeLists.txt
	cmake -H. -B${BUILD_DIR} -DCMAKE_BUILD_TYPE=Debug

test: all
	cd ${BUILD_DIR} && ctest -V -R OneMem

gen: all
	cd ${TEST_VECTOR_DIR} && ../../../${TEST_GEN}

clean:
	rm -rf ${BUILD_DIR}

format:
	find src -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find test -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find cmd -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
