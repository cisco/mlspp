# This is just a convenience Makefile to avoid having to remember
# all the CMake commands and their arguments.

# choose: Ninja, Unix Makefiles, Xcode
BUILD_DIR=build
CLANG_FORMAT=clang-format -i -style=mozilla

TEST_VECTOR_DIR=./build/test
TEST_GEN=./build/cmd/test_gen/test_gen

.PHONY: all lint test gen gen_debug example clean cclean format

all: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target mlspp

${BUILD_DIR}: CMakeLists.txt test/CMakeLists.txt cmd/CMakeLists.txt
	cmake -H. -B${BUILD_DIR} -DCMAKE_BUILD_TYPE=Debug

test: ${BUILD_DIR} test/*
	cmake --build ${BUILD_DIR} --target mlspp_test
	cd ${TEST_VECTOR_DIR} && ctest

gen: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target test_gen
	mkdir -p ${TEST_VECTOR_DIR}
	cd ${TEST_VECTOR_DIR} && ../../${TEST_GEN}

example: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target api_example
	./build/cmd/api_example/api_example

clean:
	cmake --build ${BUILD_DIR} --target clean

cclean:
	rm -rf ${BUILD_DIR}

format:
	find src -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find test -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find cmd -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
