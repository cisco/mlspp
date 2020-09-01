# This is just a convenience Makefile to avoid having to remember
# all the CMake commands and their arguments.

# Set CMAKE_GENERATOR to choose how you build, e.g.:
#   CMAKE_GENERATOR=Ninja

BUILD_DIR=build
CLANG_FORMAT=clang-format -i

TEST_VECTOR_DIR=./build/test/vectors
TEST_RUN=./build/test/mlspp_gtest
TEST_GEN=./build/cmd/test_gen/test_gen

.PHONY: all lint test gen gen_debug example clean cclean format

all: ${BUILD_DIR} ${TEST_VECTOR_DIR} src/* include/** test/*
	cmake --build ${BUILD_DIR}

${TEST_VECTOR_DIR}:
	mkdir -p ${TEST_VECTOR_DIR}

${BUILD_DIR}: CMakeLists.txt test/CMakeLists.txt cmd/CMakeLists.txt
	cmake -H. -B${BUILD_DIR} -DMLSPP_LINT=${MLSPP_LINT} -DCMAKE_BUILD_TYPE=Debug

lint:
	cmake -H. -B${BUILD_DIR} -DMLSPP_LINT=ON -DCMAKE_BUILD_TYPE=Debug

test: all ${TEST_VECTOR_DIR}
	cd ${BUILD_DIR} && ctest

test_debug:
	cd ${TEST_VECTOR_DIR} && lldb ../../../${TEST_RUN}

gen: all ${TEST_VECTOR_DIR}
	cd ${TEST_VECTOR_DIR} && ../../../${TEST_GEN}

gen_debug:
	cd ${TEST_VECTOR_DIR} && lldb ../../../${TEST_GEN}

example: all
	./build/cmd/api_example/api_example

clean:
	cd ${BUILD_DIR} && ninja clean

cclean:
	rm -rf ${BUILD_DIR}

format:
	find include -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find src -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find test -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find cmd -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
