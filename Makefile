# This is just a convenience Makefile to avoid having to remember
# all the CMake commands and their arguments.

# choose: Ninja, Unix Makefiles, Xcode
GENERATOR=Ninja
BUILD_DIR=build
CLANG_FORMAT=clang-format -i -style=mozilla

TEST_VECTOR_DIR=./build/test
TEST_GEN=./build/cmd/test_gen/test_gen

.PHONY: all lint test gen gen_debug example clean cclean format

all: ${BUILD_DIR} ${TEST_VECTOR_DIR} format src/* include/** test/*
	cmake --build ${BUILD_DIR}

test: ${BUILD_DIR} test/*
	cmake --build ${BUILD_DIR} --target mlspp_test
	cd ${TEST_VECTOR_DIR} && ctest

${TEST_VECTOR_DIR}:
	mkdir -p ${TEST_VECTOR_DIR}

${BUILD_DIR}: CMakeLists.txt test/CMakeLists.txt cmd/CMakeLists.txt
	cmake -H. -G "${GENERATOR}" -B${BUILD_DIR} -DMLSPP_LINT=${MLSPP_LINT} -DCMAKE_BUILD_TYPE=Debug

lint:
	cmake -H. -B${BUILD_DIR} -DMLSPP_LINT=ON -DCMAKE_BUILD_TYPE=Debug

gen: all ${TEST_VECTOR_DIR}
	cd ${TEST_VECTOR_DIR} && ../../${TEST_GEN}

example: all
	./build/cmd/api_example/api_example

clean:
	cd ${BUILD_DIR} && ninja clean

cclean:
	rm -rf ${BUILD_DIR}

format:
	find src -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find test -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find cmd -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
