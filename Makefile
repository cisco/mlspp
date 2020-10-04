# This is just a convenience Makefile to avoid having to remember
# all the CMake commands and their arguments.

# Set CMAKE_GENERATOR in the environment to select how you build, e.g.:
#   CMAKE_GENERATOR=Ninja

BUILD_DIR=build
CLANG_FORMAT=clang-format -i

TEST_VECTOR_DIR=./build/test
TEST_GEN=./build/cmd/test_gen/test_gen

.PHONY: all tidy test libs test-libs test-all gen wrapper example everything clean cclean format

all: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target mlspp

${BUILD_DIR}: CMakeLists.txt test/CMakeLists.txt cmd/CMakeLists.txt
	cmake -B${BUILD_DIR} -DCMAKE_BUILD_TYPE=Debug .

tidy:
	cmake -B${BUILD_DIR} -DCLANG_TIDY=ON -DCMAKE_BUILD_TYPE=Debug .

test: ${BUILD_DIR} test/*
	cmake --build ${BUILD_DIR} --target mlspp_test
	cd ${TEST_VECTOR_DIR} && ctest

libs: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target bytes
	cmake --build ${BUILD_DIR} --target hpke
	cmake --build ${BUILD_DIR} --target tls_syntax

test-libs: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target hpke_test
	cd build/lib/hpke/test/ && ctest
	cmake --build ${BUILD_DIR} --target tls_syntax_test
	cd build/lib/tls_syntax/test/ && ctest

test-all: test-libs test

gen: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target test_gen
	mkdir -p ${TEST_VECTOR_DIR}
	cd ${TEST_VECTOR_DIR} && ../../${TEST_GEN}


wrapper: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target mlspp-c

example: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target api_example
	./build/cmd/api_example/api_example
	cmake --build ${BUILD_DIR} --target wrapper_example
	./build/cmd/wrapper_example/wrapper_example

everything: ${BUILD_DIR}
	cmake --build ${BUILD_DIR}

clean:
	cmake --build ${BUILD_DIR} --target clean

cclean:
	rm -rf ${BUILD_DIR}

format:
	find include -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find src -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find test -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find cmd -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find lib -iname "*.h" -or -iname "*.cpp" |  grep -v test-vectors.cpp | xargs ${CLANG_FORMAT}
