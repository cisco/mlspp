# This is just a convenience Makefile to avoid having to remember
# all the CMake commands and their arguments.

# Set CMAKE_GENERATOR in the environment to select how you build, e.g.:
#   CMAKE_GENERATOR=Ninja

BUILD_DIR=build
TEST_DIR=build/test
CLANG_FORMAT=clang-format -i

.PHONY: all tidy test libs test-libs test-all example everything clean cclean format

all: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target mlspp

${BUILD_DIR}: CMakeLists.txt test/CMakeLists.txt cmd/CMakeLists.txt
	cmake -B${BUILD_DIR} -DCMAKE_BUILD_TYPE=Debug .

tidy:
	cmake -B${BUILD_DIR} -DCLANG_TIDY=ON -DCMAKE_BUILD_TYPE=Debug .

test: ${BUILD_DIR} test/*
	cmake --build ${BUILD_DIR} --target mlspp_test

dtest: test
	${TEST_DIR}/mlspp_test

dbtest: test
	lldb ${TEST_DIR}/mlspp_test

ctest: test
	cd ${TEST_DIR} && ctest

libs: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target bytes
	cmake --build ${BUILD_DIR} --target hpke
	cmake --build ${BUILD_DIR} --target tls_syntax
	cmake --build ${BUILD_DIR} --target mls_vectors 

test-libs: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target bytes_test
	cd build/lib/bytes/test/ && ctest
	cmake --build ${BUILD_DIR} --target hpke_test
	cd build/lib/hpke/test/ && ctest
	cmake --build ${BUILD_DIR} --target tls_syntax_test
	cd build/lib/tls_syntax/test/ && ctest
	cmake --build ${BUILD_DIR} --target mls_vectors_test
	cd build/lib/mls_vectors/test/ && ctest

test-all: test-libs ctest

example: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target api_example
	./build/cmd/api_example/api_example

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
	find lib -iname "*.h" -or -iname "*.cpp" |  xargs ${CLANG_FORMAT}
