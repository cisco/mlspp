# This is just a convenience Makefile to avoid having to remember
# all the CMake commands and their arguments.

# Set CMAKE_GENERATOR in the environment to select how you build, e.g.:
#   CMAKE_GENERATOR=Ninja

BUILD_DIR=build
TEST_DIR=build/test
CLANG_FORMAT=clang-format -i
CLANG_TIDY=OFF

.PHONY: all dev test ctest dtest dbtest libs test-libs test-all everything ci clean cclean format

all: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target mlspp

${BUILD_DIR}: CMakeLists.txt test/CMakeLists.txt
	cmake -B${BUILD_DIR} .

dev:
	# Only enable testing, not clang-tidy/sanitizers; the latter make the build
	# too slow, and we can run them in CI
	cmake -B${BUILD_DIR} -DTESTING=ON -DCMAKE_BUILD_TYPE=Debug .

test: ${BUILD_DIR} test/*
	cmake --build ${BUILD_DIR} --target mlspp_test

dtest: test
	${TEST_DIR}/mlspp_test

dbtest: test
	lldb ${TEST_DIR}/mlspp_test

ctest: test
	cmake --build ${BUILD_DIR} --target test

libs: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target bytes
	cmake --build ${BUILD_DIR} --target hpke
	cmake --build ${BUILD_DIR} --target tls_syntax
	cmake --build ${BUILD_DIR} --target mls_vectors 

test-libs: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target lib/bytes/test
	cmake --build ${BUILD_DIR} --target lib/hpke/test
	cmake --build ${BUILD_DIR} --target lib/tls_syntax/test
	cmake --build ${BUILD_DIR} --target lib/mls_vectors/test

test-all: test-libs ctest

everything: ${BUILD_DIR}
	cmake --build ${BUILD_DIR}

ci:
	cmake -B ${BUILD_DIR} -DTESTING=ON -DCLANG_TIDY=ON -DSANITIZERS=ON \
		-DCMAKE_BUILD_TYPE=Debug -DCMAKE_TOOLCHAIN_FILE="${VCPKG_TOOLCHAIN_FILE}" .

clean:
	cmake --build ${BUILD_DIR} --target clean

cclean:
	rm -rf ${BUILD_DIR}

format:
	find include -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find src -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find test -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find lib -iname "*.h" -or -iname "*.cpp" | grep -v "test_vectors.cpp" |  xargs ${CLANG_FORMAT}
