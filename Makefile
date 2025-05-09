# This is just a convenience Makefile to avoid having to remember
# all the CMake commands and their arguments.

# Set CMAKE_GENERATOR in the environment to select how you build, e.g.:
#   CMAKE_GENERATOR=Ninja

BUILD_DIR=build
TEST_DIR=build/test
CLANG_FORMAT=clang-format -i
CLANG_FORMAT_EXCLUDE="test_vectors.cpp"
CLANG_TIDY=OFF
OPENSSL11_MANIFEST=alternatives/openssl_1.1
OPENSSL3_MANIFEST=alternatives/openssl_3
BORINGSSL_MANIFEST=alternatives/boringssl
TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake

.PHONY: all dev dev3 test ctest dtest dbtest libs test-libs test-all everything ci ci3 clean cclean format

all: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target mlspp

${BUILD_DIR}: CMakeLists.txt test/CMakeLists.txt
	cmake -B${BUILD_DIR}  \
		-DVCPKG_MANIFEST_DIR=${OPENSSL11_MANIFEST} \
		-DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE}

${TOOLCHAIN_FILE}:
	git submodule update --init --recursive

# Only enable testing, not clang-tidy/sanitizers; the latter make the build
# too slow, and we can run them in CI
dev: ${TOOLCHAIN_FILE}
	cmake -B${BUILD_DIR} -DTESTING=ON -DCMAKE_BUILD_TYPE=Debug \
		-DVCPKG_MANIFEST_DIR=${OPENSSL11_MANIFEST} \
		-DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE}

# Like `dev`, but using OpenSSL 3
dev3: ${TOOLCHAIN_FILE}
	cmake -B${BUILD_DIR} -DTESTING=ON -DCMAKE_BUILD_TYPE=Debug \
		-DVCPKG_MANIFEST_DIR=${OPENSSL3_MANIFEST} \
		-DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE}

# Like `dev`, but using BoringSSL
devB: ${TOOLCHAIN_FILE}
	cmake -B${BUILD_DIR} -DTESTING=ON -DCMAKE_BUILD_TYPE=Debug \
		-DVCPKG_MANIFEST_DIR=${BORINGSSL_MANIFEST} \
		-DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE}

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

ci: ${TOOLCHAIN_FILE}
	cmake -B ${BUILD_DIR} -DTESTING=ON -DCLANG_TIDY=ON -DSANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug \
		-DVCPKG_MANIFEST_DIR=${OPENSSL11_MANIFEST} \
		-DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE}

# Like `ci`, but using OpenSSL 3
ci3: ${TOOLCHAIN_FILE}
	cmake -B ${BUILD_DIR} -DTESTING=ON -DCLANG_TIDY=ON -DSANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug \
		-DVCPKG_MANIFEST_DIR=${OPENSSL3_MANIFEST} \
		-DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE}

# Like `ci`, but using BoringSSL
ciB: ${TOOLCHAIN_FILE}
	cmake -B ${BUILD_DIR} -DTESTING=ON -DCLANG_TIDY=ON -DSANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug \
		-DVCPKG_MANIFEST_DIR=${BORINGSSL_MANIFEST} \
		-DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE}

clean:
	cmake --build ${BUILD_DIR} --target clean

cclean:
	rm -rf ${BUILD_DIR}

format:
	for dir in include src test lib; \
	do \
		find $${dir} -iname "*.h" -or -iname "*.cpp" | grep -v ${CLANG_FORMAT_EXCLUDE} \
		| xargs ${CLANG_FORMAT}; \
	done
