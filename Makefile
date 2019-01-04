# This is just a convenience Makefile to avoid having to remember
# all the CMake commands and their arguments.

BUILD_DIR=build
CLANG_FORMAT=clang-format -i -style=mozilla

all: ${BUILD_DIR} format src/* test/*
	cmake --build ${BUILD_DIR}

${BUILD_DIR}: CMakeLists.txt test/CMakeLists.txt third_party/CMakeLists.txt
	cmake -H. -B${BUILD_DIR} -DCMAKE_BUILD_TYPE=Debug

test: all
	cd ${BUILD_DIR} && ctest

clean:
	rm -rf ${BUILD_DIR}

format:
	find src -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find test -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
