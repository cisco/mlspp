BUILD_DIR=build
APP_NAME=mlspp_client

.PHONY: all run format clean cclean

all: ${BUILD_DIR}/${APP_NAME}

${BUILD_DIR}:
	cmake -B${BUILD_DIR} -DCMAKE_BUILD_TYPE=Debug .

${BUILD_DIR}/${APP_NAME}: ${BUILD_DIR} src/*.cpp
	cmake --build ${BUILD_DIR} --target ${APP_NAME}

run: ${BUILD_DIR}/${APP_NAME}
	./${BUILD_DIR}/${APP_NAME} -port 50001

format:
	clang-format -i -style=Mozilla src/*.cpp src/*.h

clean: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target clean

cclean:
	rm -rf ${BUILD_DIR}
