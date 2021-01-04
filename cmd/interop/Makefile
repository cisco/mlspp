BUILD_DIR=build
APP_NAME=mlspp_client

.PHONY: all run format clean cclean

all: ${BUILD_DIR}/${APP_NAME}

${BUILD_DIR}:
	cmake -B${BUILD_DIR} .

${BUILD_DIR}/${APP_NAME}: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target ${APP_NAME}

run: ${BUILD_DIR}/${APP_NAME}
	./${BUILD_DIR}/${APP_NAME} -port 50002

format:
	clang-format -i -style=Mozilla *.cpp

clean: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target clean
cclean:
	rm -rf ${BUILD_DIR}
