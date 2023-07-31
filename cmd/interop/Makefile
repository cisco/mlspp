BUILD_DIR=build
TEST_VECTOR_DIR=${BUILD_DIR}/third_party/src/mls-interop-extern/test-vectors
APP_NAME=mlspp_client

.PHONY: all run format clean cclean

all: ${BUILD_DIR}/${APP_NAME}

${BUILD_DIR}:
	cmake -B${BUILD_DIR} -DCMAKE_BUILD_TYPE=Debug .

${BUILD_DIR}/${APP_NAME}: ${BUILD_DIR} src/*.cpp
	cmake --build ${BUILD_DIR} --target ${APP_NAME}

run: ${BUILD_DIR}/${APP_NAME}
	./${BUILD_DIR}/${APP_NAME} -live 50001

self-test: ${BUILD_DIR}/${APP_NAME}
	# TODO(RLB) Extend to 13 to cover passive client tests
	for tv_type in 1 2 3 4 5 6 7 8 9 10 11 12; do \
		echo Self-test on test vector type $$tv_type; \
		./${BUILD_DIR}/${APP_NAME} -gen $$tv_type | ./${BUILD_DIR}/${APP_NAME} -ver $$tv_type; \
	done

interop-test: ${BUILD_DIR}/${APP_NAME}
	./${BUILD_DIR}/${APP_NAME} -ver 1 <${TEST_VECTOR_DIR}/tree-math.json
	./${BUILD_DIR}/${APP_NAME} -ver 2 <${TEST_VECTOR_DIR}/crypto-basics.json
	./${BUILD_DIR}/${APP_NAME} -ver 3 <${TEST_VECTOR_DIR}/secret-tree.json
	./${BUILD_DIR}/${APP_NAME} -ver 4 <${TEST_VECTOR_DIR}/message-protection.json
	./${BUILD_DIR}/${APP_NAME} -ver 5 <${TEST_VECTOR_DIR}/key-schedule.json
	./${BUILD_DIR}/${APP_NAME} -ver 6 <${TEST_VECTOR_DIR}/psk_secret.json
	./${BUILD_DIR}/${APP_NAME} -ver 7 <${TEST_VECTOR_DIR}/tree-validation.json
	./${BUILD_DIR}/${APP_NAME} -ver 8 <${TEST_VECTOR_DIR}/transcript-hashes.json
	./${BUILD_DIR}/${APP_NAME} -ver 9 <${TEST_VECTOR_DIR}/welcome.json
	./${BUILD_DIR}/${APP_NAME} -ver 10 <${TEST_VECTOR_DIR}/tree-operations.json
	./${BUILD_DIR}/${APP_NAME} -ver 11 <${TEST_VECTOR_DIR}/treekem.json
	./${BUILD_DIR}/${APP_NAME} -ver 12 <${TEST_VECTOR_DIR}/messages.json
	./${BUILD_DIR}/${APP_NAME} -ver 13 <${TEST_VECTOR_DIR}/passive-client-welcome.json
	./${BUILD_DIR}/${APP_NAME} -ver 13 <${TEST_VECTOR_DIR}/passive-client-handling-commit.json
	./${BUILD_DIR}/${APP_NAME} -ver 13 <${TEST_VECTOR_DIR}/passive-client-random.json

format:
	clang-format -i -style=Mozilla src/*.cpp src/*.h

clean: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target clean

cclean:
	rm -rf ${BUILD_DIR}
