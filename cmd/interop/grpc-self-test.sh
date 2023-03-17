#!/bin/bash

BIN=./build/mlspp_client
PORT=50001
INTEROP_DIR=./build/third_party/src/mls-interop-extern/interop/

# Launch the interop client
make
${BIN} -live ${PORT} &
BIN_PID=$!
sleep 1

# Run the test scenarios
cd ${INTEROP_DIR}
go mod tidy
make test-runner/test-runner
for CONFIG in `ls configs`;
do
  echo "Running ${CONFIG}..."
  ./test-runner/test-runner -client localhost:${PORT} -config configs/${CONFIG} -public -suite 1 \
        | grep -i error
done

# Clean up
kill ${BIN_PID}
