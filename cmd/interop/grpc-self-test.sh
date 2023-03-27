#!/bin/bash

BIN=./build/mlspp_client
PORT=50001
INTEROP_DIR=./build/third_party/src/mls-interop-extern/interop/

# Launch the interop client
make
${BIN} -live ${PORT} &
BIN_PID=$!
sleep 1

# Build the test runner
cd ${INTEROP_DIR}
go mod tidy
make test-runner/test-runner
cd ../../../../..

# Run the tests
find ${INTEROP_DIR}/configs -name "*.json" \
    | xargs ${INTEROP_DIR}/test-runner/test-runner -client localhost:50001 -public -suite 1 -config \
    | grep error
have_error=$?

# Clean up
kill ${BIN_PID}

# Exit status is flipped from `grep` status, because `grep` succeeds when an
# error line has been matched.
if [ $have_error == 0 ]; 
then 
  echo FAIL
  exit 1
else
  echo PASS
  exit 0
fi

