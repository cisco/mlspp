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
have_error=0
for name in `find ${INTEROP_DIR}/configs -name "*.json"`;
do
    echo $name
    ${INTEROP_DIR}/test-runner/test-runner -client localhost:50001 -public -suite 1 -config $name | grep error
    if [ $? == 0 ]
    then
      have_error=1
    fi
done

# Clean up
kill ${BIN_PID}

# Exit status is flipped from `grep` status, because `grep` succeeds when an
# error line has been matched.
if [ $have_error == 1 ]; 
then 
  echo FAIL
  exit 1
else
  echo PASS
  exit 0
fi

