#!/bin/sh

TEST_NAME=$1

if [ -z "$BINARY_DIR" ]; then
  echo "\$BINARY_DIR environment variable is not set; cannot run test"
  exit 1
fi
if [ ! -d "$BINARY_DIR" ]; then
  echo "$BINARY_DIR is not a directory; cannot run test"
  exit 1
fi

echo "Tearing down $TEST_NAME"

if [ ! -f "$BINARY_DIR/tests/$TEST_NAME/setup.sh" ]; then
  echo "Test environment file $BINARY_DIR/tests/$TEST_NAME/setup.sh does not exist - cannot run test"
  exit 1
fi
. "$BINARY_DIR/tests/$TEST_NAME/setup.sh"


if [ -z "$ORIGIN_PID" ]; then
  echo "\$ORIGIN_PID environment variable is not set; cannot tear down process"
  exit 0
fi
kill "$CACHE_PID"

if [ -z "$CACHE_PID" ]; then
  echo "\$CACHE_PID environment variable is not set; cannot tear down process"
  exit 1
fi
kill "$CACHE_PID"
