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

if [ ! -f "$BINARY_DIR/tests/$TEST_NAME/setup.sh" ]; then
  echo "Test environment file $BINARY_DIR/tests/$TEST_NAME/setup.sh does not exist - cannot run test"
  exit 1
fi
. "$BINARY_DIR/tests/$TEST_NAME/setup.sh"


#############################
# Downloads from the origin #
#############################
echo "Running $TEST_NAME - origin download"

CONTENTS=$(curl --cacert $X509_CA_FILE -v --fail "$ORIGIN_URL/hello_world.txt" 2> "$BINARY_DIR/tests/$TEST_NAME/client.log")
CURL_EXIT=$?
if [ $CURL_EXIT -ne 0 ]; then
  echo "Download of hello-world text failed"
  exit 1
fi

if [ "$CONTENTS" != "Hello, World" ]; then
  echo "Downloaded hello-world text is incorrect: $CONTENTS"
  exit 1
fi

echo "Running $TEST_NAME - missing object"

HTTP_CODE=$(curl --cacert $X509_CA_FILE --output /dev/null -v --write-out '%{http_code}' "$ORIGIN_URL/missing.txt" 2>> "$BINARY_DIR/tests/$TEST_NAME/client.log")
if [ "$HTTP_CODE" -ne 404 ]; then
  echo "Expected HTTP code is 404; actual was $HTTP_CODE"
  exit 1
fi

############################
# Downloads from the cache #
############################
echo "Running $TEST_NAME - cache download"

CONTENTS=$(curl --cacert $X509_CA_FILE -v --fail "$CACHE_URL/hello_world.txt" 2> "$BINARY_DIR/tests/$TEST_NAME/client.log")
CURL_EXIT=$?
if [ $CURL_EXIT -ne 0 ]; then
  echo "Download of hello-world text failed"
  exit 1
fi

if [ "$CONTENTS" != "Hello, World" ]; then
  echo "Downloaded hello-world text is incorrect: $CONTENTS"
  exit 1
fi

echo "Running $TEST_NAME - missing object"

HTTP_CODE=$(curl --cacert $X509_CA_FILE --output /dev/null -v --write-out '%{http_code}' "$CACHE_URL/missing.txt" 2>> "$BINARY_DIR/tests/$TEST_NAME/client.log")
if [ "$HTTP_CODE" -ne 404 ]; then
  echo "Expected HTTP code is 404; actual was $HTTP_CODE"
  exit 1
fi