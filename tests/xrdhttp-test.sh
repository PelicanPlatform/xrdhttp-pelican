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

###########################
# Test the cache eviction #
###########################

echo "Ensure the object is cached in the local directory"

CONTENTS=$(cat "$XROOTD_CACHEDIR/hello_world.txt")

if [ "$CONTENTS" != "Hello, World" ]; then
  echo "Cached hello-world text is incorrect: $CONTENTS"
  exit 1
fi

echo "Running $TEST_NAME - evict from cache"

HTTP_CODE=$(curl --cacert $X509_CA_FILE --output /dev/null -v --write-out '%{http_code}' "$CACHE_URL/pelican/api/v1.0/evict?path=/hello_world.txt" 2>> "$BINARY_DIR/tests/$TEST_NAME/client.log")
if [ "$HTTP_CODE" -ne 200 ]; then
  echo "Expected HTTP code is 200; actual was $HTTP_CODE"
  exit 1
fi

if [ -f "$XROOTD_CACHEDIR/hello_world.txt" ]; then
  echo "Cached hello-world text was not evicted"
  exit 1
fi

###########################
# Test the cache prestage #
###########################

echo "Running $TEST_NAME - prestage to cache"

HTTP_CODE=$(curl --cacert $X509_CA_FILE --output /dev/null -v --write-out '%{http_code}' "$CACHE_URL/pelican/api/v1.0/prestage?path=/hello_world.txt" 2>> "$BINARY_DIR/tests/$TEST_NAME/client.log")
if [ "$HTTP_CODE" -ne 200 ]; then
  echo "Expected HTTP code is 200; actual was $HTTP_CODE"
  exit 1
fi

if ! grep -q "pelican_Prestage: Handling prestage for path /hello_world.txt" "$BINARY_DIR/tests/$TEST_NAME/cache.log"; then
  echo "Prestage request was not logged"
  exit 1
fi

if ! grep -q "pelican_RequestManager: Created new prestage queue for nobody" "$BINARY_DIR/tests/$TEST_NAME/cache.log"; then
  echo "Prestage request queue was not created"
  exit 1
fi

if [ ! -f "$XROOTD_CACHEDIR/hello_world.txt" ]; then
  echo "hello-world text was not prestaged"
  exit 1
fi

sleep 1

if ! grep -q "pelican_PrestageRequestManager: Prestage pool nobody is idle and all workers have exited" "$BINARY_DIR/tests/$TEST_NAME/cache.log"; then
  echo "Prestage request manager did not exit on idle"
  exit 1
fi

###########################
# Test parallel prestage  #
###########################

echo "Running $TEST_NAME - parallel prestage to cache"

for idx in $(seq 1 10); do
  curl --cacert $X509_CA_FILE --output /dev/null -v --write-out '%{http_code}' "$CACHE_URL/pelican/api/v1.0/prestage?path=/random_data_$idx.txt" > "$BINARY_DIR/tests/$TEST_NAME/download_results_${idx}.txt" 2>> "$BINARY_DIR/tests/$TEST_NAME/client.log" &
done

wait

COUNT_429=0
NOT_STAGED_COUNT=0
for idx in $(seq 1 10); do
  HTTP_CODE=$(cat "$BINARY_DIR/tests/$TEST_NAME/download_results_${idx}.txt")
  if [ "$HTTP_CODE" -ne 200 ] && [ "$HTTP_CODE" -ne 429 ]; then
    echo "Expected HTTP codes are either 200 or 429; actual was $HTTP_CODE"
    exit 1
  fi
  if [ "$HTTP_CODE" -eq 429 ]; then
    COUNT_429=$((COUNT_429+1))
  fi
  if [ ! -f "$XROOTD_CACHEDIR/random_data_${idx}.txt" ]; then
    NOT_STAGED_COUNT=$((NOT_STAGED_COUNT+1))
  fi
done
if [ "$COUNT_429" -eq 0 ]; then
  echo "Expected at least one 429 response; actual was $COUNT_429"
  exit 1
fi
echo "$COUNT_429 files were not staged due to load (expected)"
if [ "$COUNT_429" -ne "$NOT_STAGED_COUNT" ]; then
  echo "Expected $COUNT_429 files to not be staged; actual was $NOT_STAGED_COUNT"
  exit 1
fi

WORKERS_STARTED=$(grep -c "for nobody starting" "$BINARY_DIR/tests/$TEST_NAME/cache.log")
if [ "$WORKERS_STARTED" -lt 3 ]; then
  echo "Expected at least 3 workers to be started; actual was $WORKERS_STARTED"
  exit 1
fi
