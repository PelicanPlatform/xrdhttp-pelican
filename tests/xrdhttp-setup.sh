#!/bin/sh

###############################
# Helper functions for script #
###############################

server_port() {
  logfile="$1"
  xrootd_pid="$2"

  touch -- "$logfile"
  SERVER_PORT=$(grep "Xrd_ProtLoad: enabling port" "$logfile" | grep 'for protocol XrdHttp' | awk '{print $7}')
  IDX=0
  while [ -z "$SERVER_PORT" ]; do
    sleep 1
    SERVER_PORT=$(grep "Xrd_ProtLoad: enabling port" "$logfile" | grep 'for protocol XrdHttp' | awk '{print $7}')
    IDX=$((IDX+1))
    if ! kill -0 "$xrootd_pid" 2>/dev/null; then
      echo "xrootd process (PID $xrootd_pid) failed to start" >&2
      exit 1
    fi
    if [ $IDX -gt 1 ]; then
      echo "Waiting for xrootd to start ($IDX seconds so far) ..." >&2
    fi
    if [ $IDX -eq 10 ]; then
      echo "xrootd failed to start - dumping logs and failing" >&2
      cat "$logfile" >&2
      exit 1
    fi
  done

  echo "$SERVER_PORT"
}

TEST_NAME="$1"

HOSTNAME="${HOSTNAME:-$(hostname)}"

if [ -z "$BINARY_DIR" ]; then
  echo "\$BINARY_DIR environment variable is not set; cannot run test"
  exit 1
fi
if [ ! -d "$BINARY_DIR" ]; then
  echo "$BINARY_DIR is not a directory; cannot run test"
  exit 1
fi
if [ -z "$SOURCE_DIR" ]; then
  echo "\$SOURCE_DIR environment variable is not set; cannot run test"
  exit 1
fi
if [ ! -d "$SOURCE_DIR" ]; then
  echo "\$SOURCE_DIR environment variable is not set; cannot run test"
  exit 1
fi
if [ -z "$XROOTD_BINDIR" ]; then
  echo "\$XROOTD_BINDIR environment variable is not set; cannot run test"
  exit 1
fi
if [ ! -d "$XROOTD_BINDIR" ]; then
  echo "\$XROOTD_BINDIR environment variable is not set; cannot run test"
  exit 1
fi

echo "Setting up origin and cache server for $TEST_NAME test"
PATH="$(realpath "$XROOTD_BINDIR"):$PATH"
XROOTD_BIN="$(command -v xrootd)"

if [ -z "$XROOTD_BIN" ]; then
  echo "xrootd binary not found; cannot run unit test"
  exit 1
fi

mkdir -p "$BINARY_DIR/tests/$TEST_NAME"
RUNDIR=$(mktemp -d -p "$BINARY_DIR/tests/$TEST_NAME" test_run.XXXXXXXX)

if [ ! -d "$RUNDIR" ]; then
  echo "Failed to create test run directory; cannot run xrootd"
  exit 1
fi

echo "Using $RUNDIR as the test run's home directory."
cd "$RUNDIR" || exit 1

export XROOTD_CONFIGDIR="$RUNDIR/xrootd-config"
mkdir -p "$XROOTD_CONFIGDIR/ca"

echo > "$BINARY_DIR/tests/$TEST_NAME/server.log"

############################################
# Create the TLS credentials for the test  #
############################################
openssl genrsa -out "$XROOTD_CONFIGDIR/tlscakey.pem" 4096 >> "$BINARY_DIR/tests/$TEST_NAME/server.log"
touch "$XROOTD_CONFIGDIR/ca/index.txt"
echo '01' > "$XROOTD_CONFIGDIR/ca/serial.txt"

cat > "$XROOTD_CONFIGDIR/tlsca.ini" <<EOF

[ ca ]
default_ca = CA_test

[ CA_test ]

default_days = 365
default_md = sha256
private_key = $XROOTD_CONFIGDIR/tlscakey.pem
certificate = $XROOTD_CONFIGDIR/tlsca.pem
new_certs_dir = $XROOTD_CONFIGDIR/ca
database = $XROOTD_CONFIGDIR/ca/index.txt
serial = $XROOTD_CONFIGDIR/ca/serial.txt

[ req ]
default_bits = 4096
distinguished_name = ca_test_dn
x509_extensions = ca_extensions
string_mask = utf8only

[ ca_test_dn ]

commonName_default = Xrootd CA

[ ca_extensions ]

basicConstraints = critical,CA:true
keyUsage = keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[ signing_policy ]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[ cert_extensions ]

basicConstraints = critical,CA:false
keyUsage = digitalSignature
extendedKeyUsage = critical, serverAuth, clientAuth

EOF

# Create the CA certificate
if ! openssl req -x509 -key "$XROOTD_CONFIGDIR/tlscakey.pem" -config "$XROOTD_CONFIGDIR/tlsca.ini" -out "$XROOTD_CONFIGDIR/tlsca.pem" -outform PEM -subj "/CN=XRootD CA" 0<&- >> "$BINARY_DIR/tests/$TEST_NAME/server.log"; then
  echo "Failed to generate CA request"
  exit 1
fi

# Create the host certificate request
openssl genrsa -out "$XROOTD_CONFIGDIR/tls.key" 4096 >> "$BINARY_DIR/tests/$TEST_NAME/server.log"
if ! openssl req -new -key "$XROOTD_CONFIGDIR/tls.key" -config "$XROOTD_CONFIGDIR/tlsca.ini" -out "$XROOTD_CONFIGDIR/tls.csr" -outform PEM -subj "/CN=$(hostname)" 0<&- >> "$BINARY_DIR/tests/$TEST_NAME/server.log"; then
  echo "Failed to generate host certificate request"
  exit 1
fi

if ! openssl ca -config "$XROOTD_CONFIGDIR/tlsca.ini" -batch -policy signing_policy -extensions cert_extensions -out "$XROOTD_CONFIGDIR/tls.crt" -infiles "$XROOTD_CONFIGDIR/tls.csr" 0<&- 2>> "$BINARY_DIR/tests/$TEST_NAME/server.log"; then
  echo "Failed to sign host certificate request"
  exit 1
fi


# Create xrootd configuration and runtime directory structure
XROOTD_EXPORTDIR="$RUNDIR/xrootd-export"
mkdir -p "$XROOTD_EXPORTDIR"
XROOTD_CACHEDIR="$RUNDIR/xrootd-cache"
mkdir -p "$XROOTD_CACHEDIR"

# XRootD has strict length limits on the admin path location.
# Therefore, we also create a directory in /tmp.
XROOTD_RUNDIR=$(mktemp -d -p /tmp xrootd_test.XXXXXXXX)
mkdir -p "$XROOTD_RUNDIR/cache"
mkdir -p "$XROOTD_RUNDIR/origin"

###########################
# Setup the XRootD origin #
###########################
export XROOTD_CONFIG="$XROOTD_CONFIGDIR/xrootd-origin.cfg"
cat > "$XROOTD_CONFIG" <<EOF

all.trace    all
http.trace   all
xrd.trace    all
xrootd.trace all
scitokens.trace all

xrd.port any

all.export /
all.sitename  XRootD
all.adminpath $XROOTD_RUNDIR/origin
all.pidpath   $XROOTD_RUNDIR/origin

xrootd.seclib libXrdSec.so

ofs.authorize 1

ofs.authlib ++ libXrdAccSciTokens.so config=$XROOTD_CONFIGDIR/scitokens.cfg
acc.authdb $XROOTD_CONFIGDIR/authdb

xrd.protocol XrdHttp:any libXrdHttp.so
http.header2cgi Authorization authz

xrd.tlsca certfile $XROOTD_CONFIGDIR/tlsca.pem
xrd.tls $XROOTD_CONFIGDIR/tls.crt $XROOTD_CONFIGDIR/tls.key

ofs.osslib ++ $BINARY_DIR/tests/libXrdOssSlowOpen.so
oss.localroot $XROOTD_EXPORTDIR

http.exthandler xrdpelican $BINARY_DIR/libXrdHttpPelican.so

EOF

cat > "$XROOTD_CONFIGDIR/authdb" <<EOF

u * /public lr /.well-known lr


EOF

cat > "$XROOTD_CONFIGDIR/scitokens.cfg" <<EOF

[Global]
audience = https://localhost:9443

[Issuer LocalTest]
issuer = https://localhost:9443
base_path = /protected

EOF

######################
# Setup token issuer #
######################

# Create .well-known directory for JWKS and OpenID configuration
mkdir -p "$XROOTD_EXPORTDIR/.well-known" || exit 1

# Generate EC keys for the issuer
if ! openssl ecparam -name prime256v1 -genkey -noout -out "$RUNDIR/issuer_private.pem" 2>> "$BINARY_DIR/tests/$TEST_NAME/server.log"; then
  echo "Failed to generate EC private key"
  exit 1
fi

if ! openssl ec -in "$RUNDIR/issuer_private.pem" -pubout -out "$RUNDIR/issuer_public.pem" 2>> "$BINARY_DIR/tests/$TEST_NAME/server.log"; then
  echo "Failed to generate EC public key"
  exit 1
fi

# Create JWKS file
if ! "$BINARY_DIR/tests/xrdscitokens-create-jwks" "$RUNDIR/issuer_public.pem" "$XROOTD_EXPORTDIR/.well-known/issuer.jwks" "test_key" >> "$BINARY_DIR/tests/$TEST_NAME/server.log" 2>&1; then
  echo "Failed to generate JWKS file"
  exit 1
fi

echo "JWKS file created at $XROOTD_EXPORTDIR/.well-known/issuer.jwks"

# Pre-load the JWKS into SciTokens cache to avoid HTTPS fetch issues
# This is needed because older versions of libscitokens-cpp don't support custom CAs
mkdir -p "$RUNDIR/issuer"
cat > "$RUNDIR/issuer/sql" << EOF
BEGIN TRANSACTION;
CREATE TABLE keycache (issuer text UNIQUE PRIMARY KEY NOT NULL,keys text NOT NULL);
INSERT INTO keycache VALUES('https://localhost:9443','{"expires":$(($(date '+%s') + 3600)),"jwks":$(cat "$XROOTD_EXPORTDIR/.well-known/issuer.jwks"),"next_update":$(($(date '+%s') + 3600))}');
COMMIT;
EOF

XDG_CACHE_HOME="$RUNDIR/tmp"
rm -rf "$XDG_CACHE_HOME"
mkdir -p "$XDG_CACHE_HOME/scitokens" || exit 1

if ! sqlite3 "$XDG_CACHE_HOME/scitokens/scitokens_cpp.sqllite" < "$RUNDIR/issuer/sql"; then
  echo "Failed to generate sqlite database"
  exit 1
fi

echo "Pre-loaded JWKS into SciTokens cache"

export XDG_CACHE_HOME

# Export some data through the origin
echo "Hello, World" > "$XROOTD_EXPORTDIR/hello_world.txt"

# Create a 256KB file for prestaging tests
dd if=/dev/urandom of="$XROOTD_EXPORTDIR/large_file.txt" bs=1024 count=256 2> /dev/null

# Create public directory for non-token files
mkdir -p "$XROOTD_EXPORTDIR/public"
mv "$XROOTD_EXPORTDIR/hello_world.txt" "$XROOTD_EXPORTDIR/public/"
mv "$XROOTD_EXPORTDIR/large_file.txt" "$XROOTD_EXPORTDIR/public/"

# Create token-protected directory and 256KB test file
mkdir -p "$XROOTD_EXPORTDIR/protected"
dd if=/dev/urandom of="$XROOTD_EXPORTDIR/protected/token_test.txt" bs=1024 count=256 2> /dev/null

for idx in $(seq 1 10); do
  dd if=/dev/urandom of="$XROOTD_EXPORTDIR/public/random_data_$idx.txt" bs=1024 count=4096 2> /dev/null
done

#####################
# Launch the origin #
#####################
echo > "$BINARY_DIR/tests/$TEST_NAME/origin.log"
"$XROOTD_BIN" -c "$XROOTD_CONFIG" -l "$BINARY_DIR/tests/$TEST_NAME/origin.log" 0<&- >>"$BINARY_DIR/tests/$TEST_NAME/server.log" 2>&1 &
ORIGIN_PID=$!
echo "origin PID: $ORIGIN_PID"
echo "XRootD origin logs are available at $BINARY_DIR/tests/$TEST_NAME/origin.log"
ORIGIN_PORT=$(server_port "$BINARY_DIR/tests/$TEST_NAME/origin.log" "$ORIGIN_PID")
if [ -z "$ORIGIN_PORT" ]; then
  exit 1
fi
ORIGIN_URL="https://$HOSTNAME:$ORIGIN_PORT/"
echo "origin started at $ORIGIN_URL"

# Create OpenID configuration with actual URL
cat > "$XROOTD_EXPORTDIR/.well-known/openid-configuration" <<EOF
{
  "issuer": "https://localhost:9443",
  "jwks_uri": "https://localhost:9443/.well-known/issuer.jwks"
}
EOF

echo "OpenID configuration created"

# Generate test tokens
if ! "$BINARY_DIR/tests/xrdscitokens-create-token" \
    "$RUNDIR/issuer_public.pem" "$RUNDIR/issuer_private.pem" "test_key" \
    "https://localhost:9443" "read:/" 600 > "$RUNDIR/read_token" 2>> "$BINARY_DIR/tests/$TEST_NAME/server.log"; then
  echo "Failed to generate read token"
  exit 1
fi

if ! "$BINARY_DIR/tests/xrdscitokens-create-token" \
    "$RUNDIR/issuer_public.pem" "$RUNDIR/issuer_private.pem" "test_key" \
    "https://localhost:9443" "write:/" 600 > "$RUNDIR/write_token" 2>> "$BINARY_DIR/tests/$TEST_NAME/server.log"; then
  echo "Failed to generate write token"
  exit 1
fi

echo "Test tokens generated at $RUNDIR/read_token and $RUNDIR/write_token"

#####################################
# Write out the cache configuration #
#####################################

cat > "$XROOTD_CONFIGDIR/cache-authdb" <<EOF

u * /public a /.well-known a

EOF

export XROOTD_CONFIG="$XROOTD_CONFIGDIR/xrootd-cache.cfg"
cat > "$XROOTD_CONFIG" <<EOF

all.trace    all
http.trace   all
xrd.trace    all
xrootd.trace all
pfc.trace debug
scitokens.trace all

xrd.port any

all.export /
all.sitename  XRootD
all.adminpath $XROOTD_RUNDIR/cache
all.pidpath   $XROOTD_RUNDIR/cache

xrootd.seclib libXrdSec.so

ofs.authorize 1

ofs.authlib ++ libXrdAccSciTokens.so config=$XROOTD_CONFIGDIR/scitokens.cfg
acc.authdb $XROOTD_CONFIGDIR/cache-authdb

xrd.protocol XrdHttp:any libXrdHttp.so
http.header2cgi Authorization authz

xrd.tlsca certfile $XROOTD_CONFIGDIR/tlsca.pem
xrd.tls $XROOTD_CONFIGDIR/tls.crt $XROOTD_CONFIGDIR/tls.key

http.header2cgi Authorization authz
http.header2cgi X-Pelican-Timeout pelican.timeout

oss.localroot $XROOTD_CACHEDIR

pfc.blocksize 128k
pfc.prefetch 0
pfc.writequeue 16 4
pfc.ram 4g
pss.setopt DebugLevel 4
pfc.diskusage 0.90 0.95 purgeinterval 300s
ofs.osslib libXrdPss.so
pss.cachelib libXrdPfc.so
pss.origin $HOSTNAME:$ORIGIN_PORT

pelican.trace debug
pelican.worker_idle 10ms
pelican.worker_max 2
pelican.idle_request_max 2

http.exthandler xrdpelican $BINARY_DIR/libXrdHttpPelican.so
EOF

####################
# Launch the cache #
####################
echo > "$BINARY_DIR/tests/$TEST_NAME/cache.log"
"$XROOTD_BIN" -c "$XROOTD_CONFIG" -l "$BINARY_DIR/tests/$TEST_NAME/cache.log" 0<&- >>"$BINARY_DIR/tests/$TEST_NAME/server.log" 2>&1 &
CACHE_PID=$!
echo "cache PID: $CACHE_PID"
echo "XRootD cache logs are available at $BINARY_DIR/tests/$TEST_NAME/cache.log"
CACHE_PORT=$(server_port "$BINARY_DIR/tests/$TEST_NAME/cache.log" "$CACHE_PID")
if [ -z "$CACHE_PORT" ]; then
  exit 1
fi
CACHE_URL="https://$HOSTNAME:$CACHE_PORT/"
echo "cache started at $CACHE_URL"

cat > "$BINARY_DIR/tests/$TEST_NAME/setup.sh" <<EOF
XROOTD_BIN=$XROOTD_BIN
ORIGIN_PID=$ORIGIN_PID
CACHE_PID=$CACHE_PID
ORIGIN_URL=$ORIGIN_URL
CACHE_URL=$CACHE_URL
X509_CA_FILE=$XROOTD_CONFIGDIR/tlsca.pem
XROOTD_CACHEDIR=$XROOTD_CACHEDIR
XROOTD_CONFIGDIR=$XROOTD_CONFIGDIR
RUNDIR=$RUNDIR
READ_TOKEN=$RUNDIR/read_token
WRITE_TOKEN=$RUNDIR/write_token
EOF

echo "Test environment written to $BINARY_DIR/tests/$TEST_NAME/setup.sh"
