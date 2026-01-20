
An XrdHttp plugin for the Pelican Platform
==========================================

This repository contains a plugin for the [XrdHttp](https://xrootd.github.io/) server
which implements specific behaviors needed by the [Pelican platform](https://pelicanplatform.org/).

The plugin provides:
- Prestage API for triggering file pulls from remote sources into the cache
- Eviction API for removing files from the cache
- Dynamic CA and certificate file reload without server restart

## Building

```bash
mkdir build
cd build
cmake ..
make
```

## Installation

To use the plugin, add the following line to your XRootD configuration:

```
http.exthandler xrdpelican libXrdHttpPelican.so
```

## Configuration

The plugin supports the following configuration directives:

### pelican.trace

Controls the logging level for the plugin. Multiple levels can be specified.

**Syntax:**
```
pelican.trace <level> [<level> ...]
```

**Levels:**
- `all` - Enable all logging levels
- `debug` - Detailed debugging information
- `info` - Informational messages
- `warning` - Warning messages
- `error` - Error messages only
- `none` - Disable all logging

**Example:**
```
pelican.trace info warning error
```

### pelican.worker_idle

Configures the idle timeout for prestage worker threads. Workers that are idle for longer than this duration will automatically exit.

**Syntax:**
```
pelican.worker_idle <duration>
```

**Duration format:** Number followed by a unit (`ms`, `s`, `m`, `h`)

**Default:** 1 minute

**Example:**
```
pelican.worker_idle 5m
```

### pelican.worker_max

Sets the maximum number of concurrent worker threads per user/VO identity for prestage operations.

**Syntax:**
```
pelican.worker_max <count>
```

**Default:** 20

**Example:**
```
pelican.worker_max 10
```

### pelican.idle_request_max

Sets the maximum number of queued prestage requests per user/VO identity. If this limit is reached, new prestage requests will be rejected with a 429 (Too Many Requests) response.

**Syntax:**
```
pelican.idle_request_max <count>
```

**Default:** 20

**Example:**
```
pelican.idle_request_max 100
```

## Message Handling (ProcessMessage)

The plugin implements dynamic configuration updates through the `Handler::ProcessMessage` method, which processes control messages from the parent XRootD process over a Unix domain socket.

### Message Types

The handler supports the following control messages:

1. **CA File Update (Message Type 1)**
   - Receives a file descriptor containing the new CA certificate bundle
   - Atomically replaces the existing CA file
   - Enables CA rotation without server restart

2. **Certificate File Update (Message Type 2)**
   - Receives a file descriptor containing the new host certificate and key
   - Atomically replaces the existing certificate file
   - Enables certificate rotation without server restart

3. **Signal Relay (Message Type 3)**
   - Receives a signal number to relay to the process itself
   - Used for graceful shutdown and reload operations

4. **Cache Self-Test File Update (Message Type 4)**
   - Receives a file descriptor containing the cache self-test file
   - Atomically replaces the existing self-test file
   - Used for cache validation and health checks

5. **Cache Self-Test File CInfo Update (Message Type 5)**
   - Receives a file descriptor containing the cache self-test file cinfo metadata
   - Atomically replaces the existing cinfo file
   - Contains metadata for cache self-test validation

6. **Auth File Update (Message Type 6)**
   - Receives a file descriptor containing the generated authorization file
   - Atomically replaces the existing auth file
   - Enables dynamic authorization updates without server restart

7. **SciTokens File Update (Message Type 7)**
   - Receives a file descriptor containing the generated SciTokens configuration
   - Atomically replaces the existing SciTokens file
   - Enables dynamic token configuration updates without server restart

### Implementation Details

The message handler:
- Uses `recvmsg()` with `SCM_RIGHTS` to receive file descriptors from the parent process
- Implements atomic file replacement using temporary files and rename operations
- Runs in a dedicated thread that polls the control socket
- Handles errors gracefully and logs all operations

## Prestage and Eviction API

The plugin provides two HTTP endpoints for cache management when running on a cache server (`XRDPFC` environment variable is set).

### Prestage API

**Endpoint:** `GET /pelican/api/v1.0/prestage?path=<absolute_path>`

Triggers a prestage operation to pull a file from the remote origin into the local cache.

**Query Parameters:**
- `path` (required): URL-encoded absolute path to the file to prestage

**Authentication:**
- Requires read permission on the requested path
- User identity is determined from the security entity (certificate, token, or username)
- Virtual organization (VO) is included if available

**Response:**

The response uses chunked transfer encoding to provide progress updates:

1. **Queued:** `status: queued`
2. **Active:** `status: active,offset=<bytes>`
3. **Success:** `success: ok`
4. **Failure:** `failure: <code>(<description>): <details>`

**Status Codes:**
- `200 OK` - Prestage completed successfully
- `400 Bad Request` - Invalid request (missing path, non-absolute path, or malformed URL encoding)
- `403 Forbidden` - Permission denied
- `404 Not Found` - File does not exist
- `409 Conflict` - Path is a directory
- `429 Too Many Requests` - Queue is full
- `500 Internal Server Error` - Prestage operation failed

**Example:**
```bash
curl -X GET "https://cache.example.com/pelican/api/v1.0/prestage?path=%2Fdata%2Ffile.txt"
```

### Eviction API

**Endpoint:** `GET /pelican/api/v1.0/evict?path=<absolute_path>`

Evicts a file from the cache, freeing up storage space.

**Query Parameters:**
- `path` (required): URL-encoded absolute path to the file to evict

**Authentication:**
- Requires delete permission on the requested path

**Response:**

The response is a simple text response indicating success or failure.

**Status Codes:**
- `200 OK` - File evicted successfully
- `400 Bad Request` - Invalid request
- `403 Forbidden` - Permission denied
- `423 Locked` - File is currently in use and cannot be evicted
- `500 Internal Server Error` - Eviction operation failed

**Example:**
```bash
curl -X GET "https://cache.example.com/pelican/api/v1.0/evict?path=%2Fdata%2Ffile.txt"
```

### Implementation Details

- **Per-User Queueing:** Prestage requests are queued per user/VO identity to ensure fair resource allocation
- **Worker Pools:** Each user/VO gets a dedicated pool of worker threads (up to `pelican.worker_max`)
- **Automatic Cleanup:** Worker pools automatically shut down after being idle for `pelican.worker_idle` duration
- **Progress Tracking:** Prestage operations report progress every 200ms or when offset changes significantly
- **Backpressure:** When queues are full, new requests receive a 429 status code

## OpenAPI Specification

See [pelican-api.yaml](pelican-api.yaml) for the complete OpenAPI 3.0 specification of the prestage and eviction APIs.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
