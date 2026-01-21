/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

#pragma once

#include <stdint.h>

namespace XrdHttpPelican {

/**
 * Install signal handlers for crash reporting.
 * Handles SIGSEGV, SIGILL, and SIGABRT by printing a stack trace
 * and then re-raising the signal with the default handler.
 */
void InstallSignalHandlers();

namespace detail {

/**
 * Format a number as hexadecimal into a buffer (async-signal-safe).
 * Returns the number of characters written (including "0x" prefix).
 * Buffer must be at least 20 bytes for 64-bit values.
 */
int WriteHexToBuffer(char *buf, uintptr_t value);

/**
 * Parse a single hexadecimal character (async-signal-safe).
 * Returns true if the character is valid hex ('0'-'9', 'a'-'f', 'A'-'F').
 * Sets *value to the numeric value (0-15) if valid.
 */
bool ParseHexChar(char c, int *value);

/**
 * Find the module path and base address for a given address by reading from
 * a file descriptor containing /proc/self/maps format data (async-signal-safe).
 * Returns true on success with module_path and base_addr filled in.
 * Returns false if address not found or error occurs.
 */
bool GetModuleForAddress(int maps_fd, uintptr_t addr, char *module_path,
                         int path_size, uintptr_t *base_addr);

} // namespace detail

} // namespace XrdHttpPelican
