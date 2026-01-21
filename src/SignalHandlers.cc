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

#include "SignalHandlers.hh"

#include <dlfcn.h>
#include <execinfo.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

// Testable helper functions in detail namespace
namespace XrdHttpPelican {
namespace detail {

// Helper to format hex into a buffer (async-signal-safe, testable)
// Returns the number of characters written
int WriteHexToBuffer(char *buf, uintptr_t value) {
    int pos = 0;
    buf[pos++] = '0';
    buf[pos++] = 'x';

    if (value == 0) {
        buf[pos++] = '0';
    } else {
        char digits[16];
        int digit_count = 0;
        while (value > 0) {
            int digit = value & 0xf;
            digits[digit_count++] = digit < 10 ? '0' + digit : 'a' + digit - 10;
            value >>= 4;
        }
        // Write digits in reverse order
        for (int i = digit_count - 1; i >= 0; i--) {
            buf[pos++] = digits[i];
        }
    }

    return pos;
}

// Helper to parse a hex character (async-signal-safe, testable)
// Returns true if valid hex char, false otherwise
bool ParseHexChar(char c, int *value) {
    if (c >= '0' && c <= '9') {
        *value = c - '0';
        return true;
    } else if (c >= 'a' && c <= 'f') {
        *value = c - 'a' + 10;
        return true;
    } else if (c >= 'A' && c <= 'F') {
        *value = c - 'A' + 10;
        return true;
    }
    return false;
}

} // namespace detail
} // namespace XrdHttpPelican

namespace {

// Helper to write a number in hex format to file descriptor (async-signal-safe)
void WriteHex(int fd, uintptr_t value) {
    char buf[32];
    int len = XrdHttpPelican::detail::WriteHexToBuffer(buf, value);
    ssize_t __attribute__((unused)) _ = write(fd, buf, len);
}

// Helper to write a decimal number (async-signal-safe)
void WriteDecimal(int fd, int value) {
    ssize_t __attribute__((unused)) _;
    if (value < 0) {
        _ = write(fd, "-", 1);
        value = -value;
    }

    char buf[16];
    int pos = 0;

    if (value == 0) {
        buf[pos++] = '0';
    } else {
        char digits[16];
        int digit_count = 0;
        while (value > 0) {
            digits[digit_count++] = '0' + (value % 10);
            value /= 10;
        }
        // Write digits in reverse order
        for (int i = digit_count - 1; i >= 0; i--) {
            buf[pos++] = digits[i];
        }
    }

    _ = write(fd, buf, pos);
}

} // anonymous namespace

namespace XrdHttpPelican {
namespace detail {

// Find the module path and base address for a given address
// Returns the base address of the segment containing the address
// Returns true on success, false on failure
bool GetModuleForAddress(int maps_fd, uintptr_t addr, char *module_path,
                         int path_size, uintptr_t *base_addr) {
    char buffer[4096];
    int bytes_read;
    char line_buffer[512];
    int line_pos = 0;

    // Find the segment containing the address
    while ((bytes_read = read(maps_fd, buffer, sizeof(buffer))) > 0) {
        for (int i = 0; i < bytes_read; i++) {
            if (buffer[i] == '\n') {
                line_buffer[line_pos] = '\0';

                // Parse the line: start-end perms offset dev inode pathname
                uintptr_t start = 0, end = 0;
                int pos = 0;

                // Parse start address (hex)
                while (pos < line_pos && line_buffer[pos] != '-') {
                    int digit;
                    if (ParseHexChar(line_buffer[pos], &digit)) {
                        start = (start << 4) | digit;
                    }
                    pos++;
                }
                pos++; // skip '-'

                // Parse end address (hex)
                while (pos < line_pos && line_buffer[pos] != ' ') {
                    int digit;
                    if (ParseHexChar(line_buffer[pos], &digit)) {
                        end = (end << 4) | digit;
                    }
                    pos++;
                }

                // Check if our address is in this range
                if (addr >= start && addr < end) {
                    // Skip to pathname: we need to skip perms, offset, dev,
                    // inode (5 fields total after address range)
                    // Format: start-end perms offset dev inode pathname
                    // After parsing 'end', we're at the space before perms
                    int space_count = 0;
                    while (pos < line_pos) {
                        if (line_buffer[pos] == ' ') {
                            space_count++;
                            if (space_count == 5) {
                                pos++;
                                // Skip any additional spaces before pathname
                                while (pos < line_pos &&
                                       line_buffer[pos] == ' ') {
                                    pos++;
                                }
                                break;
                            }
                        }
                        pos++;
                    }

                    // Copy pathname if it exists
                    if (pos < line_pos) {
                        int path_idx = 0;
                        while (pos < line_pos && path_idx < path_size - 1) {
                            module_path[path_idx++] = line_buffer[pos++];
                        }
                        module_path[path_idx] = '\0';

                        // Return the base address of THIS segment
                        *base_addr = start;
                        return true;
                    }
                }

                line_pos = 0;
            } else if (line_pos < (int)sizeof(line_buffer) - 1) {
                line_buffer[line_pos++] = buffer[i];
            }
        }
    }

    return false;
}

} // namespace detail
} // namespace XrdHttpPelican

namespace {

#ifdef __linux__

void PrintDetailedStackTrace(void **trace, int size) {
    ssize_t __attribute__((unused)) _;
    // Process each frame individually
    for (int i = 0; i < size; i++) {
        uintptr_t addr = reinterpret_cast<uintptr_t>(trace[i]);

        // Write frame number and address to stderr
        _ = write(STDERR_FILENO, "#", 1);
        WriteDecimal(STDERR_FILENO, i);
        _ = write(STDERR_FILENO, " ", 1);
        WriteHex(STDERR_FILENO, addr);
        _ = write(STDERR_FILENO, " ", 1);

        // Find which module this address belongs to
        char module_path[256];
        uintptr_t base_addr;
        int maps_fd = open("/proc/self/maps", O_RDONLY);
        if (maps_fd < 0 ||
            !XrdHttpPelican::detail::GetModuleForAddress(
                maps_fd, addr, module_path, sizeof(module_path), &base_addr)) {
            if (maps_fd >= 0) {
                close(maps_fd);
            }
            _ = write(STDERR_FILENO, "(module not found)\n", 19);
            continue;
        }
        close(maps_fd);

        // Calculate offset from base address (handle ASLR)
        uintptr_t offset = addr - base_addr;

        // Create pipe for addr2line input
        int pipe_in[2];
        if (pipe(pipe_in) != 0) {
            _ = write(STDERR_FILENO, "(pipe failed)\n", 14);
            continue;
        }

        pid_t pid = fork();
        if (pid == 0) {
            // Child process - run addr2line
            close(pipe_in[1]); // Close write end of input pipe

            dup2(pipe_in[0], STDIN_FILENO);
            close(pipe_in[0]);

            // Save the original stderr fd before we modify it
            int saved_stderr = dup(STDERR_FILENO);

            // Redirect stderr to /dev/null to suppress addr2line errors
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }

            // Redirect addr2line stdout to the original stderr (the log file)
            if (saved_stderr >= 0) {
                dup2(saved_stderr, STDOUT_FILENO);
                close(saved_stderr);
            }

            execlp("addr2line", "addr2line", "-e", module_path, "-f", "-C",
                   "-p", (char *)nullptr);
            _exit(1);
        } else if (pid > 0) {
            // Parent process
            close(pipe_in[0]); // Close read end of input pipe

            // Write the offset to addr2line
            char hex_buf[32];
            int hex_len =
                XrdHttpPelican::detail::WriteHexToBuffer(hex_buf, offset);
            hex_buf[hex_len++] = '\n';
            _ = write(pipe_in[1], hex_buf, hex_len);
            close(pipe_in[1]);

            // Wait for addr2line to finish (it writes directly to stderr)
            waitpid(pid, nullptr, 0);
        } else {
            // Fork failed
            close(pipe_in[0]);
            close(pipe_in[1]);
            _ = write(STDERR_FILENO, "(fork failed)\n", 14);
        }
    }
}

#elif defined(__APPLE__)

// Helper to write decimal to buffer (for child process args)
void WriteDecimalToBuffer(char *buf, int *pos, int value) {
    if (value < 0) {
        buf[(*pos)++] = '-';
        value = -value;
    }

    if (value == 0) {
        buf[(*pos)++] = '0';
    } else {
        char digits[16];
        int digit_count = 0;
        while (value > 0) {
            digits[digit_count++] = '0' + (value % 10);
            value /= 10;
        }
        for (int i = digit_count - 1; i >= 0; i--) {
            buf[(*pos)++] = digits[i];
        }
    }
    buf[*pos] = '\0';
}

void PrintDetailedStackTrace(void **trace, int size) {
    // Note: backtrace_symbols() uses malloc internally, so it's NOT
    // async-signal-safe. We'll invoke atos for each address without
    // pre-fetching symbols.

    for (int i = 0; i < size; i++) {
        int pipe_fds[2];
        if (pipe(pipe_fds) < 0) {
            // Fallback to raw address
            write(STDERR_FILENO, "#", 1);
            WriteDecimal(STDERR_FILENO, i);
            write(STDERR_FILENO, " ", 1);
            WriteHex(STDERR_FILENO, reinterpret_cast<uintptr_t>(trace[i]));
            write(STDERR_FILENO, "\n", 1);
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            // Fork failed, fallback to raw address
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            write(STDERR_FILENO, "#", 1);
            WriteDecimal(STDERR_FILENO, i);
            write(STDERR_FILENO, " ", 1);
            WriteHex(STDERR_FILENO, reinterpret_cast<uintptr_t>(trace[i]));
            write(STDERR_FILENO, "\n", 1);
            continue;
        }

        if (pid == 0) {
            // Child process - run atos for this single address
            close(pipe_fds[0]); // Close read end
            dup2(pipe_fds[1], STDOUT_FILENO);
            close(pipe_fds[1]);

            // Redirect stderr to /dev/null
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }

            // Build address string using async-signal-safe operations
            char addr_str[32];
            uintptr_t addr = reinterpret_cast<uintptr_t>(trace[i]);
            int addr_len =
                XrdHttpPelican::detail::WriteHexToBuffer(addr_str, addr);
            addr_str[addr_len] = '\0';

            // Build pid string
            char pid_str[32];
            int pid_pos = 0;
            WriteDecimalToBuffer(pid_str, &pid_pos, getppid());

            execlp("atos", "atos", "-p", pid_str, "-fullPath", addr_str,
                   (char *)nullptr);
            _exit(1);
        }

        // Parent process
        close(pipe_fds[1]); // Close write end

        // Write frame header
        write(STDERR_FILENO, "#", 1);
        WriteDecimal(STDERR_FILENO, i);
        write(STDERR_FILENO, " ", 1);
        WriteHex(STDERR_FILENO, reinterpret_cast<uintptr_t>(trace[i]));
        write(STDERR_FILENO, " ", 1);

        // Read atos output
        char buffer[1024];
        int bytes_read;
        bool got_output = false;

        while ((bytes_read = read(pipe_fds[0], buffer, sizeof(buffer))) > 0) {
            got_output = true;
            // Remove trailing newline from atos output if present
            if (bytes_read > 0 && buffer[bytes_read - 1] == '\n') {
                bytes_read--;
            }
            write(STDERR_FILENO, buffer, bytes_read);
        }

        close(pipe_fds[0]);

        // If atos didn't produce output, show raw address
        if (!got_output) {
            WriteHex(STDERR_FILENO, reinterpret_cast<uintptr_t>(trace[i]));
        }

        write(STDERR_FILENO, "\n", 1);

        // Wait for atos to finish
        int status;
        waitpid(pid, &status, 0);
    }
}

#else

void PrintDetailedStackTrace(void **trace, int size) {
    // Fallback for other platforms
    backtrace_symbols_fd(trace, size, STDERR_FILENO);
}

#endif

void SignalHandler(int sig) {
    ssize_t __attribute__((unused)) _;
    const char *sig_name = "UNKNOWN";
    int sig_name_len = 7; // strlen("UNKNOWN")
    if (sig == SIGSEGV) {
        sig_name = "SIGSEGV";
        sig_name_len = 7;
    } else if (sig == SIGILL) {
        sig_name = "SIGILL";
        sig_name_len = 6;
    } else if (sig == SIGABRT) {
        sig_name = "SIGABRT";
        sig_name_len = 7;
    }

    // Print signal information
    const char msg[] = "\n===== XrdHttpPelican caught signal: ";
    _ = write(STDERR_FILENO, msg, sizeof(msg) - 1);
    _ = write(STDERR_FILENO, sig_name, sig_name_len);
    _ = write(STDERR_FILENO, " =====\n", 7);

    // Get and print stack trace
    void *array[50];
    int size = backtrace(array, 50);

    const char trace_msg[] = "Stack trace:\n";
    _ = write(STDERR_FILENO, trace_msg, sizeof(trace_msg) - 1);

    PrintDetailedStackTrace(array, size);

    const char end_msg[] = "===== End of stack trace =====\n";
    _ = write(STDERR_FILENO, end_msg, sizeof(end_msg) - 1);

    // Restore default handler and re-raise signal
    struct sigaction sa;
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(sig, &sa, nullptr);

    // Unblock the signal in case it's blocked
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, sig);
    sigprocmask(SIG_UNBLOCK, &set, nullptr);

    // Re-raise the signal
    raise(sig);

    // Signal delivery is asynchronous, so sleep forever waiting for it
    while (true) {
        pause();
    }
}

} // anonymous namespace

namespace XrdHttpPelican {

void InstallSignalHandlers() {
    struct sigaction sa;
    sa.sa_handler = SignalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGILL, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
}

} // namespace XrdHttpPelican
