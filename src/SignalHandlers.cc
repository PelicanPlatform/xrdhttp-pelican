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

#include <atomic>

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

#ifdef __linux__
#include <sys/syscall.h>
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

// Absolute path to the addr2line symbolizer (Linux only), resolved during
// signal handler installation.  Empty string means no symbolizer is
// available.  Resolved up front so the post-fork child can execv() it
// without a PATH search, which is not async-signal-safe.
static char g_symbolizer_path[512] = {0};

// Set once the first crashing thread enters the handler; later threads park
// in pause() so only one trace is produced and no handler-vs-handler
// deadlock can form.
static std::atomic_flag g_crash_in_progress = ATOMIC_FLAG_INIT;

#if defined(__linux__)
// Fork without running the registered atfork handlers.
//
// The handlers are the deadlock: glibc's fork() acquires the atfork lock,
// the stdio list locks, and every malloc arena mutex.  A synchronous fault
// signal (SIGSEGV/SIGABRT from heap corruption) is delivered on the thread
// that already holds an arena mutex, so calling fork() from the handler
// self-deadlocks and wedges the whole process (issue #25).  _Fork() is the
// async-signal-safe variant that skips all of that; the child only ever
// calls close/dup2/open/execv/_exit, so it has no need for the handlers.
pid_t AsyncSignalSafeFork() {
#if defined(__GLIBC__) &&                                                      \
    (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 34))
    return _Fork();
#else
    // Pre-2.34 glibc has no _Fork(); clone with just SIGCHLD is the direct
    // syscall equivalent.  All arguments past the flags are zero, so the
    // arch-specific clone argument orders agree except on s390, where the
    // flags come second.
#if defined(__s390__) || defined(__s390x__)
    return syscall(SYS_clone, 0L, (long)SIGCHLD, 0L, 0L, 0L);
#else
    return syscall(SYS_clone, (long)SIGCHLD, 0L, 0L, 0L, 0L);
#endif
#endif
}
#endif // defined(__linux__)

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

#if defined(__linux__)
// Resolve an executable to an absolute path, checking common locations and
// then $PATH.  Called during initialization, not in signal handler context,
// so ordinary libc use is fine here.  Returns true and fills `out` on
// success.
bool ResolveExecutable(const char *exe_name, char *out, size_t out_size) {
    const char *dirs[] = {"/usr/bin", "/bin", "/usr/local/bin", nullptr};
    for (int i = 0; dirs[i] != nullptr; i++) {
        int len = snprintf(out, out_size, "%s/%s", dirs[i], exe_name);
        if (len > 0 && (size_t)len < out_size && access(out, X_OK) == 0) {
            return true;
        }
    }

    const char *path = getenv("PATH");
    if (path == nullptr) {
        out[0] = '\0';
        return false;
    }
    const char *start = path;
    while (true) {
        const char *end = strchr(start, ':');
        size_t dir_len = end ? (size_t)(end - start) : strlen(start);
        if (dir_len > 0) {
            int len = snprintf(out, out_size, "%.*s/%s", (int)dir_len, start,
                               exe_name);
            if (len > 0 && (size_t)len < out_size && access(out, X_OK) == 0) {
                return true;
            }
        }
        if (end == nullptr) {
            break;
        }
        start = end + 1;
    }
    out[0] = '\0';
    return false;
}
#endif // defined(__linux__)

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
                    // After parsing 'end', we're at the space before perms.
                    // The file offset (field 2) is extracted along the way:
                    // subtracting it from the segment start yields the
                    // module's load base, which is what symbolizers need.
                    uintptr_t file_offset = 0;
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
                        } else if (space_count == 2) {
                            int digit;
                            if (ParseHexChar(line_buffer[pos], &digit)) {
                                file_offset = (file_offset << 4) | digit;
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

                        // Return the module's load base: the segment start
                        // minus the offset at which the file is mapped
                        // there.  (The containing segment's start is NOT
                        // the load base when the linker places text after a
                        // leading read-only segment, e.g. x86_64's default
                        // -z separate-code layout.)
                        *base_addr = start - file_offset;
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

        // Compute the address to hand the symbolizer.  base_addr is the
        // module's load base, so the difference is the module-relative
        // virtual address -- correct for ET_DYN objects (shared libraries
        // and PIE executables, which link at vaddr 0).  A fixed-position
        // ET_EXEC executable links at an absolute address, so there the
        // runtime address already is the virtual address; sniff e_type from
        // the ELF header (plain open/read, async-signal-safe) to tell the
        // two apart.
        uintptr_t sym_addr = addr - base_addr;
        int elf_fd = open(module_path, O_RDONLY);
        if (elf_fd >= 0) {
            unsigned char ehdr[18];
            if (read(elf_fd, ehdr, sizeof(ehdr)) == (ssize_t)sizeof(ehdr) &&
                ehdr[0] == 0x7f && ehdr[1] == 'E' && ehdr[2] == 'L' &&
                ehdr[3] == 'F') {
                bool big_endian = ehdr[5] == 2; // EI_DATA == ELFDATA2MSB
                uint16_t e_type = big_endian ? ((ehdr[16] << 8) | ehdr[17])
                                             : (ehdr[16] | (ehdr[17] << 8));
                if (e_type == 2) { // ET_EXEC
                    sym_addr = addr;
                }
            }
            close(elf_fd);
        }

        // If addr2line is not available, just print module path and offset
        if (g_symbolizer_path[0] == '\0') {
            // Write module path
            int path_len = 0;
            while (module_path[path_len] != '\0' && path_len < 256) {
                path_len++;
            }
            _ = write(STDERR_FILENO, module_path, path_len);
            _ = write(STDERR_FILENO, " ", 1);
            WriteHex(STDERR_FILENO, sym_addr);
            _ = write(STDERR_FILENO, "\n", 1);
            continue;
        }

        // Create pipe for addr2line input
        int pipe_in[2];
        if (pipe(pipe_in) != 0) {
            _ = write(STDERR_FILENO, "(pipe failed)\n", 14);
            continue;
        }

        pid_t pid = AsyncSignalSafeFork();
        if (pid == 0) {
            // Child process - run addr2line.  Because AsyncSignalSafeFork()
            // skips the atfork handlers, the child inherits whatever lock
            // state the crashing process had (e.g. a held malloc arena
            // mutex), so only async-signal-safe calls are permitted here:
            // close/dup2/open/execv on a pre-resolved absolute path.
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

            char *const argv[] = {const_cast<char *>("addr2line"),
                                  const_cast<char *>("-e"),
                                  module_path,
                                  const_cast<char *>("-f"),
                                  const_cast<char *>("-C"),
                                  const_cast<char *>("-p"),
                                  nullptr};
            execv(g_symbolizer_path, argv);
            _exit(1);
        } else if (pid > 0) {
            // Parent process
            close(pipe_in[0]); // Close read end of input pipe

            // Write the symbolization address to addr2line
            char hex_buf[32];
            int hex_len =
                XrdHttpPelican::detail::WriteHexToBuffer(hex_buf, sym_addr);
            hex_buf[hex_len++] = '\n';
            _ = write(pipe_in[1], hex_buf, hex_len);
            close(pipe_in[1]);

            // Wait for addr2line to finish (it writes directly to stderr).
            // If it failed (e.g. the "module" is [vdso] or the exec failed),
            // it produced no output, so terminate the frame's line ourselves.
            int status = 0;
            waitpid(pid, &status, 0);
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                _ = write(STDERR_FILENO, "(no symbol info)\n", 17);
            }
        } else {
            // Fork failed
            close(pipe_in[0]);
            close(pipe_in[1]);
            _ = write(STDERR_FILENO, "(fork failed)\n", 14);
        }
    }
}

#elif defined(__APPLE__)

void PrintDetailedStackTrace(void **trace, int size) {
    // No external symbolizer on macOS: fork() here runs the atfork prepare
    // handlers (libmalloc takes every zone lock), so it deadlocks in exactly
    // the scenario this handler exists for, and there is no _Fork()
    // equivalent.  Worse, libmalloc's fatal corruption paths mark the
    // process for termination before raising the catchable SIGABRT, so a
    // slow per-frame atos would be cut short anyway.  Print module+offset
    // and the nearest exported symbol via dladdr instead; full
    // symbolization can be done offline with atos.  (dladdr takes the dyld
    // lock and is not strictly async-signal-safe; the alarm() watchdog in
    // the handler bounds that hazard.)
    for (int i = 0; i < size; i++) {
        write(STDERR_FILENO, "#", 1);
        WriteDecimal(STDERR_FILENO, i);
        write(STDERR_FILENO, " ", 1);
        WriteHex(STDERR_FILENO, reinterpret_cast<uintptr_t>(trace[i]));
        write(STDERR_FILENO, " ", 1);

        Dl_info info;
        if (dladdr(trace[i], &info) && info.dli_fname) {
            // Write library name
            const char *fname = info.dli_fname;
            int fname_len = 0;
            while (fname[fname_len] != '\0')
                fname_len++;
            write(STDERR_FILENO, fname, fname_len);
            write(STDERR_FILENO, " ", 1);

            // Write offset from library base
            uintptr_t offset = (uintptr_t)trace[i] - (uintptr_t)info.dli_fbase;
            WriteHex(STDERR_FILENO, offset);

            // Write nearest exported symbol, if any
            if (info.dli_sname && info.dli_saddr) {
                write(STDERR_FILENO, " (", 2);
                const char *sname = info.dli_sname;
                int sname_len = 0;
                while (sname[sname_len] != '\0')
                    sname_len++;
                write(STDERR_FILENO, sname, sname_len);
                write(STDERR_FILENO, " + ", 3);
                WriteHex(STDERR_FILENO,
                         (uintptr_t)trace[i] - (uintptr_t)info.dli_saddr);
                write(STDERR_FILENO, ")", 1);
            }
        }
        write(STDERR_FILENO, "\n", 1);
    }
}

#else

void PrintDetailedStackTrace(void **trace, int size) {
    // Fallback for other platforms
    backtrace_symbols_fd(trace, size, STDERR_FILENO);
}

#endif

void SignalHandler(int sig, siginfo_t *info, void * /*ucontext*/) {
    // First crashing thread wins; any other thread that faults concurrently
    // parks here until the winner's re-raise terminates the process.
    // (std::atomic_flag is guaranteed lock-free and async-signal-safe.)
    if (g_crash_in_progress.test_and_set()) {
        while (true) {
            pause();
        }
    }

    // Watchdog: the trace below is best-effort.  backtrace() retains a
    // residual AS-Unsafe heap/lock hazard even after the warm-up call at
    // install time, and the symbolizer child could in principle hang.  If
    // anything wedges, let SIGALRM's default action terminate the process
    // rather than hanging it forever.
    struct sigaction alarm_sa;
    alarm_sa.sa_handler = SIG_DFL;
    sigemptyset(&alarm_sa.sa_mask);
    alarm_sa.sa_flags = 0;
    sigaction(SIGALRM, &alarm_sa, nullptr);
    sigset_t alarm_set;
    sigemptyset(&alarm_set);
    sigaddset(&alarm_set, SIGALRM);
    sigprocmask(SIG_UNBLOCK, &alarm_set, nullptr);
    alarm(60);

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

    // Restore default handler and re-deliver the signal
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

    // For kernel-generated faults (si_code > 0), simply return: the faulting
    // instruction re-executes and faults again under the default handler, so
    // the core dump records the true siginfo (si_addr) and fault-time
    // registers instead of a raise() from this handler.  User-sent signals
    // (kill(2), abort(2)'s tgkill: si_code <= 0) would not re-fault on
    // return, so those are re-raised instead; the core then shows the
    // raise() but the original frames remain further down the stack.
    if (info && info->si_code > 0 && (sig == SIGSEGV || sig == SIGILL)) {
        return;
    }

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
    // Resolve the symbolizer to an absolute path now, in normal (non-signal)
    // context, so the handler's post-fork child can execv() it directly.
    // Only Linux runs an external symbolizer from the handler: macOS has no
    // async-signal-safe fork, so its handler symbolizes via dladdr instead.
#ifdef __linux__
    ResolveExecutable("addr2line", g_symbolizer_path,
                      sizeof(g_symbolizer_path));
#else
    g_symbolizer_path[0] = '\0';
#endif

    // Warm up backtrace(): its first call may dlopen/initialize the unwinder
    // (glibc annotates it AS-Unsafe init/dlopen/plugin), which must not
    // happen for the first time in signal context.  This does not clear the
    // residual heap/lock hazard; the alarm() watchdog in the handler covers
    // that.
    void *warmup[4];
    backtrace(warmup, 4);

    struct sigaction sa;
    // SA_SIGINFO: the handler uses si_code to distinguish genuine faults
    // (re-delivered by returning, preserving the fault's siginfo in the
    // core dump) from user-sent signals (re-raised).
    sa.sa_sigaction = SignalHandler;
    // Block the other handled fault signals while the handler runs so a
    // second fault class (e.g. SIGABRT during the SIGSEGV handler) cannot
    // interleave on the same thread.
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGSEGV);
    sigaddset(&sa.sa_mask, SIGILL);
    sigaddset(&sa.sa_mask, SIGABRT);
    sa.sa_flags = SA_RESTART | SA_SIGINFO;

    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGILL, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
}

} // namespace XrdHttpPelican
