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

#include "../src/SignalHandlers.hh"

#include <gtest/gtest.h>

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <string>

class StackTraceTest : public testing::Test {
  protected:
    void SetUp() override {
        // Get BINARY_DIR from environment
        const char *binary_dir = getenv("BINARY_DIR");
        if (!binary_dir) {
            GTEST_SKIP() << "BINARY_DIR not set - cannot run test";
        }

        std::string binary_dir_str = binary_dir;
        std::string setup_file = binary_dir_str + "/tests/pelican/setup.sh";

        // Source setup.sh to get XROOTD_BIN and XROOTD_CONFIGDIR
        std::ifstream setup(setup_file);
        if (!setup.is_open()) {
            GTEST_SKIP() << "Test fixture setup file not found at "
                         << setup_file;
        }

        // Parse setup.sh for XROOTD_BIN, XROOTD_CONFIGDIR, and RUNDIR
        std::string line;
        std::string rundir;
        std::string xrootd_configdir;
        while (std::getline(setup, line)) {
            if (line.find("XROOTD_BIN=") == 0) {
                m_xrootd_bin = line.substr(11); // Skip "XROOTD_BIN="
            } else if (line.find("XROOTD_CONFIGDIR=") == 0) {
                xrootd_configdir = line.substr(17); // Skip "XROOTD_CONFIGDIR="
            } else if (line.find("RUNDIR=") == 0) {
                rundir = line.substr(7); // Skip "RUNDIR="
            }
        }
        setup.close();

        if (m_xrootd_bin.empty()) {
            GTEST_SKIP() << "XROOTD_BIN not found in setup.sh";
        }
        if (xrootd_configdir.empty()) {
            GTEST_SKIP() << "XROOTD_CONFIGDIR not found in setup.sh";
        }
        if (rundir.empty()) {
            GTEST_SKIP() << "RUNDIR not found in setup.sh";
        }

        // Create subdirectory for stacktrace test within the test run directory
        std::string test_dir = rundir + "/stacktrace";

        // Remove directory if it exists from a previous run
        system(("rm -rf " + test_dir).c_str());

        if (mkdir(test_dir.c_str(), 0755) != 0) {
            GTEST_SKIP() << "Failed to create stacktrace test directory at "
                         << test_dir;
        }

        m_config_file = test_dir + "/xrootd.cfg";
        m_log_file = test_dir + "/xrootd.log";
        m_ca_file = test_dir + "/ca.pem";
        m_cert_file = test_dir + "/cert.pem";
        m_cache_self_test_file = test_dir + "/cache_self_test";
        m_cache_self_test_file_cinfo = test_dir + "/cache_self_test.cinfo";
        m_authfile_generated = test_dir + "/authfile";
        m_scitokens_generated = test_dir + "/scitokens";

        // Create basic config file
        CreateXrootdConfig(test_dir, binary_dir_str, xrootd_configdir);

        // Create dummy files
        CreateDummyFile(m_ca_file, "CA certificate");
        CreateDummyFile(m_cert_file, "Host certificate");
        CreateDummyFile(m_cache_self_test_file, "cache self test");
        CreateDummyFile(m_cache_self_test_file_cinfo, "cache self test cinfo");
        CreateDummyFile(m_authfile_generated, "authfile");
        CreateDummyFile(m_scitokens_generated, "scitokens");
    }

    void TearDown() override {
        // Kill server if still running
        if (m_server_pid > 0) {
            kill(m_server_pid, SIGKILL);
            waitpid(m_server_pid, nullptr, 0);
        }

        // Test directory cleanup is handled by the pelican fixture teardown
    }

    void CreateDummyFile(const std::string &path, const std::string &content) {
        std::ofstream file(path);
        ASSERT_TRUE(file.is_open()) << "Failed to create " << path;
        file << content;
        file.close();
    }

    void CreateXrootdConfig(const std::string &test_dir,
                            const std::string &binary_dir,
                            const std::string &xrootd_configdir) {
        std::ofstream config(m_config_file);
        ASSERT_TRUE(config.is_open()) << "Failed to create config file";

        config << "# XRootD test configuration for stack trace test\n";
        config << "all.trace all\n";
        config << "http.trace all\n";
        config << "xrd.trace all\n";
        config << "xrd.port any\n";
        config << "all.export /\n";
        config << "all.sitename XRootD-StackTrace-Test\n";
        config << "all.adminpath " << test_dir << "\n";
        config << "all.pidpath " << test_dir << "\n";
        config << "xrd.protocol XrdHttp:any libXrdHttp.so\n";
        config << "http.exthandler xrdpelican " << binary_dir
               << "/libXrdHttpPelican.so\n";
        config << "pelican.trace all\n";
        config << "xrd.tlsca certfile " << xrootd_configdir << "/tlsca.pem\n";
        config << "xrd.tls " << xrootd_configdir << "/tls.crt "
               << xrootd_configdir << "/tls.key\n";
        config << "oss.localroot " << test_dir << "\n";

        config.close();
    }

    bool StartXrootdServer() {
        // Use xrootd binary from setup.sh
        if (m_xrootd_bin.empty()) {
            return false;
        }

        m_server_pid = fork();
        EXPECT_NE(m_server_pid, -1) << "Failed to fork";

        if (m_server_pid == 0) {
            // Child process - start xrootd

            // Set all required environment variables (skip INFO_FD - not needed
            // for this test)
            setenv("XRDHTTP_PELICAN_CA_FILE", m_ca_file.c_str(), 1);
            setenv("XRDHTTP_PELICAN_CERT_FILE", m_cert_file.c_str(), 1);
            setenv("XRDHTTP_PELICAN_CACHE_SELF_TEST_FILE",
                   m_cache_self_test_file.c_str(), 1);
            setenv("XRDHTTP_PELICAN_CACHE_SELF_TEST_FILE_CINFO",
                   m_cache_self_test_file_cinfo.c_str(), 1);
            setenv("XRDHTTP_PELICAN_AUTHFILE_GENERATED",
                   m_authfile_generated.c_str(), 1);
            setenv("XRDHTTP_PELICAN_SCITOKENS_GENERATED",
                   m_scitokens_generated.c_str(), 1);

            // Redirect stdout/stderr to log file
            int log_fd =
                open(m_log_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (log_fd != -1) {
                dup2(log_fd, STDOUT_FILENO);
                dup2(log_fd, STDERR_FILENO);
                close(log_fd);
            }

            // Execute xrootd
            execl(m_xrootd_bin.c_str(), m_xrootd_bin.c_str(), "-c",
                  m_config_file.c_str(), "-l", m_log_file.c_str(), nullptr);

            // If we get here, exec failed
            perror("exec failed");
            exit(1);
        }

        // Parent process - wait for server to start
        return WaitForServerStart();
    }

    bool WaitForServerStart() {
        // Wait up to 10 seconds for server to start
        for (int i = 0; i < 100; i++) {
            // Check if process is still alive
            int status;
            pid_t result = waitpid(m_server_pid, &status, WNOHANG);
            if (result != 0) {
                // Process exited
                std::cerr << "Server process exited unexpectedly" << std::endl;
                DumpLogFile();
                return false;
            }

            // Check log file for startup message
            if (CheckLogForPattern("initialization completed")) {
                // Wait a bit more for full initialization
                usleep(500000); // 500ms
                return true;
            }

            usleep(100000); // 100ms
        }

        std::cerr << "Server failed to start within timeout" << std::endl;
        DumpLogFile();
        return false;
    }

    bool CheckLogForPattern(const std::string &pattern) {
        std::ifstream log(m_log_file);
        if (!log.is_open()) {
            return false;
        }

        std::string line;
        while (std::getline(log, line)) {
            if (line.find(pattern) != std::string::npos) {
                log.close();
                return true;
            }
        }

        log.close();
        return false;
    }

    void DumpLogFile() {
        std::ifstream log(m_log_file);
        if (log.is_open()) {
            std::cerr << "=== Log file contents ===" << std::endl;
            std::string line;
            while (std::getline(log, line)) {
                std::cerr << line << std::endl;
            }
            std::cerr << "=== End of log ===" << std::endl;
            log.close();
        }
    }

    bool WaitForProcessExit(int &status, int timeout_ms = 5000) {
        // Poll every 100ms for up to timeout_ms
        int iterations = timeout_ms / 100;
        for (int i = 0; i < iterations; i++) {
            pid_t result = waitpid(m_server_pid, &status, WNOHANG);
            if (result == m_server_pid) {
                return true;
            }
            if (result < 0) {
                std::cerr << "waitpid failed: " << strerror(errno) << std::endl;
                return false;
            }
            usleep(100000); // 100ms
        }
        std::cerr << "Process did not exit within timeout" << std::endl;
        return false;
    }

    bool WaitForLogPattern(const std::string &pattern, int timeout_ms = 2000) {
        // Poll every 100ms for up to timeout_ms
        int iterations = timeout_ms / 100;
        for (int i = 0; i < iterations; i++) {
            if (CheckLogForPattern(pattern)) {
                return true;
            }
            usleep(100000); // 100ms
        }
        return false;
    }

    std::string m_xrootd_bin;
    std::string m_config_file;
    std::string m_log_file;
    std::string m_ca_file;
    std::string m_cert_file;
    std::string m_cache_self_test_file;
    std::string m_cache_self_test_file_cinfo;
    std::string m_authfile_generated;
    std::string m_scitokens_generated;
    pid_t m_server_pid = -1;
};

TEST_F(StackTraceTest, SignalHandlersInstalled) {
    // Start server
    ASSERT_TRUE(StartXrootdServer()) << "Failed to start XRootD server";

    // Wait for signal handlers to be installed (should be immediate with plugin
    // load)
    ASSERT_TRUE(WaitForLogPattern("Signal handlers installed", 2000))
        << "Signal handlers were not installed within timeout";

    // Success - cleanup will be done in TearDown
    m_server_pid =
        -1; // Don't kill in TearDown since we're testing normal shutdown
}

TEST_F(StackTraceTest, SegfaultPrintsStackTrace) {
    // Start server
    ASSERT_TRUE(StartXrootdServer()) << "Failed to start XRootD server";

    // Wait for signal handlers to be installed
    ASSERT_TRUE(WaitForLogPattern("Signal handlers installed", 2000))
        << "Signal handlers were not installed within timeout";

    // Send SIGSEGV to trigger stack trace
    kill(m_server_pid, SIGSEGV);

    // Wait for process to handle signal and exit
    int status;
    ASSERT_TRUE(WaitForProcessExit(status))
        << "Process did not exit within timeout";

    m_server_pid = -1;

    // Verify the process was terminated by SIGSEGV
    EXPECT_TRUE(WIFSIGNALED(status))
        << "Process did not terminate due to signal";
    if (WIFSIGNALED(status)) {
        EXPECT_EQ(WTERMSIG(status), SIGSEGV)
            << "Process terminated by unexpected signal";
    }

    // Check that stack trace was printed
    EXPECT_TRUE(CheckLogForPattern("XrdHttpPelican caught signal: SIGSEGV"))
        << "Signal handler message not found in log";
    EXPECT_TRUE(CheckLogForPattern("Stack trace:"))
        << "Stack trace header not found in log";

    if (testing::Test::HasFailure()) {
        DumpLogFile();
    }
}

TEST_F(StackTraceTest, SigillPrintsStackTrace) {
    // Start server
    ASSERT_TRUE(StartXrootdServer()) << "Failed to start XRootD server";

    // Wait for signal handlers to be installed
    ASSERT_TRUE(WaitForLogPattern("Signal handlers installed", 2000))
        << "Signal handlers were not installed within timeout";

    // Send SIGILL to trigger stack trace
    kill(m_server_pid, SIGILL);

    // Wait for process to handle signal and exit
    int status;
    ASSERT_TRUE(WaitForProcessExit(status))
        << "Process did not exit within timeout";

    m_server_pid = -1;

    // Verify the process was terminated by SIGILL
    EXPECT_TRUE(WIFSIGNALED(status))
        << "Process did not terminate due to signal";
    if (WIFSIGNALED(status)) {
        EXPECT_EQ(WTERMSIG(status), SIGILL)
            << "Process terminated by unexpected signal";
    }

    // Check that stack trace was printed
    EXPECT_TRUE(CheckLogForPattern("XrdHttpPelican caught signal: SIGILL"))
        << "Signal handler message not found in log";
    EXPECT_TRUE(CheckLogForPattern("Stack trace:"))
        << "Stack trace header not found in log";

    if (testing::Test::HasFailure()) {
        DumpLogFile();
    }
}

TEST_F(StackTraceTest, SigabrtPrintsStackTrace) {
    // Start server
    ASSERT_TRUE(StartXrootdServer()) << "Failed to start XRootD server";

    // Wait for signal handlers to be installed
    ASSERT_TRUE(WaitForLogPattern("Signal handlers installed", 2000))
        << "Signal handlers were not installed within timeout";

    // Send SIGABRT to trigger stack trace
    kill(m_server_pid, SIGABRT);

    // Wait for process to handle signal and exit
    int status;
    ASSERT_TRUE(WaitForProcessExit(status))
        << "Process did not exit within timeout";

    m_server_pid = -1;

    // Verify the process was terminated by SIGABRT
    EXPECT_TRUE(WIFSIGNALED(status))
        << "Process did not terminate due to signal";
    if (WIFSIGNALED(status)) {
        EXPECT_EQ(WTERMSIG(status), SIGABRT)
            << "Process terminated by unexpected signal";
    }

    // Check that stack trace was printed
    EXPECT_TRUE(CheckLogForPattern("XrdHttpPelican caught signal: SIGABRT"))
        << "Signal handler message not found in log";
    EXPECT_TRUE(CheckLogForPattern("Stack trace:"))
        << "Stack trace header not found in log";

    if (testing::Test::HasFailure()) {
        DumpLogFile();
    }
}
