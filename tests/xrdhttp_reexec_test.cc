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

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

class ReExecTest : public testing::Test {
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

        // Create subdirectory for reexec test within the test run directory
        std::string test_dir = rundir + "/reexec";
        if (mkdir(test_dir.c_str(), 0755) != 0) {
            GTEST_SKIP() << "Failed to create reexec test directory at "
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
            kill(m_server_pid, SIGTERM);
            waitpid(m_server_pid, nullptr, 0);
        }

        // Close socket if open
        if (m_control_socket >= 0) {
            close(m_control_socket);
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

        config << "# XRootD test configuration for re-exec test\n";
        config << "all.trace all\n";
        config << "http.trace all\n";
        config << "xrd.trace all\n";
        config << "xrd.port any\n";
        config << "all.export /\n";
        config << "all.sitename XRootD-ReExec-Test\n";
        config << "all.adminpath " << test_dir << "\n";
        config << "all.pidpath " << test_dir << "\n";
        config << "xrd.protocol XrdHttp:any libXrdHttp.so\n";
        config << "http.exthandler xrdpelican " << binary_dir
               << "/libXrdHttpPelican.so\n";
        config << "pelican.trace all\n";
        config << "pfc.ram 256m\n"; // Enable proxy file cache
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

        // Create socket pair for control messages
        int sockets[2];
        EXPECT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
        m_control_socket = sockets[0]; // Parent keeps this one
        int child_socket = sockets[1]; // Child gets this one

        m_server_pid = fork();
        EXPECT_NE(m_server_pid, -1) << "Failed to fork";

        if (m_server_pid == 0) {
            // Child process - start xrootd
            close(m_control_socket);

            // Set all required environment variables
            setenv("XRDHTTP_PELICAN_INFO_FD",
                   std::to_string(child_socket).c_str(), 1);
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

        // Parent process - close child socket
        close(child_socket);

        // Wait for server to start
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

            // Check log file for startup message - look for server
            // initialization complete
            if (CheckLogForPattern("initialization completed", false)) {
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

    bool CheckLogForPattern(const std::string &pattern,
                            bool from_current_pos = true) {
        std::ifstream log(m_log_file);
        if (!log.is_open()) {
            return false;
        }

        if (from_current_pos && m_last_log_pos > 0) {
            log.seekg(m_last_log_pos);
        }

        std::string line;
        bool found = false;
        while (std::getline(log, line)) {
            if (line.find(pattern) != std::string::npos) {
                found = true;
            }
        }

        m_last_log_pos = log.tellg();
        log.close();
        return found;
    }

    int CountOccurrencesInLog(const std::string &pattern) {
        std::ifstream log(m_log_file);
        if (!log.is_open()) {
            return 0;
        }

        int count = 0;
        std::string line;
        while (std::getline(log, line)) {
            if (line.find(pattern) != std::string::npos) {
                count++;
            }
        }

        log.close();
        return count;
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

    bool WaitForLogPattern(const std::string &pattern,
                           bool from_current_pos = true,
                           int timeout_ms = 2000) {
        // Poll every 100ms for up to timeout_ms
        int iterations = timeout_ms / 100;
        for (int i = 0; i < iterations; i++) {
            if (CheckLogForPattern(pattern, from_current_pos)) {
                return true;
            }
            usleep(100000); // 100ms
        }
        return false;
    }

    bool WaitForCountIncrease(const std::string &pattern, int initial_count,
                              int timeout_ms = 2000) {
        // Poll every 100ms for up to timeout_ms
        int iterations = timeout_ms / 100;
        for (int i = 0; i < iterations; i++) {
            int current_count = CountOccurrencesInLog(pattern);
            if (current_count > initial_count) {
                return true;
            }
            usleep(100000); // 100ms
        }
        return false;
    }

    bool SendReExecCommand() {
        char cmd = 8; // Message type 8 for re-exec

        struct iovec iov;
        iov.iov_base = &cmd;
        iov.iov_len = sizeof(cmd);

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        ssize_t result = sendmsg(m_control_socket, &msg, 0);
        return result == sizeof(cmd);
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
    int m_control_socket = -1;
    std::streampos m_last_log_pos = 0;
};

TEST_F(ReExecTest, ReExecTriggersRestart) {
    // Start the server
    ASSERT_TRUE(StartXrootdServer()) << "Failed to start xrootd server";

    // Wait for plugin to load
    ASSERT_TRUE(WaitForLogPattern("Executable path saved for re-exec", false))
        << "Plugin did not load or log executable path within timeout";

    // Record initial startup count
    std::string startup_marker = "Executable path saved for re-exec";
    int initial_count = CountOccurrencesInLog(startup_marker);
    ASSERT_GE(initial_count, 1) << "Server did not log startup message";

    // Record position in log
    std::ifstream log(m_log_file);
    log.seekg(0, std::ios::end);
    m_last_log_pos = log.tellg();
    log.close();

    // Send re-exec command
    ASSERT_TRUE(SendReExecCommand()) << "Failed to send re-exec command";

    // Wait for server to process re-exec
    EXPECT_TRUE(WaitForLogPattern("Re-executing process"))
        << "Re-exec command was not logged within timeout";

    // Wait for the server to restart
    EXPECT_TRUE(WaitForCountIncrease(startup_marker, initial_count))
        << "Server did not appear to restart within timeout";

    // Verify server is still running
    int status;
    pid_t result = waitpid(m_server_pid, &status, WNOHANG);
    EXPECT_EQ(result, 0) << "Server process exited after re-exec";

    if (testing::Test::HasFailure()) {
        DumpLogFile();
    }
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
