/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

#include <XrdOuc/XrdOucEnv.hh>
#include <XrdSys/XrdSysError.hh>
#include <XrdSys/XrdSysLogger.hh>
#include <private/XrdHttp/XrdHttpExtHandler.hh>

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <string>
#include <vector>

extern "C" {

extern XrdHttpExtHandler *XrdHttpGetExtHandler(XrdSysError *log,
                                               const char *config,
                                               const char * /*parms*/,
                                               XrdOucEnv *myEnv);
}

class HandlerDeathTest : public testing::Test {
  public:
    // Child process function for shutdown
    void InnerShutdown();

    // Child process function for overwriting files
    void InnerOverwrite();

    // Child process function for sending signals to self
    void InnerSignal();

  private:
    void SetUp() override;

    void TearDown() override;

    // Launch the XrdHttp handler, spawning a worker thread.
    // Should be done in a DeathTest as the worker is otherwise launched once.
    void LaunchHandler();

    // Write a simple test file with some known contents.
    void WriteTestFile(const std::string &location,
                       const std::string &contents);

    // Read test file; verify it has known contents.
    void CheckTestFile(const std::string &location,
                       const std::string &contents);

    // Create a temporary file given a template
    std::string CreateTempfile(const std::string &location);

    // Send a specific command to the processing thread
    void SendCommand(char cmd, int socket, int fd);

    std::string m_ca_file;
    std::string m_cert_file;
    std::string m_ca_file_overwrite;
    std::string m_cert_file_overwrite;

    int m_socket[2];
};

std::string HandlerDeathTest::CreateTempfile(const std::string &location) {
    auto location_template = location + ".XXXXXX";
    std::vector<char> location_template_buff;
    location_template_buff.resize(location_template.size() + 1);
    std::copy(location_template.begin(), location_template.end(),
              location_template_buff.begin());
    location_template_buff[location_template.size()] = '\0';

    int fd;
    EXPECT_NE(fd = mkstemp(location_template_buff.data()), -1);
    close(fd);

    return location_template_buff.data();
}

void HandlerDeathTest::CheckTestFile(const std::string &location,
                                     const std::string &expected_contents) {
    static const int maxsize = 4096;
    ASSERT_LE(expected_contents.size(), maxsize);

    std::string contents;
    usleep(5'000);
    for (int idx = 0; idx < 10; idx++) {
        auto fd = open(location.c_str(), O_RDONLY);
        ASSERT_NE(fd, -1);

        std::vector<char> buff;
        buff.resize(maxsize);
        auto remaining = buff.size();
        off_t offset = 0;
        while (remaining) {
            int rval = read(fd, buff.data() + offset, remaining);
            if (rval == -1 && rval == EINTR) {
                continue;
            }
            ASSERT_GE(rval, 0);
            if (rval == 0) {
                break;
            }
            remaining -= rval;
            offset += rval;
        }
        close(fd);

        contents = std::string{buff.data()};
        if (contents == expected_contents) {
            return;
        }
        usleep(50'000);
    }
    fprintf(stderr, "Contents: %s\nExpected contents: %s\n", contents.c_str(),
            expected_contents.c_str());
    ASSERT_STREQ(contents.c_str(), expected_contents.c_str());
    ASSERT_TRUE(contents == expected_contents);
    ASSERT_TRUE(false);
    fprintf(stderr, "Passed check test.\n");
}

void HandlerDeathTest::WriteTestFile(const std::string &location,
                                     const std::string &contents) {
    auto fd = open(location.c_str(), O_WRONLY);
    EXPECT_NE(fd, -1) << "Error opening " << location << ": " << strerror(fd);

    off_t offset = 0;
    auto remaining = contents.size();
    while (remaining) {
        int rval = write(fd, contents.data() + offset, remaining);
        if (rval == -1 && rval == EINTR) {
            continue;
        }
        ASSERT_GE(rval, 0);
        remaining -= rval;
        offset += rval;
    }
    close(fd);
}

void HandlerDeathTest::SetUp() {
    m_socket[0] = -1;
    m_socket[1] = -1;

    m_ca_file = CreateTempfile("ca_file");
    setenv("XRDHTTP_PELICAN_CA_FILE", m_ca_file.c_str(), 1);
    WriteTestFile(m_ca_file, "This is a CA file");

    m_ca_file_overwrite = CreateTempfile("ca_file_overwrite");
    WriteTestFile(m_ca_file_overwrite, "This is a new CA file");

    m_cert_file = CreateTempfile("cert_file");
    setenv("XRDHTTP_PELICAN_CERT_FILE", m_cert_file.c_str(), 1);
    WriteTestFile(m_cert_file, "This is a cert file");

    m_cert_file_overwrite = CreateTempfile("cert_file_overwrite");
    WriteTestFile(m_cert_file_overwrite, "This is a new cert file");
}

void HandlerDeathTest::TearDown() {
    if (!m_ca_file.empty()) {
        EXPECT_EQ(unlink(m_ca_file.c_str()), 0);
    }
    if (!m_cert_file.empty()) {
        EXPECT_EQ(unlink(m_cert_file.c_str()), 0);
    }
    if (!m_ca_file_overwrite.empty()) {
        EXPECT_EQ(unlink(m_ca_file_overwrite.c_str()), 0);
    }
    if (!m_cert_file_overwrite.empty()) {
        EXPECT_EQ(unlink(m_cert_file_overwrite.c_str()), 0);
    }
}

void HandlerDeathTest::LaunchHandler() {
    auto log = new XrdSysLogger();
    auto eMsg = new XrdSysError(log, "Shutdown");
    XrdOucEnv env;

    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, m_socket), 0);

    setenv("XRDHTTP_PELICAN_INFO_FD", std::to_string(m_socket[1]).c_str(), 1);
    ASSERT_NE(XrdHttpGetExtHandler(eMsg, "", nullptr, &env), nullptr);
}

void HandlerDeathTest::InnerShutdown() {
    LaunchHandler();

    close(m_socket[0]);

    // Above close should trigger the handler thread to SIGTERM the process.
    sleep(2);
}

void HandlerDeathTest::SendCommand(char cmd, int socket, int fd) {
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } controlMsg;

    struct msghdr msg;
    memset(&msg, '\0', sizeof(msg));

    struct iovec iov;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    iov.iov_base = &cmd;
    iov.iov_len = sizeof(cmd);

    msg.msg_control = controlMsg.buf;
    msg.msg_controllen = sizeof(controlMsg.buf);

    auto cmsgp = CMSG_FIRSTHDR(&msg);
    cmsgp->cmsg_level = SOL_SOCKET;
    cmsgp->cmsg_type = SCM_RIGHTS;
    cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsgp), &fd, sizeof(int));

    ASSERT_EQ(sendmsg(socket, &msg, 0), 1);
};

TEST_F(HandlerDeathTest, Shutdown) {
    EXPECT_EXIT(InnerShutdown(), testing::KilledBySignal(SIGTERM), "");
}

void HandlerDeathTest::InnerSignal() {
    LaunchHandler();

    char messageBuffer[5];
    union {
        char buf[sizeof(uint32_t)];
        uint32_t signal;
    } signalBuffer;
    signalBuffer.signal = htonl(SIGINT);
    messageBuffer[0] = 3;
    memcpy(messageBuffer + 1, signalBuffer.buf, sizeof(signalBuffer));

    ASSERT_NE(send(m_socket[0], messageBuffer, sizeof(messageBuffer), 0), -1);

    // Above command should trigger a SIGINT; sleep until it is received
    sleep(2);
}

TEST_F(HandlerDeathTest, Signal) {
    EXPECT_EXIT(InnerSignal(), testing::KilledBySignal(SIGINT), "");
}

void HandlerDeathTest::InnerOverwrite() {
    LaunchHandler();

    auto fd = open(m_ca_file_overwrite.c_str(), O_RDONLY);
    ASSERT_NE(fd, -1);
    SendCommand(1, m_socket[0], fd);
    CheckTestFile(m_ca_file, "This is a new CA file");

    ASSERT_NE(fd = open(m_cert_file_overwrite.c_str(), O_RDONLY), -1);
    SendCommand(2, m_socket[0], fd);
    CheckTestFile(m_cert_file, "This is a new cert file");
}

TEST_F(HandlerDeathTest, Overwrite) { InnerOverwrite(); }
