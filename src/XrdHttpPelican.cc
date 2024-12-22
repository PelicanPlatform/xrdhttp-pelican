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

#include "private/XrdHttp/XrdHttpExtHandler.hh"

#include "XrdSys/XrdSysError.hh"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>

#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

class PelicanHandler : public XrdHttpExtHandler {
  public:
    PelicanHandler(XrdSysError *log, const char *config, XrdOucEnv *myEnv);
    virtual ~PelicanHandler();

    virtual bool MatchesPath(const char *verb, const char *path) override;
    virtual int ProcessReq(XrdHttpExtReq &req) override;
    virtual int Init(const char *cfgfile) override { return 0; }

  private:
    // A thread that does nothing but listens for the parent's pipe to
    // close.  When it does close, send a SIGTERM to the existing
    // process followed by a SIGTERM.
    //
    // This allows XRootD to auto-info when Pelican goes away.
    void InfoThread();

    // Ensure that the info thread is only started once.
    static std::once_flag m_info_launch;

    // The file descriptor to listen on for a pipe-based info.
    static int m_info_fd;

    // The location of the CA file for this process
    static std::string m_ca_file;

    // The location of the host certificate for this process
    static std::string m_cert_file;

    // Send a SIGTERM to self, followed by a 5 second sleep, followed
    // by a SIGKILL (until the process exits).
    void ShutdownSelf();

    // Process a message from the info file descriptor; this pipe
    // provides the ability for the parent process to update the CA
    // and TLS certificate files.
    void ProcessMessage();

    // Atomically overwrite a location given a file descriptor with
    // the new contents.
    void AtomicOverwriteFile(int fd, const std::string &loc);

    // Logger associated with the object
    XrdSysError &m_log;
};

std::once_flag PelicanHandler::m_info_launch;
int PelicanHandler::m_info_fd = -1;
std::string PelicanHandler::m_ca_file;
std::string PelicanHandler::m_cert_file;

PelicanHandler::~PelicanHandler() {}

PelicanHandler::PelicanHandler(XrdSysError *log, const char * /*config*/,
                               XrdOucEnv * /*myEnv*/)
    : m_log(*log) {
    std::call_once(m_info_launch, [&] {
        auto fd_char = getenv("PELICAN_INFO_FD");
        if (fd_char) {
            m_log.Emsg("PelicanHandler", "Will listen for command on FD",
                       fd_char);
            int info_fd = std::stol(fd_char);
            if (info_fd < 0) {
                std::stringstream ss;
                ss << "Invalid value for the Pelican monitor file "
                      "descriptor: "
                   << info_fd;
                throw std::invalid_argument(ss.str());
            }
            m_info_fd = info_fd;
        }

        auto ca_file_char = getenv("XRDHTTP_PELICAN_CA_FILE");
        if (ca_file_char) {
            m_ca_file = std::string(ca_file_char);
        } else {
            m_log.Emsg("PelicanHandler",
                       "XRDHTTP_PELICAN_CA_FILE environment variable not set; "
                       "cannot update the CAs");
        }
        auto cert_file_char = getenv("XRDHTTP_PELICAN_CERT_FILE");
        if (cert_file_char) {
            m_cert_file = cert_file_char;
        } else {
            m_log.Emsg("PelicanHandler",
                       "XRDHTTP_PELICAN_CERT_FILE environment variable not "
                       "set; cannot update the host certificate");
        }

        std::thread t(&PelicanHandler::InfoThread, this);
        t.detach();
    });
}

void PelicanHandler::InfoThread() {
    if (m_info_fd < 0) {
        return;
    }

    struct pollfd info_event[1];
    while (true) {
        info_event[0].fd = m_info_fd;
        info_event[0].events = POLLIN;

        auto ready = poll(info_event, 1, -1);
        if (info_event[0].revents == POLLIN) {
            ProcessMessage();
        } else if (ready == -1 || info_event[0].revents) {
            ShutdownSelf();
        }
    }
}

void PelicanHandler::ProcessMessage() {
    if (m_info_fd < 0) {
        return;
    }

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } controlMsg;

    struct msghdr msg;
    memset(&msg, '\0', sizeof(msg));

    struct iovec iov;
    char data;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    iov.iov_base = &data;
    iov.iov_len = 1;

    msg.msg_control = controlMsg.buf;
    msg.msg_controllen = sizeof(controlMsg.buf);

    auto rval = recvmsg(m_info_fd, &msg, 0);
    if (rval == -1) {
        m_log.Emsg("ProcessMessage",
                   "Failed to receive message from parent:", strerror(errno));
        return;
    }

    auto cmsgp = CMSG_FIRSTHDR(&msg);
    if (cmsgp == nullptr || cmsgp->cmsg_len != CMSG_LEN(sizeof(int)) ||
        cmsgp->cmsg_level != SOL_SOCKET || cmsgp->cmsg_type != SCM_RIGHTS) {
        m_log.Emsg("ProcessMessage",
                   "Received invalid control message from parent");
        return;
    }
    int fd;
    memcpy(&fd, CMSG_DATA(cmsgp), sizeof(int));

    if (data == 1) {
        // Update the CA file.
        AtomicOverwriteFile(fd, m_ca_file);
    } else if (data == 2) {
        // Update the host certificate file (should contain the key as well
        AtomicOverwriteFile(fd, m_cert_file);
    } else {
        m_log.Emsg("ProcessMessage", "Unknown message from parent:",
                   std::to_string(data).c_str());
    }
}

void PelicanHandler::AtomicOverwriteFile(int fd, const std::string &loc) {
    std::vector<char> loc_template;
    loc_template.resize(loc.size() + 7 + 1);
    loc_template[loc.size() + 7] = '\0';

    const static std::string template_characters{".XXXXXX"};
    std::copy(loc.begin(), loc.end(), loc_template.begin());
    std::copy(template_characters.begin(), template_characters.end(),
              loc_template.begin() + loc.size());

    int fd_new;
    if (-1 == (fd_new = mkstemp(loc_template.data()))) {
        m_log.Emsg(
            "AtomicOverwrite",
            "Failed to create temporary file for overwrite:", strerror(errno));
        close(fd);
        return;
    }

    static const size_t bufsize = 4096;
    std::vector<char> buffer;
    buffer.resize(bufsize);
    while (true) {
        auto rval = read(fd, buffer.data(), bufsize);
        if (rval == -1) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            } else {
                m_log.Emsg("AtomicOverwrite",
                           "Failed to read from source FD:", strerror(errno));
                close(fd);
                close(fd_new);
                if (-1 == unlink(loc_template.data())) {
                    m_log.Emsg("AtomicOverwrite",
                               "Failed to unlink temporary file on cleanup:",
                               strerror(errno));
                }
                return;
            }
        } else if (rval == 0) {
            break;
        }
        auto remaining = rval;
        do {
            rval = write(fd_new, buffer.data(), remaining);
            if (rval == -1) {
                if (errno == EINTR || errno == EAGAIN) {
                    continue;
                } else {
                    m_log.Emsg(
                        "AtomicOverwrite",
                        "Failed to write to destination FD:", strerror(errno));
                    close(fd);
                    close(fd_new);
                    if (-1 == unlink(loc_template.data())) {
                        m_log.Emsg(
                            "AtomicOverwrite",
                            "Failed to unlink temporary file on cleanup:",
                            strerror(errno));
                    }
                    return;
                }
            }
            remaining -= rval;
        } while (remaining);
    };
    close(fd);
    close(fd_new);

    if (-1 == rename(loc_template.data(), loc.data())) {
        m_log.Emsg("AtomicOverwrite",
                   "Failed to overwrite file:", strerror(errno));
        if (-1 == unlink(loc_template.data())) {
            m_log.Emsg(
                "AtomicOverwrite",
                "Failed to unlink temporary file on cleanup:", strerror(errno));
        }
    }
}

void PelicanHandler::ShutdownSelf() {
    auto self = getpid();
    auto rv = kill(self, SIGTERM);
    if (rv == -1) {
        m_log.Emsg("Shutdown",
                   "Failed to send self a SIGTERM:", strerror(errno));
        // Fallthrough -- still send a SIGKILL below.
    }
    sleep(5);
    while (true) {
        rv = kill(self, SIGKILL);
        if (rv == -1) {
            m_log.Emsg("Shutdown",
                       "Failed to send self a SIGKILL:", strerror(errno));
        }
    }
}

bool PelicanHandler::MatchesPath(const char *verb, const char * /*path*/) {
    return false;
}

int PelicanHandler::ProcessReq(XrdHttpExtReq &req) { return -1; }

extern "C" {

XrdHttpExtHandler *XrdHttpGetExtHandler(XrdSysError *log, const char *config,
                                        const char * /*parms*/,
                                        XrdOucEnv *myEnv) {
    PelicanHandler *retval{nullptr};

    if (!config) {
        log->Emsg(
            "PelicanHandler",
            "Pelican HTTP handler requires a config filename in order to load");
        return NULL;
    }

    try {
        log->Emsg("PelicanHandler",
                  "Will load configuration for the Pelican handler from",
                  config);
        retval = new PelicanHandler(log, config, myEnv);
    } catch (std::runtime_error &re) {
        log->Emsg("PelicanInitialize",
                  "Encountered a runtime failure when loading ", re.what());
    }
    return retval;
}
}
