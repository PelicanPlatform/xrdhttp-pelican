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

#include "XrdHttpPelican.hh"

#include <XrdAcc/XrdAccAuthorize.hh>
#include <XrdOfs/XrdOfsFSctl_PI.hh>
#include <XrdOss/XrdOss.hh>
#include <XrdOuc/XrdOucEnv.hh>
#include <XrdOuc/XrdOucErrInfo.hh>
#include <XrdSec/XrdSecEntity.hh>
#include <XrdSec/XrdSecEntityAttr.hh>
#include <XrdSfs/XrdSfsInterface.hh>
#include <XrdSys/XrdSysError.hh>
#include <XrdVersion.hh>

#include <arpa/inet.h>
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

std::once_flag PelicanHandler::m_info_launch;
int PelicanHandler::m_info_fd = -1;
std::string PelicanHandler::m_ca_file;
std::string PelicanHandler::m_cert_file;
std::filesystem::path PelicanHandler::m_api_root{"/api/v1.0/pelican"};
decltype(PelicanHandler::m_acc) PelicanHandler::m_acc{nullptr};
decltype(PelicanHandler::m_is_cache) PelicanHandler::m_is_cache{false};
decltype(PelicanHandler::m_fsctl) PelicanHandler::m_fsctl{nullptr};

namespace {

std::pair<bool, std::string> urlunquote(const std::string_view encoded) {
    std::string decoded;
    decoded.reserve(encoded.size());

    for (size_t idx = 0; idx < encoded.size(); idx++) {
        char c = encoded[idx];
        if (c == '%') {
            if (idx + 2 >= encoded.size()) {
                return {false, ""};
            }
            char hex[3] = {encoded[idx + 1], encoded[idx + 2], '\0'};
            idx += 3;
            std::size_t pos;
            try {
                decoded += static_cast<char>(std::stoi(hex, &pos, 16));
            } catch (std::invalid_argument const &exc) {
                return {false, ""};
            }
            if (pos != 2) {
                return {false, ""};
            }
        } else if (c == '+') {
            decoded += ' ';
        } else {
            decoded += c;
        }
    }

    return {true, decoded};
}

} // namespace

PelicanHandler::~PelicanHandler() {}

PelicanHandler::PelicanHandler(XrdSysError *log, const char * /*config*/,
                               XrdOucEnv *xrdEnv)
    : m_log(*log), m_manager(*xrdEnv) {
    std::call_once(m_info_launch, [&] {
        auto fd_char = getenv("XRDHTTP_PELICAN_INFO_FD");
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

        m_acc = reinterpret_cast<XrdAccAuthorize *>(
            xrdEnv->GetPtr("XrdAccAuthorize*"));

        long one;
        m_is_cache = XrdOucEnv::Import("XRDPFC", one);

        if (m_is_cache) {
            m_fsctl = (XrdOfsFSctl_PI *)xrdEnv->GetPtr("XrdFSCtl_PC*");
            if (!m_fsctl) {
                m_log.Emsg("PelicanHandler", "m_fsctl:",
                           std::to_string(reinterpret_cast<long long>(m_fsctl))
                               .c_str());
                // throw std::runtime_error("Cache control plugin is not
                // loaded");
            }
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

    // First, process messages that don't have a socket passed
    if (data == 3) {
        // Command to self-signal; payload is the signal to pass
        union {
            char buf[4];
            uint32_t signal;
        } signalBuffer;
        if (recv(m_info_fd, signalBuffer.buf, 4, 0) == -1) {
            m_log.Emsg("ProcessMessage",
                       "Failed to receive signal number from parent:",
                       strerror(errno));
            return;
        }
        signalBuffer.signal = ntohl(signalBuffer.signal);
        if (kill(getpid(), signalBuffer.signal) == -1) {
            m_log.Emsg("ProcessMessage",
                       "Failed to send signal to self:", strerror(errno));
        }
        return;
    } else if (data != 1 && data != 2) {
        m_log.Emsg("ProcessMessage", "Unknown control message from parent:",
                   std::to_string(data).c_str());
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

bool PelicanHandler::MatchesPath(const char *verb, const char *path) {
    return m_is_cache && !strcmp(verb, "GET") &&
           (!strcmp(path, "/pelican/api/v1.0/prestage") ||
            !strcmp(path, "/pelican/api/v1.0/evict"));
}

int PelicanHandler::ProcessReq(XrdHttpExtReq &req) {
    auto pos = req.resource.find('?');
    if (pos == std::string::npos) {
        req.SendSimpleResp(400, "Bad Request", nullptr,
                           "Prestage command request `path` query parameter",
                           0);
        return 1;
    }
    std::string_view query_params =
        std::string_view{req.resource}.substr(pos + 1);
    std::string_view path_view;
    while (!query_params.empty()) {
        if (query_params[0] == '&') {
            query_params = query_params.substr(1);
            continue;
        }
        auto last_arg = (pos = query_params.find('&')) == std::string::npos;
        auto param = query_params.substr(0, last_arg);
        if ((pos = param.find('=')) == std::string::npos) {
            continue;
        }
        auto param_name = param.substr(0, pos);
        if (param_name != "path") {
            continue;
        }
        path_view = param.substr(pos);
    }
    auto [success, path_str] = urlunquote(path_view);
    if (!success) {
        req.SendSimpleResp(400, "Bad Request", nullptr,
                           "Failed to unquote `path` query parameter value", 0);
        return 1;
    }

    std::filesystem::path path(path_str);
    path = path.lexically_normal();
    if (!path.is_absolute()) {
        req.SendSimpleResp(400, "Bad Request", nullptr,
                           "Prestage request must be an absolute path", 0);
    }

    if (!strcmp("/pelican/api/v1.0/prestage", path.string().c_str())) {
        return PrestageReq(path, req);
    } else {
        return EvictReq(path, req);
    }
}

int PelicanHandler::EvictReq(const std::string &path, XrdHttpExtReq &req) {
    auto &ent = req.GetSecEntity();
    if (m_acc) {
        if ((m_acc->Access(&ent, path.c_str(), AOP_Delete) &
             XrdAccPriv_Delete) != XrdAccPriv_Read) {
            req.SendSimpleResp(403, "Forbidden", nullptr,
                               "Permission denied to evict path", 0);
            return 1;
        }
    }

    std::string message = "evict " + path;
    XrdOucErrInfo einfo;
    XrdSfsFSctl myData;
    myData.Arg1 = "evict";
    myData.Arg1Len = 1;
    myData.Arg2Len = 1;
    const char *myArgs[1];
    myArgs[0] = path.c_str();
    myData.ArgP = myArgs;
    int fsctlRes = m_fsctl->FSctl(SFS_FSCTL_PLUGXC, myData, einfo);
    bool locked = false;
    if (fsctlRes == SFS_ERROR) {
        auto ec = einfo.getErrInfo();
        if (ec == ENOTTY) {
            locked = true;
        }
    } else if (fsctlRes == 5) {
        locked = true;
    }
    if (locked) {
        return req.SendSimpleResp(
            423, "Locked", nullptr,
            "Cannot evict file that is in-use by the cache", 0);
    } else {
        return req.SendSimpleResp(200, "OK", nullptr,
                                  "Cache eviction successful", 0);
    }
}

int PelicanHandler::PrestageReq(const std::string &path, XrdHttpExtReq &req) {
    auto &ent = req.GetSecEntity();
    if (m_acc) {
        if ((m_acc->Access(&ent, path.c_str(), AOP_Read) & XrdAccPriv_Read) !=
            XrdAccPriv_Read) {
            req.SendSimpleResp(403, "Forbidden", nullptr,
                               "Permission denied to prestage path", 0);
            return 1;
        }
    }

    std::string user;
    std::string vo{ent.vorg ? ent.vorg : ""};
    if (ent.eaAPI && !ent.eaAPI->Get("token.subject", user)) {
        std::string request_user;
        if (ent.eaAPI->Get("request.name", request_user) &&
            !request_user.empty()) {
            user = request_user;
        }
    }
    if (user.empty()) {
        user = ent.name ? ent.name : "nobody";
    }
    if (!vo.empty()) {
        user = vo + ":" + user;
    }

    XrdOucEnv env(nullptr, 0, &ent);
    PrestageRequestManager::PrestageRequest request(user, path, env);
    if (!m_manager.Produce(request)) {
        req.SendSimpleResp(429, "Too Many Requests", nullptr,
                           "Too many prestage requests at server", 0);
    }

    auto sent_resp = false;
    int status;
    while ((status = request.WaitFor(std::chrono::seconds(2))) <= 0) {
        if (!sent_resp) {
            if (req.StartChunkedResp(200, "OK", nullptr) < 0) {
                m_log.Emsg("ProcessReq", "Failed to start response to client");
                return -1;
            }
            sent_resp = true;
        }
        std::string resp;
        if (request.IsActive()) {
            resp = "status: active,offset=" +
                   std::to_string(request.GetProgress());
        } else {
            resp = "status: queued";
        }
        if (req.ChunkResp(resp.c_str(), resp.size()) < 0) {
            m_log.Emsg("ProcessReq", "Failed to send status report to client");
            return -1;
        }
    }
    std::string desc;
    switch (status) {
    case 401:
        desc = "Unauthorized";
        break;
    case 403:
        desc = "Forbidden";
        break;
    case 404:
        desc = "File not found";
        break;
    case 409:
        desc = "Resource is a directory";
        break;
    case 500:
        desc = "Internal Server Error";
        break;
    default:
        desc = "Internal Server Error";
        status = 500;
    }
    if (!sent_resp) {
        return req.SendSimpleResp(status, desc.c_str(), nullptr, nullptr, 0);
    } else {
        int rc;
        if (status >= 300) {
            auto resp = "failure: " + std::to_string(status) + "(" + desc +
                        "): " + request.GetResults();
            rc = req.ChunkResp(resp.c_str(), resp.size());
        } else {
            rc = req.ChunkResp("success: ok", 0);
        }
        if (rc < 0) {
            m_log.Emsg("ProcessReq", "Failed to send final response to client");
            return rc;
        }
        return req.ChunkResp(nullptr, 0);
    }
}

extern "C" {

XrdVERSIONINFO(XrdHttpGetExtHandler, XrdHttpPelican);

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
