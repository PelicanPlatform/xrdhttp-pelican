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
#include <XrdOuc/XrdOucGatherConf.hh>
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

using namespace XrdHttpPelican;
using namespace XrdHttpPelican::detail;

std::once_flag Handler::m_info_launch;
int Handler::m_info_fd = -1;
std::string Handler::m_ca_file;
std::string Handler::m_cert_file;
std::string Handler::m_cache_self_test_file;
std::string Handler::m_cache_self_test_file_cinfo;
std::string Handler::m_authfile_generated;
std::string Handler::m_scitokens_generated;
std::filesystem::path Handler::m_api_root{"/api/v1.0/pelican"};
decltype(Handler::m_acc) Handler::m_acc{nullptr};
decltype(Handler::m_is_cache) Handler::m_is_cache{false};
decltype(Handler::m_sfs) Handler::m_sfs{nullptr};

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

std::string LogMaskToString(int mask) {
    if (mask == LogMask::All) {
        return "all";
    }

    bool has_entry = false;
    std::stringstream ss;
    if (mask & LogMask::Debug) {
        ss << (has_entry ? ", " : "") << "debug";
        has_entry = true;
    }
    if (mask & LogMask::Info) {
        ss << (has_entry ? ", " : "") << "info";
        has_entry = true;
    }
    if (mask & LogMask::Warning) {
        ss << (has_entry ? ", " : "") << "warning";
        has_entry = true;
    }
    if (mask & LogMask::Error) {
        ss << (has_entry ? ", " : "") << "error";
        has_entry = true;
    }
    return ss.str();
}

bool ParseTimeout(const std::string &duration, struct timespec &result,
                  std::string &errmsg) {

    if (duration.empty()) {
        errmsg = "cannot parse empty string as a time duration";
        return false;
    }
    if (duration == "0") {
        result = {0, 0};
        return true;
    }
    struct timespec ts = {0, 0};
    auto strValue = duration;
    while (!strValue.empty()) {
        std::size_t pos;
        double value;
        try {
            value = std::stod(strValue, &pos);
        } catch (std::invalid_argument const &exc) {
            errmsg = "Invalid number provided as timeout: " + strValue;
            return false;
        } catch (std::out_of_range const &exc) {
            errmsg = "Provided timeout out of representable range: " +
                     std::string(exc.what());
            return false;
        }
        if (value < 0) {
            errmsg = "Provided timeout was negative";
            return false;
        }
        strValue = strValue.substr(pos);
        char unit[3] = {'\0', '\0', '\0'};
        if (!strValue.empty()) {
            unit[0] = strValue[0];
            if (unit[0] >= '0' && unit[0] <= '9') {
                unit[0] = '\0';
            }
        }
        if (strValue.size() > 1) {
            unit[1] = strValue[1];
            if (unit[1] >= '0' && unit[1] <= '9') {
                unit[1] = '\0';
            }
        }
        if (!strncmp(unit, "ns", 2)) {
            ts.tv_nsec += value;
        } else if (!strncmp(unit, "us", 2)) {
            auto value_s = (static_cast<long long>(value)) / 1'000'000;
            ts.tv_sec += value_s;
            value -= value_s * 1'000'000;
            ts.tv_nsec += value * 1'000'000;
        } else if (!strncmp(unit, "ms", 2)) {
            auto value_s = (static_cast<long long>(value)) / 1'000;
            ts.tv_sec += value_s;
            value -= value_s * 1'000;
            ts.tv_nsec += value * 1'000'000;
        } else if (!strncmp(unit, "s", 1)) {
            auto value_s = (static_cast<long long>(value));
            ts.tv_sec += value_s;
            value -= value_s;
            ts.tv_nsec += value * 1'000'000'000;
        } else if (!strncmp(unit, "m", 1)) {
            value *= 60;
            auto value_s = (static_cast<long long>(value));
            ts.tv_sec += value_s;
            value -= value_s;
            ts.tv_nsec += value * 1'000'000'000;
        } else if (!strncmp(unit, "h", 1)) {
            value *= 3600;
            auto value_s = (static_cast<long long>(value));
            ts.tv_sec += value_s;
            value -= value_s;
            ts.tv_nsec += value * 1'000'000'000;
        } else if (strlen(unit) > 0) {
            errmsg = "Unknown unit in duration: " + std::string(unit);
            return false;
        } else {
            errmsg = "Unit missing from duration: " + duration;
            return false;
        }
        if (ts.tv_nsec > 1'000'000'000) {
            ts.tv_sec += ts.tv_nsec / 1'000'000'000;
            ts.tv_nsec = ts.tv_nsec % 1'000'000'000;
        }
        strValue = strValue.substr(strlen(unit));
    }
    result.tv_nsec = ts.tv_nsec;
    result.tv_sec = ts.tv_sec;
    return true;
}

unsigned ParseUnsignedConfig(const std::string &val, const std::string &name,
                             XrdSysError &log) {
    size_t consumed;
    int result;
    try {
        result = std::stoi(val, &consumed);
    } catch (std::invalid_argument const &exc) {
        log.Emsg("Config",
                 "Invalid value for pelican.worker_max:", val.c_str());
        throw std::invalid_argument(
            "Invalid configuration value in pelican.worker_max");
    } catch (std::out_of_range const &exc) {
        log.Emsg("Config",
                 "Value for pelican.worker_max out of range:", val.c_str());
        throw std::invalid_argument(
            "Invalid configuration value in pelican.worker_max");
    }
    if (result <= 0) {
        log.Emsg("Config",
                 "Invalid value for pelican.worker_max:", val.c_str());
        throw std::invalid_argument(
            "Invalid configuration value in pelican.worker_max");
    } else if (consumed != strlen(val.c_str())) {
        log.Emsg("Config",
                 "Invalid value for pelican.worker_max:", val.c_str());
        throw std::invalid_argument(
            "Invalid configuration value in pelican.worker_max");
    }
    return static_cast<unsigned>(result);
}

} // namespace

Handler::~Handler() {}

Handler::Handler(XrdSysError *log, const char *configfn, XrdOucEnv *xrdEnv)
    : m_log(*log), m_manager(*xrdEnv, *log) {
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
        auto cache_self_test_file_char =
            getenv("XRDHTTP_PELICAN_CACHE_SELF_TEST_FILE");
        if (cache_self_test_file_char) {
            m_cache_self_test_file = cache_self_test_file_char;
        } else {
            m_log.Emsg("PelicanHandler",
                       "XRDHTTP_PELICAN_CACHE_SELF_TEST_FILE environment "
                       "variable not set; cannot pass a cache self-test file");
        }
        auto cache_self_test_file_cinfo_char =
            getenv("XRDHTTP_PELICAN_CACHE_SELF_TEST_FILE_CINFO");
        if (cache_self_test_file_cinfo_char) {
            m_cache_self_test_file_cinfo = cache_self_test_file_cinfo_char;
        } else {
            m_log.Emsg(
                "PelicanHandler",
                "XRDHTTP_PELICAN_CACHE_SELF_TEST_FILE_CINFO environment "
                "variable not set; cannot pass a cache self-test file cinfo");
        }
        auto authfile_generated_char =
            getenv("XRDHTTP_PELICAN_AUTHFILE_GENERATED");
        if (authfile_generated_char) {
            m_authfile_generated = authfile_generated_char;
        } else {
            m_log.Emsg("PelicanHandler",
                       "XRDHTTP_PELICAN_AUTHFILE_GENERATED environment "
                       "variable not set; cannot update the authfile");
        }
        auto scitokens_generated_char =
            getenv("XRDHTTP_PELICAN_SCITOKENS_GENERATED");
        if (scitokens_generated_char) {
            m_scitokens_generated = scitokens_generated_char;
        } else {
            m_log.Emsg("PelicanHandler",
                       "XRDHTTP_PELICAN_SCITOKENS_GENERATED environment "
                       "variable not set; cannot update the SciTokens");
        }

        if (configfn && strlen(configfn)) {
            XrdOucGatherConf pelicanhandler_conf("pelican.", &m_log);
            int result;
            if ((result = pelicanhandler_conf.Gather(
                     configfn, XrdOucGatherConf::full_lines)) < 0) {
                m_log.Emsg("Config", -result, "parsing config file", configfn);
                throw std::invalid_argument(
                    "Failed to parse the configuration file");
            }
            m_log.setMsgMask(LogMask::Warning);
            char *temporary;
            while ((temporary = pelicanhandler_conf.GetLine())) {
                auto attribute = pelicanhandler_conf.GetToken();

                if (!strcmp(attribute, "pelican.trace")) {
                    char *val = nullptr;
                    if (!(val = pelicanhandler_conf.GetToken())) {
                        m_log.Emsg(
                            "Config",
                            "pelican.trace requires an argument.  Usage: "
                            "pelican.trace "
                            "[all|error|warning|info|debug|none]");
                        throw std::invalid_argument(
                            "Invalid configuration value in pelican.trace");
                    }
                    do {
                        if (!strcmp(val, "all")) {
                            m_log.setMsgMask(m_log.getMsgMask() | LogMask::All);
                        } else if (!strcmp(val, "error")) {
                            m_log.setMsgMask(m_log.getMsgMask() |
                                             LogMask::Error);
                        } else if (!strcmp(val, "warning")) {
                            m_log.setMsgMask(m_log.getMsgMask() |
                                             LogMask::Warning);
                        } else if (!strcmp(val, "info")) {
                            m_log.setMsgMask(m_log.getMsgMask() |
                                             LogMask::Info);
                        } else if (!strcmp(val, "debug")) {
                            m_log.setMsgMask(m_log.getMsgMask() |
                                             LogMask::Debug);
                        } else if (!strcmp(val, "none")) {
                            m_log.setMsgMask(0);
                        } else {
                            m_log.Emsg("Config",
                                       "pelican.trace encountered an unknown "
                                       "directive:",
                                       val);
                            throw std::invalid_argument(
                                "Invalid configuration value in pelican.trace");
                        }
                    } while ((val = pelicanhandler_conf.GetToken()));
                    m_log.Emsg("Config", "Logging levels enabled -",
                               LogMaskToString(m_log.getMsgMask()).c_str());
                } else if (!strcmp(attribute, "pelican.worker_idle")) {
                    char *val = nullptr;
                    if (!(val = pelicanhandler_conf.GetToken())) {
                        m_log.Emsg("Config",
                                   "pelican.worker_idle requires an argument.\n"
                                   "Usage: pelican.worker_idle <idle_timeout>\n"
                                   "Example: pelican.worker_idle 5m\n"
                                   "Units accepted include ms, s, m, h; unit "
                                   "must be specified");
                        throw std::invalid_argument(
                            "Invalid configuration value in "
                            "pelican.worker_idle");
                    }
                    struct timespec idle_timeout;
                    std::string errmsg;
                    if (!ParseTimeout(val, idle_timeout, errmsg)) {
                        m_log.Emsg("Config",
                                   "Failed to parse worker idle timeout:",
                                   errmsg.c_str());
                        throw std::invalid_argument(
                            "Invalid configuration value in "
                            "pelican.worker_idle");
                    }
                    m_manager.SetWorkerIdleTimeout(
                        std::chrono::seconds(idle_timeout.tv_sec) +
                        std::chrono::nanoseconds(idle_timeout.tv_nsec));
                    m_log.Emsg("Config", "Worker idle timeout set to", val);
                } else if (!strcmp(attribute, "pelican.worker_max")) {
                    char *val = nullptr;
                    if (!(val = pelicanhandler_conf.GetToken())) {
                        m_log.Emsg("Config",
                                   "pelican.worker_max requires an argument.\n"
                                   "Usage: pelican.worker_max <max_workers>\n"
                                   "Example: pelican.worker_max 20");
                        throw std::invalid_argument(
                            "Invalid configuration value in "
                            "pelican.worker_max");
                    }
                    int max_workers =
                        ParseUnsignedConfig(val, "pelican.worker_max", m_log);
                    m_manager.SetMaxWorkers(max_workers);
                    m_log.Emsg("Config", "Maximum worker count set to", val);
                } else if (!strcmp(attribute, "pelican.idle_request_max")) {
                    char *val = nullptr;
                    if (!(val = pelicanhandler_conf.GetToken())) {
                        m_log.Emsg(
                            "Config",
                            "pelican.idle_request_max requires an argument.\n"
                            "Usage: pelican.idle_request_max <max_requests>\n"
                            "Example: pelican.idle_request_max 100");
                        throw std::invalid_argument(
                            "Invalid configuration value in "
                            "pelican.idle_request_max");
                    }
                    int max_requests = ParseUnsignedConfig(
                        val, "pelican.idle_request_max", m_log);
                    m_manager.SetMaxIdleRequests(max_requests);
                    m_log.Emsg("Config", "Maximum idle request count set to",
                               val);
                } else {
                    m_log.Emsg("Config",
                               "Unknown configuration directive:", attribute);
                    throw std::invalid_argument(
                        "Unknown configuration directive in pelican.");
                }
            }

            m_acc = reinterpret_cast<XrdAccAuthorize *>(
                xrdEnv->GetPtr("XrdAccAuthorize*"));

            long one;
            m_is_cache = XrdOucEnv::Import("XRDPFC", one);

            if (m_is_cache) {
                m_sfs = reinterpret_cast<XrdSfsFileSystem *>(
                    xrdEnv->GetPtr("XrdSfsFileSystem*"));
                if (!m_sfs) {
                    m_log.Emsg(
                        "PelicanHandler",
                        "Filesystem control plugin is not available; cannot "
                        "manage eviction");
                }
            }
        }

        std::thread t(&Handler::InfoThread, this);
        t.detach();
    });
}

void Handler::InfoThread() {
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

void Handler::ProcessMessage() {
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
    } else if (data < 0 || data > 7) {
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
    } else if (data == 4) {
        // Pass a cache self test file
        AtomicOverwriteFile(fd, m_cache_self_test_file);
    } else if (data == 5) {
        // Pass a cache self test file cinfo
        AtomicOverwriteFile(fd, m_cache_self_test_file_cinfo);
    } else if (data == 6) {
        // Pass an auth file
        AtomicOverwriteFile(fd, m_authfile_generated);
    } else if (data == 7) {
        // Pass a scitokens file
        AtomicOverwriteFile(fd, m_scitokens_generated);
    } else {
        m_log.Emsg("ProcessMessage", "Unknown message from parent:",
                   std::to_string(data).c_str());
    }
}

void Handler::AtomicOverwriteFile(int fd, const std::string &loc) {
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

void Handler::ShutdownSelf() {
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

bool Handler::MatchesPath(const char *verb, const char *path) {
    return m_is_cache && !strcmp(verb, "GET") &&
           (!strcmp(path, "/pelican/api/v1.0/prestage") ||
            !strcmp(path, "/pelican/api/v1.0/evict"));
}

int Handler::ProcessReq(XrdHttpExtReq &req) {
    auto iter = req.headers.find("xrd-http-query");
    if (iter == req.headers.end()) {
        m_log.Emsg("ProcessReq", "Missing internally-generated server data",
                   req.resource.c_str());
        req.SendSimpleResp(500, "Bad Request", nullptr,
                           "Prestage request missing internal server data", 0);
        return 1;
    }
    auto &query = iter->second;
    if (query.empty()) {
        m_log.Emsg("ProcessReq", "Missing query parameter from request",
                   req.resource.c_str());
        req.SendSimpleResp(
            400, "Bad Request", nullptr,
            "Prestage command request requires the `path` query parameter", 0);
        return 1;
    }
    std::string_view query_params = query;
    std::string_view path_view;
    while (!query_params.empty()) {
        if (query_params[0] == '&') {
            query_params = query_params.substr(1);
            continue;
        }
        auto pos = query_params.find('&');
        auto param = query_params.substr(0, pos);
        if (pos == std::string::npos) {
            query_params = "";
        } else {
            query_params = query_params.substr(pos + 1);
        }
        auto equal_pos = param.find('=');
        if (equal_pos == std::string::npos) {
            continue;
        }
        auto param_name = param.substr(0, equal_pos);
        if (param_name != "path") {
            continue;
        }
        path_view = param.substr(equal_pos + 1);
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

    std::filesystem::path resource_clean(req.resource);

    if (!strcmp("/pelican/api/v1.0/prestage", resource_clean.c_str())) {
        return PrestageReq(path, req);
    } else {
        return EvictReq(path, req);
    }
}

int Handler::EvictReq(const std::string &path, XrdHttpExtReq &req) {
    auto &ent = req.GetSecEntity();
    if (m_acc) {
        if (!m_acc->Access(&ent, path.c_str(), AOP_Delete)) {
            m_log.Log(LogMask::Info, "evict", "Permission denied to evict path",
                      path.c_str());
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
    myData.Arg2Len = -2;
    const char *myArgs[2];
    myArgs[0] = path.c_str();
    myArgs[1] = req.headers.find("xrd-http-query")->second.c_str();
    myData.ArgP = myArgs;
    int fsctlRes =
        m_sfs->FSctl(SFS_FSCTL_PLUGXC, myData, einfo, &req.GetSecEntity());
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
        m_log.Log(LogMask::Info, "evict",
                  "Evict failed because path is locked:", path.c_str());
        return req.SendSimpleResp(
            423, "Locked", nullptr,
            "Cannot evict file that is in-use by the cache", 0);
    } else {
        m_log.Log(LogMask::Info, "evict", "Evicted path", path.c_str());
        return req.SendSimpleResp(200, "OK", nullptr,
                                  "Cache eviction successful", 0);
    }
}

int Handler::PrestageReq(const std::string &path, XrdHttpExtReq &req) {
    auto &ent = req.GetSecEntity();
    if (m_acc) {
        if (!m_acc->Access(&ent, path.c_str(), AOP_Read)) {
            req.SendSimpleResp(403, "Forbidden", nullptr,
                               "Permission denied to prestage path", 0);
            return 1;
        }
    }

    m_log.Log(LogMask::Debug, "Prestage", "Handling prestage for path",
              path.c_str());
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
    case 200:
        desc = "OK";
        break;
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
    Handler *retval{nullptr};

    if (log) {
        log = new XrdSysError(log->logger(), "pelican_");
    }

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
        retval = new Handler(log, config, myEnv);
    } catch (std::runtime_error &re) {
        log->Emsg("PelicanInitialize",
                  "Encountered a runtime failure when loading ", re.what());
    }
    return retval;
}
}
