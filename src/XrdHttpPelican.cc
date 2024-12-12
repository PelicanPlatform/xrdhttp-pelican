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

#include <sstream>
#include <string>
#include <thread>

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
    // This allows XRootD to auto-shutdown when Pelican goes away.
    void ShutdownThread();

    // Ensure that the shutdown thread is only started once.
    static std::once_flag m_shutdown_launch;

    // The file descriptor to listen on for a pipe-based shutdown.
    static int m_shutdown_fd;

    // Send a SIGTERM to self, followed by a 5 second sleep, followed
    // by a SIGKILL (until the process exits).
    void ShutdownSelf();

    // Logger associated with the object
    XrdSysError &m_log;
};

std::once_flag PelicanHandler::m_shutdown_launch;
int PelicanHandler::m_shutdown_fd = -1;

PelicanHandler::~PelicanHandler() {}

PelicanHandler::PelicanHandler(XrdSysError *log, const char *config,
                               XrdOucEnv *myEnv)
    : m_log(*log) {
    std::call_once(m_shutdown_launch, [&] {
        auto fd_char = getenv("PELICAN_SHUTDOWN_FD");
        if (fd_char) {
            int shutdown_fd = std::stol(fd_char);
            if (shutdown_fd < 0) {
                std::stringstream ss;
                ss << "Invalid value for the Pelican shutdown monitor file "
                      "descriptor: "
                   << shutdown_fd;
                throw std::invalid_argument(ss.str());
            }
            m_shutdown_fd = shutdown_fd;
        }

        std::thread t(&PelicanHandler::ShutdownThread, this);
        t.detach();
    });
}

void PelicanHandler::ShutdownThread() {
    if (m_shutdown_fd < 0) {
        return;
    }

    struct pollfd shutdown_event[1];
    while (true) {
        shutdown_event[0].fd = m_shutdown_fd;
        shutdown_event[0].events = POLLIN;

        auto ready = poll(shutdown_event, 1, -1);
        if (ready == -1 || shutdown_event[0].revents) {
            ShutdownSelf();
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
    return verb && !strcmp(verb, "OPTIONS");
}

int PelicanHandler::ProcessReq(XrdHttpExtReq &req) {
    const static std::string options_resp =
        "DAV: 1\r\n"
        "DAV: <http://apache.org/dav/propset/fs/1>\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: authorization\r\n"
        "Access-Control-Allow-Methods: GET, HEAD\r\n"
        "Allow: HEAD,GET,PUT,PROPFIND,DELETE,OPTIONS\r\n";

    return req.SendSimpleResp(200, nullptr, options_resp.c_str(), NULL, 0);
}

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
