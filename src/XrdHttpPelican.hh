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

#include <chrono>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>

class XrdAccAuthorize;
class XrdOfsFSctl_PI;
class XrdOss;
class XrdOucEnv;
class XrdSysError;

// A manager for prestage requests
//
// The manager maintains a set of worker pools, one for each identifier.  When
// the pool has been idle for a "reasonable" period, then it'll automatically
// shut down.
class PrestageRequestManager final {
  public:
    class PrestageRequest {
      public:
        PrestageRequest(const std::string &ident, const std::string &path,
                        XrdOucEnv &env)
            : m_ident(ident), m_path(path), m_env(env) {}

        int WaitFor(std::chrono::steady_clock::duration);

        XrdOucEnv &GetEnv() const { return m_env; }
        std::string GetPath() const { return m_path; }
        void SetProgress(off_t offset);
        void SetDone(int status, const std::string &msg);
        const std::string &GetIdentifier() const { return m_ident; }
        bool IsActive() const {
            return m_active.load(std::memory_order_relaxed);
        }
        std::string GetResults() const { return m_message; }
        off_t GetProgress() const {
            return m_prestage_offset.load(std::memory_order_relaxed);
        }

      private:
        std::atomic<bool> m_active{false};
        int m_status{-1};
        std::atomic<off_t> m_prestage_offset{0};
        std::string m_ident;
        std::string m_path;
        std::condition_variable m_cv;
        std::mutex m_mutex;
        std::string m_message;
        XrdOucEnv &m_env;
    };

    PrestageRequestManager(XrdOucEnv &xrdEnv);

    bool Produce(PrestageRequest &handler);

  private:
    class PrestageQueue {
        class PrestageWorker;

      public:
        PrestageQueue(const std::string &ident, PrestageRequestManager &parent,
                      XrdOss &oss)
            : m_oss(oss), m_parent(parent) {}

        bool Produce(PrestageRequest &handler);
        PrestageRequest &Consume();
        PrestageRequest *TryConsume();
        PrestageRequest *ConsumeUntil(std::chrono::steady_clock::duration dur);
        void Done(PrestageWorker *);

      private:
        class PrestageWorker final {
          public:
            PrestageWorker(const std::string &label, XrdOss &oss,
                           PrestageQueue &queue);
            PrestageWorker(const PrestageWorker &) = delete;

            void Run();
            static void RunStatic(PrestageWorker *myself);

          private:
            void Prestage(PrestageRequest &request);

            const std::string m_label;
            XrdOss &m_oss;
            PrestageQueue &m_queue;
        };

        int m_idle{0};
        const std::string m_label;
        XrdOss &m_oss;
        std::vector<std::unique_ptr<PrestageWorker>> m_workers;
        std::deque<PrestageRequest *> m_ops;
        std::condition_variable m_cv;
        std::mutex m_mutex;
        PrestageRequestManager &m_parent;
        const static unsigned m_max_pending_ops{20};
        const static unsigned m_max_workers{20};
    };

    void Done(const std::string &ident);

    static std::shared_mutex m_mutex;

    static XrdOss *m_oss;

    static std::unordered_map<std::string, std::shared_ptr<PrestageQueue>>
        m_pool_map;
    static std::once_flag m_init_once;
};

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

    // Process a prestage request from the remote client
    int PrestageReq(const std::string &path, XrdHttpExtReq &req);

    // Process a cache eviction request
    int EvictReq(const std::string &path, XrdHttpExtReq &req);

    // Indicates whether the plugin is running in a cache.
    static bool m_is_cache;

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

    // Request manager object
    PrestageRequestManager m_manager;

    // Pointer to the global authorization object (used to authorize
    // prestage/evict requests)
    static XrdAccAuthorize *m_acc;

    // Pointer to the global FSctl object (used to evict paths)
    static XrdOfsFSctl_PI *m_fsctl;

    static std::filesystem::path m_api_root;
};