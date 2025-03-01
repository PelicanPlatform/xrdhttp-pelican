/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

#include <XrdOss/XrdOss.hh>
#include <XrdOuc/XrdOucEnv.hh>
#include <XrdSys/XrdSysError.hh>

#include <string>
#include <thread>

#include <fcntl.h>

using namespace XrdHttpPelican;
using namespace XrdHttpPelican::detail;

decltype(PrestageRequestManager::m_pool_map) PrestageRequestManager::m_pool_map;
decltype(PrestageRequestManager::m_init_once)
    PrestageRequestManager::m_init_once;
decltype(PrestageRequestManager::m_oss) PrestageRequestManager::m_oss;
decltype(PrestageRequestManager::m_mutex) PrestageRequestManager::m_mutex;
decltype(PrestageRequestManager::m_idle_timeout)
    PrestageRequestManager::m_idle_timeout = std::chrono::minutes(1);
unsigned PrestageRequestManager::m_max_pending_ops = 20;
unsigned PrestageRequestManager::m_max_workers = 20;

PrestageRequestManager::PrestageQueue::PrestageWorker::PrestageWorker(
    const std::string &label, XrdOss &oss, PrestageQueue &queue)
    : m_label(label), m_oss(oss), m_queue(queue) {}

void PrestageRequestManager::PrestageQueue::PrestageWorker::RunStatic(
    PrestageWorker *myself) {
    myself->Run();
}

void PrestageRequestManager::PrestageQueue::PrestageWorker::Prestage(
    PrestageRequestManager::PrestageRequest &request) {
    auto fp = m_oss.newFile("Prestage Worker");

    ssize_t rc =
        fp->Open(request.GetPath().c_str(), O_RDONLY, 0, request.GetEnv());
    if (rc < 0) {
        if (rc == -ENOENT) {
            request.SetDone(404, "Object does not exist");
            return;
        } else if (rc == -EISDIR) {
            request.SetDone(409, "Object is a directory");
            return;
        } else {
            request.SetDone(500, "Unknown error when preparing for prestage");
            return;
        }
    }
    off_t off{0};
    auto lastUpdate = std::chrono::steady_clock::now();
    while ((rc = fp->Read(off, 64 * 1024)) > 0) {
        off += rc;
        if (std::chrono::steady_clock::now() - lastUpdate >
            std::chrono::milliseconds(200)) {
            request.SetProgress(off);
        }
    }
    fp->Close();
    if (rc < 0) {
        std::stringstream ss;
        ss << "I/O failure when prestaging: " << strerror(-rc);
        request.SetDone(500, ss.str());
        return;
    }
    request.SetDone(200, "Prestage successful");
    return;
}

void PrestageRequestManager::PrestageQueue::PrestageWorker::Run() {
    m_queue.m_parent.m_log.Log(LogMask::Info, "PrestageWorker", "Worker for",
                               m_queue.m_label.c_str(), "starting");

    while (true) {
        auto request = m_queue.TryConsume();
        if (!request) {
            request = m_queue.ConsumeUntil(m_idle_timeout, this);
            if (!request) {
                break;
            }
        }
        Prestage(*request);
    }

    m_queue.m_parent.m_log.Log(LogMask::Info, "PrestageWorker", "Worker for",
                               m_queue.m_label.c_str(), "exiting");
    m_queue.Done(this);
}

void PrestageRequestManager::PrestageQueue::Done(PrestageWorker *worker) {
    std::unique_lock lock(m_mutex);
    m_done = true;
    std::erase_if(m_workers, [&](std::unique_ptr<PrestageWorker> &other) {
        return other.get() == worker;
    });

    if (m_workers.empty()) {
        lock.unlock();
        m_parent.Done(m_label);
    }
}

void PrestageRequestManager::Done(const std::string &ident) {
    m_log.Log(LogMask::Info, "PrestageRequestManager", "Prestage pool",
              ident.c_str(), "is idle and all workers have exited.");
    std::unique_lock lock(m_mutex);

    auto iter = m_pool_map.find(ident);
    if (iter != m_pool_map.end()) {
        m_pool_map.erase(iter);
    }
}

// Produce a request for processing.  If the queue is full, the request will
// be rejected and false will be returned.
//
// Implementation notes:
// - If a worker is idle, it will be woken up to process the request.
// - If no workers are idle, a new worker will be created to process the
//   request.
// - If the maximum number of workers is reached, the request will be queued
//   until a worker is available.
// - If the maximum number of pending operations is reached, the request will
//   be rejected.
// - If there are multiple idle workers, the oldest worker will be woken.  This
//   causes the newest workers to be idle for as long as possible and
//   potentially exit due to lack of work.  This is done to reduce the number of
//   "mostly idle" workers in the thread pool.
bool PrestageRequestManager::PrestageQueue::Produce(PrestageRequest &handler) {
    std::unique_lock lk{m_mutex};
    if (m_ops.size() == m_max_pending_ops) {
        m_parent.m_log.Log(LogMask::Warning, "PrestageQueue",
                           "Queue is full; rejecting request");
        return false;
    }

    m_ops.push_back(&handler);
    for (auto &worker : m_workers) {
        if (worker->IsIdle()) {
            worker->m_cv.notify_one();
            return true;
        }
    }

    if (m_workers.size() < m_max_workers) {
        auto worker = std::make_unique<
            PrestageRequestManager::PrestageQueue::PrestageWorker>(
            handler.GetIdentifier(), m_oss, *this);
        std::thread t(
            PrestageRequestManager::PrestageQueue::PrestageWorker::RunStatic,
            worker.get());
        t.detach();
        m_workers.push_back(std::move(worker));
    }
    lk.unlock();

    return true;
}

PrestageRequestManager::PrestageRequest *
PrestageRequestManager::PrestageQueue::TryConsume() {
    std::unique_lock<std::mutex> lk(m_mutex);
    if (m_ops.size() == 0) {
        return nullptr;
    }

    auto result = m_ops.front();
    m_ops.pop_front();

    return result;
}

// Wait for a request to be available for processing, or until the duration
// has elapsed.
//
// Returns the request that is available, or nullptr if the duration has
// elapsed.
PrestageRequestManager::PrestageRequest *
PrestageRequestManager::PrestageQueue::ConsumeUntil(
    std::chrono::steady_clock::duration dur, PrestageWorker *worker) {
    std::unique_lock<std::mutex> lk(m_mutex);
    worker->SetIdle(true);
    worker->m_cv.wait_for(lk, dur, [&] { return m_ops.size() > 0; });
    worker->SetIdle(false);
    if (m_ops.size() == 0) {
        return nullptr;
    }

    auto result = m_ops.front();
    m_ops.pop_front();

    return result;
}

void PrestageRequestManager::PrestageRequest::SetProgress(off_t offset) {
    m_prestage_offset.store(offset, std::memory_order_relaxed);
}

void PrestageRequestManager::PrestageRequest::SetDone(int status,
                                                      const std::string &msg) {
    std::unique_lock lock(m_mutex);
    m_status = status;
    m_message = msg;
    m_cv.notify_one();
}

int PrestageRequestManager::PrestageRequest::WaitFor(
    std::chrono::steady_clock::duration dur) {
    std::unique_lock lock(m_mutex);
    m_cv.wait_for(lock, dur, [&] { return m_status >= 0; });

    return m_status;
}

PrestageRequestManager::PrestageRequestManager(XrdOucEnv &xrdEnv,
                                               XrdSysError &eDest)
    : m_log(eDest) {
    std::call_once(m_init_once, [&] {
        m_oss = static_cast<XrdOss *>(xrdEnv.GetPtr("XrdOss*"));
        if (!m_oss) {
            m_log.Log(LogMask::Error, "RequestManager",
                      "XrdOss plugin is not configured; prestage functionality "
                      "disabled");
        }
    });
}

void PrestageRequestManager::SetWorkerIdleTimeout(
    std::chrono::steady_clock::duration dur) {
    m_idle_timeout = dur;
}

// Send a request to a worker for processing.  If the worker is not available,
// the request will be queued until a worker is available.  If the queue is
// full, the request will be rejected and false will be returned.
bool PrestageRequestManager::Produce(
    PrestageRequestManager::PrestageRequest &handler) {

    if (!m_oss) {
        m_log.Log(
            LogMask::Debug, "RequestManager",
            "XrdOss plugin is not configured; prestage functionality disabled");
        return false;
    }

    std::shared_ptr<PrestageQueue> queue;
    // Get the queue from our per-label map.  To avoid a race condition,
    // if the queue we get has already been shut down, we release the lock
    // and try again (with the expectation that the queue will eventually
    // get the lock and remove itself from the map).
    while (true) {
        m_mutex.lock_shared();
        std::lock_guard guard{m_mutex, std::adopt_lock};
        auto iter = m_pool_map.find(handler.GetIdentifier());
        if (iter != m_pool_map.end()) {
            queue = iter->second;
            if (!queue->IsDone())
                break;
        } else {
            break;
        }
    }
    if (!queue) {
        auto created_queue = false;
        std::string queue_name = "";
        {
            std::lock_guard guard(m_mutex);
            auto iter = m_pool_map.find(handler.GetIdentifier());
            if (iter == m_pool_map.end()) {
                queue = std::make_shared<PrestageQueue>(handler.GetIdentifier(),
                                                        *this, *m_oss);
                m_pool_map.insert(iter, {handler.GetIdentifier(), queue});
                created_queue = true;
                queue_name = handler.GetIdentifier();
            } else {
                queue = iter->second;
            }
        }
        if (created_queue) {
            m_log.Log(LogMask::Info, "RequestManager",
                      "Created new prestage queue for", queue_name.c_str());
        }
    }
    return queue->Produce(handler);
}
