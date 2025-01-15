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
    while (true) {
        auto request = m_queue.TryConsume();
        if (!request) {
            request = m_queue.ConsumeUntil(std::chrono::minutes(1));
            if (!request) {
                break;
            }
        }
        Prestage(*request);
    }

    m_queue.Done(this);
}

void PrestageRequestManager::PrestageQueue::Done(PrestageWorker *worker) {
    std::unique_lock lock(m_mutex);
    m_idle--;
    std::erase_if(m_workers, [&](std::unique_ptr<PrestageWorker> &other) {
        return other.get() == worker;
    });

    if (m_workers.empty()) {
        m_parent.Done(m_label);
    }
}

void PrestageRequestManager::Done(const std::string &ident) {
    std::unique_lock lock(m_mutex);

    auto iter = m_pool_map.find(ident);
    if (iter != m_pool_map.end()) {
        m_pool_map.erase(iter);
    }
}

bool PrestageRequestManager::PrestageQueue::Produce(PrestageRequest &handler) {
    std::unique_lock lk{m_mutex};
    if (m_ops.size() == m_max_pending_ops) {
        return false;
    }

    m_ops.push_back(&handler);
    m_cv.notify_one();

    if (!m_idle && m_workers.size() < m_max_workers) {
        m_workers.push_back(
            std::make_unique<
                PrestageRequestManager::PrestageQueue::PrestageWorker>(
                handler.GetIdentifier(), m_oss, *this));
        std::thread t(
            PrestageRequestManager::PrestageQueue::PrestageWorker::RunStatic,
            m_workers.back().get());
        t.detach();
    }
    lk.unlock();

    return true;
}

PrestageRequestManager::PrestageRequest &
PrestageRequestManager::PrestageQueue::Consume() {
    std::unique_lock<std::mutex> lk(m_mutex);
    m_idle++;
    m_cv.wait(lk, [&] { return m_ops.size() > 0; });
    m_idle--;

    auto result = std::move(m_ops.front());
    m_ops.pop_front();

    return *result;
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

PrestageRequestManager::PrestageRequest *
PrestageRequestManager::PrestageQueue::ConsumeUntil(
    std::chrono::steady_clock::duration dur) {
    std::unique_lock<std::mutex> lk(m_mutex);
    m_idle++;
    m_cv.wait_for(lk, dur, [&] { return m_ops.size() > 0; });
    m_idle--;
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

PrestageRequestManager::PrestageRequestManager(XrdOucEnv &xrdEnv, XrdSysError &eDest)
    : m_log(eDest)
{
    std::call_once(m_init_once, [&] {
        m_oss = static_cast<XrdOss *>(xrdEnv.GetPtr("XrdOss*"));
        if (!m_oss) {
            m_log.Log(LogMask::Error, "RequestManager", "XrdOss plugin is not configured; prestage functionality disabled");
        }
    });
}

bool PrestageRequestManager::Produce(
    PrestageRequestManager::PrestageRequest &handler) {

    if (!m_oss) {
        m_log.Log(LogMask::Debug, "RequestManager", "XrdOss plugin is not configured; prestage functionality disabled");
        return false;
    }

    std::shared_ptr<PrestageQueue> queue;
    {
        m_mutex.lock_shared();
        std::lock_guard guard{m_mutex, std::adopt_lock};
        auto iter = m_pool_map.find(handler.GetIdentifier());
        if (iter != m_pool_map.end()) {
            queue = iter->second;
        }
    }
    if (!queue) {
        std::lock_guard guard(m_mutex);
        auto iter = m_pool_map.find(handler.GetIdentifier());
        if (iter == m_pool_map.end()) {
            queue = std::make_shared<PrestageQueue>(handler.GetIdentifier(),
                                                       *this, *m_oss);
            m_pool_map.insert(
                iter, {handler.GetIdentifier(), queue});
        } else {
            queue = iter->second;
        }
    }
    return queue->Produce(handler);
}
