#include "event_stream.h"

#include <sddl.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <limits>
#include <memory>
#include <string_view>

#include "jansson/jansson.h"

namespace mcp {
namespace {
constexpr DWORD kMaxFrameBytes = 1024U * 1024U;

bool ReadAll(const HANDLE handle, void* data, DWORD size) noexcept {
    auto* cursor = static_cast<std::byte*>(data);
    while (size != 0U) {
        DWORD read = 0U;
        if (!ReadFile(handle, cursor, size, &read, nullptr) || read == 0U) return false;
        cursor += read;
        size -= read;
    }
    return true;
}

bool WriteAll(const HANDLE handle, const void* data, DWORD size) noexcept {
    const auto* cursor = static_cast<const std::byte*>(data);
    while (size != 0U) {
        DWORD written = 0U;
        if (!WriteFile(handle, cursor, size, &written, nullptr) || written == 0U) return false;
        cursor += written;
        size -= written;
    }
    return true;
}

bool ReadFrameBounded(const HANDLE pipe, std::string& payload, const DWORD timeoutMs) {
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    const auto waitForBytes = [pipe, deadline](const DWORD required) {
        for (;;) {
            DWORD available = 0U;
            if (!PeekNamedPipe(pipe, nullptr, 0U, nullptr, &available, nullptr)) return false;
            if (available >= required) return true;
            if (GetTickCount64() >= deadline) return false;
            Sleep(10U);
        }
    };
    if (!waitForBytes(sizeof(DWORD))) return false;
    DWORD length = 0U;
    if (!ReadAll(pipe, &length, sizeof(length)) || length == 0U || length > kMaxFrameBytes ||
        !waitForBytes(length)) return false;
    payload.resize(length);
    return ReadAll(pipe, payload.data(), length);
}

bool WriteFrame(const HANDLE pipe, const std::string_view payload) noexcept {
    if (payload.empty() || payload.size() > kMaxFrameBytes ||
        payload.size() > (std::numeric_limits<DWORD>::max)()) return false;
    const auto length = static_cast<DWORD>(payload.size());
    return WriteAll(pipe, &length, sizeof(length)) && WriteAll(pipe, payload.data(), length);
}

struct JsonDeleter { void operator()(json_t* value) const noexcept { json_decref(value); } };

bool ValidHello(const std::string_view bytes, const std::string& nonce,
                const std::string& instanceId) {
    std::unique_ptr<json_t, JsonDeleter> root(
        json_loadb(bytes.data(), bytes.size(), JSON_REJECT_DUPLICATES, nullptr));
    if (!root || !json_is_object(root.get()) || json_object_size(root.get()) != 3U) return false;
    const json_t* type = json_object_get(root.get(), "type");
    const json_t* suppliedNonce = json_object_get(root.get(), "nonce");
    const json_t* suppliedInstance = json_object_get(root.get(), "instance_id");
    return json_is_string(type) && json_string_length(type) == 5U &&
        std::string_view(json_string_value(type), 5U) == "HELLO" &&
        json_is_string(suppliedNonce) && json_string_length(suppliedNonce) == nonce.size() &&
        std::equal(nonce.begin(), nonce.end(), json_string_value(suppliedNonce)) &&
        json_is_string(suppliedInstance) && json_string_length(suppliedInstance) == instanceId.size() &&
        std::equal(instanceId.begin(), instanceId.end(), json_string_value(suppliedInstance));
}
}

EventStream::~EventStream() { Stop(); }

bool EventStream::Start(const std::wstring& pipeName, const std::string& nonce) {
    Stop();
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;OW)(A;;GA;;;SY)", SDDL_REVISION_1, &descriptor, nullptr)) return false;
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    pipe_ = CreateNamedPipeW(pipeName.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1U, kMaxFrameBytes, kMaxFrameBytes, 5000U, &attributes);
    LocalFree(descriptor);
    if (pipe_ == INVALID_HANDLE_VALUE) return false;
    {
        std::lock_guard lock(mutex_);
        nonce_ = nonce;
        instanceId_.clear();
        queue_.clear();
        dropped_ = 0U;
        stopping_ = false;
    }
    try { worker_ = std::thread(&EventStream::Worker, this); }
    catch (...) {
        CloseHandle(pipe_);
        pipe_ = INVALID_HANDLE_VALUE;
        return false;
    }
    return true;
}

void EventStream::SetInstanceId(const std::string& instanceId) noexcept {
    {
        std::lock_guard lock(mutex_);
        try { instanceId_ = instanceId; }
        catch (...) { stopping_ = true; }
    }
    changed_.notify_all();
}

void EventStream::Enqueue(const EventRecord& event) noexcept {
    {
        std::lock_guard lock(mutex_);
        if (stopping_) return;
        try {
            if (queue_.size() == kMaxQueuedEvents) {
                queue_.pop_front();
                ++dropped_;
            }
            queue_.push_back(event);
        } catch (...) { ++dropped_; }
    }
    changed_.notify_one();
}

void EventStream::Worker() noexcept {
    try {
        for (;;) {
            const BOOL connected = ConnectNamedPipe(pipe_, nullptr);
            if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) return;
            std::string hello;
            if (!ReadFrameBounded(pipe_, hello, 3000U)) {
                DisconnectNamedPipe(pipe_);
                continue;
            }
            std::string nonce;
            std::string instanceId;
            {
                std::unique_lock lock(mutex_);
                changed_.wait(lock, [this] { return stopping_ || !instanceId_.empty(); });
                if (stopping_) return;
                nonce = nonce_;
                instanceId = instanceId_;
            }
            if (!ValidHello(hello, nonce, instanceId) ||
                !WriteFrame(pipe_, R"({"type":"READY"})")) {
                DisconnectNamedPipe(pipe_);
                continue;
            }
            for (;;) {
                EventRecord event;
                std::uint64_t dropped = 0U;
                bool hasEvent = false;
                bool disconnected = false;
                {
                    std::unique_lock lock(mutex_);
                    while (!stopping_ && dropped_ == 0U && queue_.empty()) {
                        if (changed_.wait_for(lock, std::chrono::milliseconds(250)) !=
                            std::cv_status::timeout) continue;
                        lock.unlock();
                        DWORD available = 0U;
                        const bool stillConnected = PeekNamedPipe(
                            pipe_, nullptr, 0U, nullptr, &available, nullptr) != FALSE;
                        lock.lock();
                        if (!stillConnected) {
                            disconnected = true;
                            break;
                        }
                    }
                    if (stopping_) return;
                    if (disconnected) {
                        DisconnectNamedPipe(pipe_);
                        break;
                    }
                    dropped = dropped_;
                    dropped_ = 0U;
                    if (dropped == 0U) {
                        event = queue_.front();
                        queue_.pop_front();
                        hasEvent = true;
                    }
                }
                const std::string payload = dropped != 0U
                    ? std::string("{\"type\":\"gap\",\"dropped\":") +
                          std::to_string(dropped) + "}"
                    : EventJson(event);
                if (WriteFrame(pipe_, payload)) continue;
                {
                    std::lock_guard lock(mutex_);
                    if (hasEvent) {
                        try { queue_.push_front(event); }
                        catch (...) { ++dropped_; }
                    } else {
                        dropped_ += dropped;
                    }
                }
                DisconnectNamedPipe(pipe_);
                break;
            }
        }
    } catch (...) {
        {
            std::lock_guard lock(mutex_);
            dropped_ += queue_.size();
            queue_.clear();
        }
    }
}

void EventStream::Stop() noexcept {
    {
        std::lock_guard lock(mutex_);
        stopping_ = true;
    }
    changed_.notify_all();
    if (worker_.joinable()) CancelSynchronousIo(worker_.native_handle());
    if (pipe_ != INVALID_HANDLE_VALUE) {
        CancelIoEx(pipe_, nullptr);
        DisconnectNamedPipe(pipe_);
    }
    if (worker_.joinable()) worker_.join();
    if (pipe_ != INVALID_HANDLE_VALUE) {
        CloseHandle(pipe_);
        pipe_ = INVALID_HANDLE_VALUE;
    }
    std::lock_guard lock(mutex_);
    queue_.clear();
    dropped_ = 0U;
    SecureZeroMemory(nonce_.data(), nonce_.size());
    nonce_.clear();
    instanceId_.clear();
}
}
