#include <Windows.h>
#include <TlHelp32.h>
#include <winhttp.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "control_policy.h"

namespace {
using Clock = std::chrono::steady_clock;

constexpr std::size_t kMaxTextFileBytes = 1024U * 1024U;
constexpr std::size_t kMaxHealthBytes = 64U * 1024U;

class Handle final {
public:
    Handle() = default;
    explicit Handle(HANDLE value) : value_(value) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(other.release()) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) reset(other.release());
        return *this;
    }
    ~Handle() { reset(); }
    [[nodiscard]] HANDLE get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }
    [[nodiscard]] HANDLE release() noexcept {
        const HANDLE value = value_;
        value_ = nullptr;
        return value;
    }
    void reset(HANDLE value = nullptr) noexcept {
        if (*this) CloseHandle(value_);
        value_ = value;
    }

private:
    HANDLE value_{nullptr};
};

class InternetHandle final {
public:
    InternetHandle() = default;
    explicit InternetHandle(HINTERNET value) : value_(value) {}
    InternetHandle(const InternetHandle&) = delete;
    InternetHandle& operator=(const InternetHandle&) = delete;
    ~InternetHandle() { if (value_ != nullptr) WinHttpCloseHandle(value_); }
    [[nodiscard]] HINTERNET get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept { return value_ != nullptr; }

private:
    HINTERNET value_{nullptr};
};

enum class Backend : std::uint8_t { x32, x64 };
enum class Command : std::uint8_t { status, start, stop, restart, scyllaProfile };

struct Options {
    Command command{Command::status};
    std::optional<Backend> backend;
    std::optional<std::filesystem::path> root;
    std::optional<std::string> profile;
    std::uint32_t timeoutMs{20'000U};
    bool force{false};
};

struct Paths {
    std::filesystem::path releaseRoot;
    std::filesystem::path host;
    std::filesystem::path config;
    std::filesystem::path scyllaIni;
};

struct HostProcess {
    DWORD id{0U};
    Handle handle;
};

struct Health {
    bool ready{false};
    std::string instanceId;
    std::string debuggeeState;
};

std::optional<std::string> Utf8(const std::wstring_view value) {
    if (value.empty()) return std::string{};
    if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return std::nullopt;
    }
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                             static_cast<int>(value.size()), nullptr, 0, nullptr,
                                             nullptr);
    if (required <= 0) return std::nullopt;
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                           static_cast<int>(value.size()), result.data(), required, nullptr,
                           nullptr) != required) {
        return std::nullopt;
    }
    return result;
}

std::optional<std::wstring> Wide(const std::string_view value) {
    if (value.empty()) return std::wstring{};
    if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return std::nullopt;
    }
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                             static_cast<int>(value.size()), nullptr, 0);
    if (required <= 0) return std::nullopt;
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                           static_cast<int>(value.size()), result.data(), required) != required) {
        return std::nullopt;
    }
    return result;
}

std::string JsonString(const std::string_view value) {
    std::string result{"\""};
    result.reserve(value.size() + 2U);
    constexpr char digits[] = "0123456789abcdef";
    for (const unsigned char byte : value) {
        switch (byte) {
        case '"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\b': result += "\\b"; break;
        case '\f': result += "\\f"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (byte < 0x20U) {
                result += "\\u00";
                result.push_back(digits[byte >> 4U]);
                result.push_back(digits[byte & 0x0fU]);
            } else {
                result.push_back(static_cast<char>(byte));
            }
        }
    }
    result.push_back('"');
    return result;
}

int Error(const int exitCode, const std::string_view code, const std::string_view message,
          const bool retryable) {
    std::cout << "{\"status\":\"error\",\"code\":" << JsonString(code)
              << ",\"message\":" << JsonString(message)
              << ",\"retryable\":" << (retryable ? "true" : "false") << "}\n";
    return exitCode;
}

const char* BackendName(const Backend backend) noexcept {
    return backend == Backend::x32 ? "x32" : "x64";
}

bool ParseUnsigned(const std::wstring_view value, std::uint32_t& result) {
    if (value.empty() || value.size() > 10U) return false;
    std::uint64_t parsed = 0U;
    for (const wchar_t character : value) {
        if (character < L'0' || character > L'9') return false;
        parsed = parsed * 10U + static_cast<unsigned int>(character - L'0');
        if (parsed > std::numeric_limits<std::uint32_t>::max()) return false;
    }
    result = static_cast<std::uint32_t>(parsed);
    return true;
}

std::optional<Options> ParseOptions(const int argc, wchar_t* argv[], std::string& error) {
    error.clear();
    if (argc < 2 || argc > 12) {
        error = "expected one command and bounded options";
        return std::nullopt;
    }
    Options options;
    const std::wstring_view command(argv[1]);
    if (command == L"status") options.command = Command::status;
    else if (command == L"start") options.command = Command::start;
    else if (command == L"stop") options.command = Command::stop;
    else if (command == L"restart") options.command = Command::restart;
    else if (command == L"scyllahide-profile") options.command = Command::scyllaProfile;
    else {
        error = "unknown command";
        return std::nullopt;
    }
    bool timeoutSeen = false;
    for (int index = 2; index < argc; ++index) {
        const std::wstring_view flag(argv[index]);
        if (flag == L"--force") {
            if (options.force) {
                error = "--force must not be repeated";
                return std::nullopt;
            }
            options.force = true;
            continue;
        }
        if (index + 1 >= argc) {
            error = "option requires a value";
            return std::nullopt;
        }
        const std::wstring_view value(argv[++index]);
        if (flag == L"--backend") {
            if (options.backend) {
                error = "--backend must not be repeated";
                return std::nullopt;
            }
            if (value == L"x32") options.backend = Backend::x32;
            else if (value == L"x64") options.backend = Backend::x64;
            else {
                error = "--backend must be x32 or x64";
                return std::nullopt;
            }
        } else if (flag == L"--root") {
            if (options.root || value.empty() || value.size() > 32'767U) {
                error = "--root is repeated, empty, or oversized";
                return std::nullopt;
            }
            options.root = std::filesystem::path(value);
        } else if (flag == L"--profile") {
            if (options.profile) {
                error = "--profile must not be repeated";
                return std::nullopt;
            }
            const auto encoded = Utf8(value);
            if (!encoded || encoded->empty() || encoded->size() > 128U) {
                error = "--profile is invalid or oversized";
                return std::nullopt;
            }
            options.profile = *encoded;
        } else if (flag == L"--timeout-ms") {
            if (timeoutSeen || !ParseUnsigned(value, options.timeoutMs) ||
                options.timeoutMs < 1'000U || options.timeoutMs > 60'000U) {
                error = "--timeout-ms must be a unique value from 1000 through 60000";
                return std::nullopt;
            }
            timeoutSeen = true;
        } else {
            error = "unknown option";
            return std::nullopt;
        }
    }
    if (!options.backend) {
        error = "--backend is required";
        return std::nullopt;
    }
    if ((options.command == Command::scyllaProfile) != options.profile.has_value()) {
        error = "--profile is required only for scyllahide-profile";
        return std::nullopt;
    }
    if (options.force && options.command != Command::stop &&
        options.command != Command::restart) {
        error = "--force is valid only for stop and restart";
        return std::nullopt;
    }
    return options;
}

std::optional<std::filesystem::path> ExecutablePath() {
    std::wstring value(32'768U, L'\0');
    const DWORD length =
        GetModuleFileNameW(nullptr, value.data(), static_cast<DWORD>(value.size()));
    if (length == 0U || length >= value.size()) return std::nullopt;
    value.resize(length);
    return std::filesystem::path(value);
}

std::optional<Paths> ResolvePaths(const Options& options, std::string& error) {
    std::filesystem::path candidate;
    if (options.root) {
        candidate = std::filesystem::absolute(*options.root);
        if (std::filesystem::is_directory(candidate / "release" / "x32") &&
            std::filesystem::is_directory(candidate / "release" / "x64")) {
            candidate /= "release";
        }
    } else {
        const auto executable = ExecutablePath();
        if (!executable) {
            error = "controller executable path is unavailable";
            return std::nullopt;
        }
        candidate = executable->parent_path().parent_path();
    }
    std::error_code canonicalError;
    candidate = std::filesystem::weakly_canonical(candidate, canonicalError);
    if (canonicalError || !std::filesystem::is_directory(candidate / "x32") ||
        !std::filesystem::is_directory(candidate / "x64")) {
        error = "x64dbg root must contain x32 and x64 directories";
        return std::nullopt;
    }
    const Backend backend = *options.backend;
    const std::filesystem::path backendDirectory =
        candidate / (backend == Backend::x32 ? "x32" : "x64");
    const std::filesystem::path host =
        backendDirectory / (backend == Backend::x32 ? "x32dbg.exe" : "x64dbg.exe");
    if (!std::filesystem::is_regular_file(host)) {
        error = "selected debugger executable is missing";
        return std::nullopt;
    }
    return Paths{candidate,
                 std::filesystem::weakly_canonical(host),
                 candidate / "mcp" /
                     (backend == Backend::x32 ? "x64dbg-mcp-server-x32.toml"
                                              : "x64dbg-mcp-server-x64.toml"),
                 backendDirectory / "plugins" / "scylla_hide.ini"};
}

std::optional<std::string> ReadFileBounded(const std::filesystem::path& path,
                                           const std::size_t maximum,
                                           std::string& error) {
    std::error_code sizeError;
    const std::uintmax_t size = std::filesystem::file_size(path, sizeError);
    if (sizeError || size == 0U || size > maximum) {
        error = "file is missing, empty, or exceeds its bound";
        return std::nullopt;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        error = "file could not be opened";
        return std::nullopt;
    }
    std::string value(static_cast<std::size_t>(size), '\0');
    input.read(value.data(), static_cast<std::streamsize>(value.size()));
    if (input.gcount() != static_cast<std::streamsize>(value.size()) ||
        input.peek() != std::char_traits<char>::eof()) {
        error = "file could not be read exactly";
        return std::nullopt;
    }
    return value;
}

bool EqualPath(const std::filesystem::path& left, const std::filesystem::path& right) {
    return _wcsicmp(left.c_str(), right.c_str()) == 0;
}

std::optional<std::vector<HostProcess>> FindHosts(const std::filesystem::path& expected,
                                                  std::string& error) {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0U));
    if (!snapshot) {
        error = "process snapshot failed";
        return std::nullopt;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::vector<HostProcess> result;
    if (Process32FirstW(snapshot.get(), &entry) == FALSE) {
        if (GetLastError() == ERROR_NO_MORE_FILES) return result;
        error = "process enumeration failed";
        return std::nullopt;
    }
    do {
        Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE,
                                   entry.th32ProcessID));
        if (!process) continue;
        std::wstring path(32'768U, L'\0');
        DWORD length = static_cast<DWORD>(path.size());
        if (QueryFullProcessImageNameW(process.get(), 0U, path.data(), &length) == FALSE ||
            length == 0U) {
            continue;
        }
        path.resize(length);
        if (EqualPath(std::filesystem::path(path), expected)) {
            result.push_back({entry.th32ProcessID, std::move(process)});
        }
    } while (Process32NextW(snapshot.get(), &entry) != FALSE);
    return result;
}

std::optional<std::string> JsonStringField(const std::string_view json,
                                           const std::string_view field) {
    const std::string needle = "\"" + std::string(field) + "\"";
    const std::size_t key = json.find(needle);
    if (key == std::string_view::npos) return std::nullopt;
    std::size_t cursor = key + needle.size();
    while (cursor < json.size() && (json[cursor] == ' ' || json[cursor] == '\t' ||
                                    json[cursor] == '\r' || json[cursor] == '\n')) ++cursor;
    if (cursor >= json.size() || json[cursor++] != ':') return std::nullopt;
    while (cursor < json.size() && (json[cursor] == ' ' || json[cursor] == '\t' ||
                                    json[cursor] == '\r' || json[cursor] == '\n')) ++cursor;
    if (cursor >= json.size() || json[cursor++] != '"') return std::nullopt;
    const std::size_t end = json.find('"', cursor);
    if (end == std::string_view::npos || end - cursor > 128U ||
        json.substr(cursor, end - cursor).find('\\') != std::string_view::npos) {
        return std::nullopt;
    }
    return std::string(json.substr(cursor, end - cursor));
}

Health QueryHealth(const mcp::control::ServerConfig& config, const std::uint32_t timeoutMs) {
    Health result;
    const auto token = Wide(config.bearerToken);
    if (!token) return result;
    InternetHandle session(WinHttpOpen(L"x96dbg-mcp-control/1",
                                       WINHTTP_ACCESS_TYPE_NO_PROXY,
                                       WINHTTP_NO_PROXY_NAME,
                                       WINHTTP_NO_PROXY_BYPASS, 0U));
    if (!session) return result;
    const int timeout = static_cast<int>((std::max)(1U, (std::min)(timeoutMs, 5'000U)));
    if (WinHttpSetTimeouts(session.get(), timeout, timeout, timeout, timeout) == FALSE) {
        return result;
    }
    InternetHandle connection(
        WinHttpConnect(session.get(), L"127.0.0.1", config.port, 0U));
    if (!connection) return result;
    InternetHandle request(WinHttpOpenRequest(connection.get(), L"GET", L"/health/ready",
                                               nullptr, WINHTTP_NO_REFERER,
                                               WINHTTP_DEFAULT_ACCEPT_TYPES, 0U));
    if (!request) return result;
    const std::wstring authorization = L"Authorization: Bearer " + *token;
    if (WinHttpAddRequestHeaders(request.get(), authorization.c_str(),
                                 static_cast<DWORD>(authorization.size()),
                                 WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE) == FALSE ||
        WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0U,
                           WINHTTP_NO_REQUEST_DATA, 0U, 0U, 0U) == FALSE ||
        WinHttpReceiveResponse(request.get(), nullptr) == FALSE) {
        return result;
    }
    DWORD status = 0U;
    DWORD statusSize = sizeof(status);
    if (WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE |
                                              WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize,
                            WINHTTP_NO_HEADER_INDEX) == FALSE ||
        status != 200U) {
        return result;
    }
    std::string body;
    for (;;) {
        DWORD available = 0U;
        if (WinHttpQueryDataAvailable(request.get(), &available) == FALSE) return {};
        if (available == 0U) break;
        if (available > kMaxHealthBytes - body.size()) return {};
        const std::size_t oldSize = body.size();
        body.resize(oldSize + available);
        DWORD read = 0U;
        if (WinHttpReadData(request.get(), body.data() + oldSize, available, &read) == FALSE ||
            read == 0U) {
            return {};
        }
        body.resize(oldSize + read);
    }
    const auto instance = JsonStringField(body, "instance_id");
    const auto debuggerState = JsonStringField(body, "debugger_state");
    if (!instance || !mcp::control::IsCanonicalUuid(*instance) || !debuggerState ||
        !(*debuggerState == "absent" || *debuggerState == "starting" ||
          *debuggerState == "paused" || *debuggerState == "running" ||
          *debuggerState == "stopping" || *debuggerState == "exited")) {
        return {};
    }
    result.ready = true;
    result.instanceId = *instance;
    result.debuggeeState = *debuggerState;
    return result;
}

std::optional<mcp::control::ServerConfig> LoadServerConfig(const Paths& paths,
                                                           std::string& error) {
    const auto text = ReadFileBounded(paths.config, 64U * 1024U, error);
    if (!text) return std::nullopt;
    return mcp::control::ParseServerConfig(*text, error);
}

struct WindowSearch {
    DWORD processId{0U};
    HWND window{nullptr};
};

BOOL CALLBACK FindMainWindow(HWND window, LPARAM parameter) {
    auto* search = reinterpret_cast<WindowSearch*>(parameter);
    DWORD processId = 0U;
    GetWindowThreadProcessId(window, &processId);
    if (processId == search->processId && IsWindowVisible(window) != FALSE &&
        GetWindow(window, GW_OWNER) == nullptr) {
        search->window = window;
        return FALSE;
    }
    return TRUE;
}

std::uint32_t RemainingMs(const Clock::time_point deadline) {
    const auto now = Clock::now();
    if (now >= deadline) return 0U;
    const auto value =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
    return static_cast<std::uint32_t>((std::min<std::int64_t>)(value, 60'000));
}

int Status(const Backend backend, const Paths& paths,
           const mcp::control::ServerConfig& config, const std::uint32_t timeoutMs) {
    std::string error;
    auto hosts = FindHosts(paths.host, error);
    if (!hosts) return Error(5, "OS_ERROR", error, true);
    if (hosts->size() > 1U) {
        return Error(3, "MULTIPLE_HOSTS", "multiple exact-path debugger hosts are running",
                     false);
    }
    const auto path = Utf8(paths.host.native());
    if (!path) return Error(5, "OS_ERROR", "host path is not valid UTF-16", false);
    if (hosts->empty()) {
        std::cout << "{\"status\":\"ok\",\"backend\":" << JsonString(BackendName(backend))
                  << ",\"host_state\":\"stopped\",\"host_path\":" << JsonString(*path)
                  << ",\"process_id\":null,\"mcp_state\":\"unavailable\","
                     "\"instance_id\":null,\"debuggee_state\":null}\n";
        return 0;
    }
    const Health health = QueryHealth(config, (std::min)(timeoutMs, 2'000U));
    std::cout << "{\"status\":\"ok\",\"backend\":" << JsonString(BackendName(backend))
              << ",\"host_state\":\"running\",\"host_path\":" << JsonString(*path)
              << ",\"process_id\":" << hosts->front().id << ",\"mcp_state\":"
              << JsonString(health.ready ? "ready" : "unavailable") << ",\"instance_id\":"
              << (health.ready ? JsonString(health.instanceId) : "null")
              << ",\"debuggee_state\":"
              << (health.ready ? JsonString(health.debuggeeState) : "null") << "}\n";
    return 0;
}

struct StartResult {
    int exitCode{0};
    DWORD processId{0U};
    std::string instanceId;
    bool alreadyRunning{false};
};

StartResult StartHost(const Paths& paths,
                      const mcp::control::ServerConfig& config,
                      const Clock::time_point deadline) {
    std::string error;
    auto hosts = FindHosts(paths.host, error);
    if (!hosts) return {Error(5, "OS_ERROR", error, true)};
    if (hosts->size() > 1U) {
        return {Error(3, "MULTIPLE_HOSTS", "multiple exact-path debugger hosts are running",
                      false)};
    }
    if (!hosts->empty()) {
        const Health health = QueryHealth(config, (std::min)(RemainingMs(deadline), 2'000U));
        if (!health.ready) {
            return {Error(3, "HOST_RUNNING_NOT_READY",
                          "debugger host is running but its MCP backend is not ready", true)};
        }
        return {0, hosts->front().id, health.instanceId, true};
    }
    std::wstring commandLine = L"\"" + paths.host.native() + L"\"";
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const std::wstring workingDirectory = paths.host.parent_path().native();
    if (CreateProcessW(paths.host.c_str(), mutableCommand.data(), nullptr, nullptr, FALSE, 0U,
                       nullptr, workingDirectory.c_str(), &startup, &process) == FALSE) {
        return {Error(5, "START_FAILED", "CreateProcessW failed", true)};
    }
    Handle processHandle(process.hProcess);
    Handle threadHandle(process.hThread);
    while (Clock::now() < deadline) {
        if (WaitForSingleObject(processHandle.get(), 0U) == WAIT_OBJECT_0) {
            return {Error(3, "HOST_EXITED", "debugger exited before MCP readiness", false)};
        }
        const Health health = QueryHealth(config, (std::min)(RemainingMs(deadline), 1'000U));
        if (health.ready) return {0, process.dwProcessId, health.instanceId, false};
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return {Error(4, "START_TIMEOUT",
                  "debugger was started but MCP readiness was not observed; outcome is unknown",
                  true)};
}

int EmitStart(const Backend backend, const StartResult& result) {
    if (result.exitCode != 0) return result.exitCode;
    std::cout << "{\"status\":\"ok\",\"backend\":" << JsonString(BackendName(backend))
              << ",\"action\":\"start\",\"process_id\":" << result.processId
              << ",\"instance_id\":" << JsonString(result.instanceId)
              << ",\"already_running\":" << (result.alreadyRunning ? "true" : "false")
              << "}\n";
    return 0;
}

struct StopResult {
    int exitCode{0};
    DWORD processId{0U};
    bool alreadyStopped{false};
};

StopResult StopHost(const Paths& paths, const mcp::control::ServerConfig& config,
                    const Clock::time_point deadline, const bool force) {
    std::string error;
    auto hosts = FindHosts(paths.host, error);
    if (!hosts) return {Error(5, "OS_ERROR", error, true)};
    if (hosts->size() > 1U) {
        return {Error(3, "MULTIPLE_HOSTS", "multiple exact-path debugger hosts are running",
                      false)};
    }
    if (hosts->empty()) return {0, 0U, true};
    HostProcess& host = hosts->front();
    if (!force) {
        const Health health = QueryHealth(config, (std::min)(RemainingMs(deadline), 2'000U));
        if (!health.ready) {
            return {Error(3, "BACKEND_UNAVAILABLE",
                          "refusing to close a host whose debugger state is unobservable; use --force",
                          false)};
        }
        if (health.debuggeeState != "absent") {
            return {Error(3, "DEBUGGEE_ACTIVE",
                          "refusing to close a host with an active debuggee; use --force", false)};
        }
    }
    WindowSearch search{host.id, nullptr};
    EnumWindows(FindMainWindow, reinterpret_cast<LPARAM>(&search));
    if (search.window == nullptr ||
        PostMessageW(search.window, WM_CLOSE, 0U, 0) == FALSE) {
        return {Error(3, "NO_MAIN_WINDOW", "debugger main window could not be closed", false)};
    }
    const DWORD wait = WaitForSingleObject(host.handle.get(), RemainingMs(deadline));
    if (wait == WAIT_TIMEOUT) {
        return {Error(4, "STOP_TIMEOUT",
                      "debugger did not exit before the deadline; outcome is unknown", true)};
    }
    if (wait != WAIT_OBJECT_0) {
        return {Error(5, "WAIT_FAILED", "waiting for debugger exit failed", true)};
    }
    return {0, host.id, false};
}

int EmitStop(const Backend backend, const StopResult& result) {
    if (result.exitCode != 0) return result.exitCode;
    std::cout << "{\"status\":\"ok\",\"backend\":" << JsonString(BackendName(backend))
              << ",\"action\":\"stop\",\"process_id\":"
              << (result.alreadyStopped ? "null" : std::to_string(result.processId))
              << ",\"already_stopped\":" << (result.alreadyStopped ? "true" : "false")
              << "}\n";
    return 0;
}

bool AtomicReplace(const std::filesystem::path& path, const std::string_view text,
                   std::string& error) {
    const std::filesystem::path temporary =
        path.parent_path() / (L".scylla-hide-mcp-" + std::to_wstring(GetCurrentProcessId()) +
                              L".tmp");
    Handle output(CreateFileW(temporary.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!output) {
        error = "temporary ScyllaHide config could not be created";
        return false;
    }
    DWORD written = 0U;
    const bool writeOk = text.size() <= std::numeric_limits<DWORD>::max() &&
                         WriteFile(output.get(), text.data(), static_cast<DWORD>(text.size()),
                                   &written, nullptr) != FALSE &&
                         written == static_cast<DWORD>(text.size()) &&
                         FlushFileBuffers(output.get()) != FALSE;
    output.reset();
    if (!writeOk || MoveFileExW(temporary.c_str(), path.c_str(),
                                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
        DeleteFileW(temporary.c_str());
        error = "ScyllaHide config replacement failed";
        return false;
    }
    return true;
}

int UpdateProfile(const Backend backend, const Paths& paths, const std::string_view profile) {
    std::string error;
    auto hosts = FindHosts(paths.host, error);
    if (!hosts) return Error(5, "OS_ERROR", error, true);
    if (!hosts->empty()) {
        return Error(3, "HOST_RUNNING",
                     "ScyllaHide profile can be changed only while the debugger is stopped",
                     false);
    }
    const auto text = ReadFileBounded(paths.scyllaIni, kMaxTextFileBytes, error);
    if (!text) return Error(3, "SCYLLAHIDE_NOT_INSTALLED", error, false);
    const auto updated = mcp::control::SetScyllaHideProfile(*text, profile, error);
    if (!updated) return Error(2, "INVALID_PROFILE", error, false);
    if (!AtomicReplace(paths.scyllaIni, updated->text, error)) {
        return Error(5, "PROFILE_WRITE_FAILED", error, true);
    }
    std::cout << "{\"status\":\"ok\",\"backend\":" << JsonString(BackendName(backend))
              << ",\"action\":\"scyllahide-profile\",\"profile\":"
              << JsonString(updated->canonicalProfile) << ",\"reload_required\":true}\n";
    return 0;
}

} // namespace

int wmain(const int argc, wchar_t* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    std::string error;
    const auto options = ParseOptions(argc, argv, error);
    if (!options) return Error(2, "INVALID_ARGUMENT", error, false);
    const auto paths = ResolvePaths(*options, error);
    if (!paths) return Error(2, "INVALID_LAYOUT", error, false);
    const Backend backend = *options->backend;
    if (options->command == Command::scyllaProfile) {
        return UpdateProfile(backend, *paths, *options->profile);
    }
    const auto config = LoadServerConfig(*paths, error);
    if (!config) return Error(2, "CONFIG_INVALID", error, false);
    const Clock::time_point deadline =
        Clock::now() + std::chrono::milliseconds(options->timeoutMs);
    switch (options->command) {
    case Command::status: return Status(backend, *paths, *config, options->timeoutMs);
    case Command::start:
        return EmitStart(backend, StartHost(*paths, *config, deadline));
    case Command::stop:
        return EmitStop(backend, StopHost(*paths, *config, deadline, options->force));
    case Command::restart: {
        const StopResult stopped = StopHost(*paths, *config, deadline, options->force);
        if (stopped.exitCode != 0) return stopped.exitCode;
        const StartResult started = StartHost(*paths, *config, deadline);
        if (started.exitCode != 0) return started.exitCode;
        std::cout << "{\"status\":\"ok\",\"backend\":"
                  << JsonString(BackendName(backend))
                  << ",\"action\":\"restart\",\"previous_process_id\":"
                  << (stopped.alreadyStopped ? "null" : std::to_string(stopped.processId))
                  << ",\"process_id\":" << started.processId << ",\"instance_id\":"
                  << JsonString(started.instanceId) << "}\n";
        return 0;
    }
    case Command::scyllaProfile: break;
    }
    return Error(5, "INTERNAL", "unreachable command state", false);
}
