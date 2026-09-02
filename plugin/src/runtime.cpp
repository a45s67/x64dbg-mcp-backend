#include "runtime.h"
#include "utf8.h"
#include "control_policy.h"

#include <bcrypt.h>
#include <sddl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "_plugins.h"
#include "_scriptapi_function.h"
#include "_scriptapi_module.h"
#include "_scriptapi_symbol.h"
#include "breakpoint_policy.h"
#include "jansson/jansson.h"
#include "launch_arguments.h"
#include "memory_filters.h"
#include "memory_search.h"
#include "patch_policy.h"
#include "pe_policy.h"
#include "register_policy.h"
#include "trace_policy.h"

namespace mcp {
namespace {
constexpr DWORD kMaxFrameBytes = 1024U * 1024U;
constexpr DWORD kShutdownMs = 5000U;
constexpr duint kMaxAnalysisModuleBytes = 128U * 1024U * 1024U;
#ifdef _WIN64
constexpr wchar_t kBackend[] = L"x64dbg";
constexpr char kBackendUtf8[] = "x64dbg";
constexpr wchar_t kConfigBackend[] = L"x64";
#else
constexpr wchar_t kBackend[] = L"x32dbg";
constexpr char kBackendUtf8[] = "x32dbg";
constexpr wchar_t kConfigBackend[] = L"x32";
#endif

void PluginLog(const char* message) {
#ifdef MCP_LIFECYCLE_HARNESS
    (void)message;
#else
    _plugin_logputs(message);
#endif
}

std::string Hex(const std::span<const unsigned char> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result(bytes.size() * 2U, '0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        result[index * 2U] = digits[bytes[index] >> 4U];
        result[index * 2U + 1U] = digits[bytes[index] & 0x0fU];
    }
    return result;
}

std::string BoundedNativeError(const std::span<const char> bytes) {
    const std::size_t length =
        (std::min)(strnlen_s(bytes.data(), bytes.size()), std::size_t{256U});
    std::string result;
    result.reserve(length);
    for (std::size_t index = 0; index < length; ++index) {
        const unsigned char byte = static_cast<unsigned char>(bytes[index]);
        result.push_back(byte >= 0x20U && byte <= 0x7eU ? static_cast<char>(byte) : '?');
    }
    return result;
}

bool WriteAll(const HANDLE handle, const void* data, DWORD size) {
    const auto* cursor = static_cast<const std::byte*>(data);
    while (size != 0U) {
        DWORD written = 0;
        if (WriteFile(handle, cursor, size, &written, nullptr) == FALSE || written == 0U) {
            return false;
        }
        cursor += written;
        size -= written;
    }
    return true;
}

bool ReadAll(const HANDLE handle, void* data, DWORD size) {
    auto* cursor = static_cast<std::byte*>(data);
    while (size != 0U) {
        DWORD read = 0;
        if (ReadFile(handle, cursor, size, &read, nullptr) == FALSE || read == 0U) {
            return false;
        }
        cursor += read;
        size -= read;
    }
    return true;
}

bool WriteFrame(const HANDLE pipe, const std::string_view payload) {
    if (payload.empty() || payload.size() > kMaxFrameBytes ||
        payload.size() > std::numeric_limits<DWORD>::max()) {
        return false;
    }
    const auto length = static_cast<DWORD>(payload.size());
    return WriteAll(pipe, &length, sizeof(length)) && WriteAll(pipe, payload.data(), length);
}

bool ReadFrame(const HANDLE pipe, std::string& payload) {
    DWORD length = 0;
    if (!ReadAll(pipe, &length, sizeof(length)) || length == 0U || length > kMaxFrameBytes) {
        return false;
    }
    payload.resize(length);
    return ReadAll(pipe, payload.data(), length);
}

struct JsonDeleter {
    void operator()(json_t* value) const noexcept { json_decref(value); }
};
using JsonOwner = std::unique_ptr<json_t, JsonDeleter>;

enum class AddressReferenceKind : std::uint8_t { absolute, moduleRva };

struct AddressReference {
    AddressReferenceKind kind{AddressReferenceKind::absolute};
    duint absolute{0};
    std::string module;
    duint rva{0};
    bool pointerWidthValid{true};
};

struct Request {
    std::string requestId;
    std::string method;
    std::uint64_t deadlineUnixMs;
    bool mutation;
    std::string expression;
    std::string path;
    std::string workingDirectory;
    std::vector<std::string> launchArguments;
    std::uint32_t targetProcessId{0U};
    AddressReference address;
    std::size_t length{0};
    std::vector<std::string> registerNames;
    std::size_t pageLimit{100U};
    std::optional<std::uint64_t> cursorGeneration;
    std::size_t cursorIndex{0U};
    std::size_t instructionCount{32U};
    std::vector<unsigned char> writeBytes;
    std::uint64_t afterGeneration{0};
    std::size_t waitTimeoutMs{5000U};
    std::string module;
    std::string query;
    std::string stringEncoding{"both"};
    std::size_t minStringLength{4U};
    std::size_t stringContextBytes{64U};
    std::optional<std::uint64_t> cursorFingerprint;
    bool discoveryCursorInvalid{false};
    bool committedOnly{false};
    bool executableOnly{false};
    bool compact{false};
    std::string registerName;
    std::uint64_t registerWriteValue{0U};
    std::string breakpointKind;
    std::string breakpointAccess;
    std::size_t breakpointSize{0U};
    std::string instruction;
    std::vector<unsigned char> expectedBytes;
    std::vector<unsigned char> expectedOriginalBytes;
    bool fillNop{false};
    bool addressProvided{false};
    std::optional<std::uint32_t> targetThreadId;
    std::string symbolName;
    std::optional<std::uint64_t> cursorSnapshotFingerprint;
    std::uint64_t afterEventSequence{0U};
    std::vector<EventKind> eventTypes;
    std::string operationId;
    std::size_t runToTimeoutMs{9000U};
    bool memorySearchModuleScope{false};
    MemoryPattern memoryPattern;
    std::uint32_t exceptionCode{0U};
    std::string exceptionChance;
    std::string managedBreakpointId;
    ConditionalSpec conditionalSpec;
    std::string conditionalExpression;
    bool conditionalInvalid{false};
    std::string traceId;
    std::string traceMode;
    std::size_t traceMaxSteps{0U};
    std::size_t traceTimeoutMs{0U};
    bool traceCursorInvalid{false};
    std::vector<std::string> expressions;
    std::string callingConvention{"auto"};
    std::size_t argumentCount{8U};
    std::string scyllaAction;
    std::string scyllaProfile;
    std::string expectedConfigGeneration;
    std::string exceptionDisposition;
    std::vector<RegisterAssignment> exceptionRegisterOverrides;
};

bool IsMutation(const std::string_view method) {
    return method == "debugger.pause" || method == "debugger.resume" ||
           method == "debugger.continue_exception" ||
           method == "debugger.step_into" || method == "debugger.step_over" ||
           method == "debugger.step_out" || method == "debugger.run_to_address" ||
           method == "registers.write" ||
           method == "debugger.stop" || method == "memory.write" ||
           method == "breakpoints.set" || method == "breakpoints.remove" ||
           method == "breakpoints.hardware.set" ||
           method == "breakpoints.hardware.remove" ||
           method == "breakpoints.memory.set" ||
           method == "breakpoints.memory.remove" ||
           method == "breakpoints.exception.set" ||
           method == "breakpoints.exception.remove" ||
           method == "breakpoints.conditional.set" ||
           method == "breakpoints.conditional.remove" ||
           method == "breakpoints.enable" || method == "breakpoints.disable" ||
           method == "assembly.patch" || method == "patches.restore" ||
           method == "debuggee.launch" || method == "debuggee.launch_dll" ||
           method == "debuggee.attach" ||
           method == "debuggee.detach" || method == "analysis.function" ||
           method == "trace.start" || method == "trace.cancel";
}

const char* EventKindName(EventKind kind) noexcept;
std::optional<EventKind> ParseEventKind(std::string_view value) noexcept;

bool IsPageMethod(const std::string_view method) {
    return method == "modules.list" || method == "threads.list" ||
           method == "breakpoints.list";
}

bool IsDiscoveryMethod(const std::string_view method) {
    return method == "symbols.search" || method == "functions.list" ||
           method == "strings.search" || method == "references.to" ||
           method == "imports.list" || method == "exports.list" ||
           method == "sections.list";
}

std::uint64_t DiscoveryFingerprint(const std::string_view method,
                                   const std::string_view module,
                                   const std::string_view query,
                                   const std::string_view encoding,
                                   const std::size_t minLength,
                                   const std::size_t contextBytes = 0U) {
    std::uint64_t hash = 14695981039346656037ULL;
    const auto add = [&hash](const std::string_view part) {
        for (const unsigned char byte : part) {
            hash ^= byte;
            hash *= 1099511628211ULL;
        }
        hash ^= 0xffU;
        hash *= 1099511628211ULL;
    };
    add(method);
    add(module);
    add(query);
    add(encoding);
    add(std::to_string(minLength));
    add(std::to_string(contextBytes));
    return hash;
}

bool ParseDiscoveryCursor(const std::string_view cursor, std::uint64_t& generation,
                          std::uint64_t& fingerprint, std::size_t& index) {
    if (!cursor.starts_with("v2:") || cursor.size() > 128U) return false;
    const auto first = cursor.find(':', 3U);
    const auto second = first == std::string_view::npos
                            ? std::string_view::npos
                            : cursor.find(':', first + 1U);
    if (first == std::string_view::npos || second == std::string_view::npos) return false;
    const auto generationResult =
        std::from_chars(cursor.data() + 3U, cursor.data() + first, generation, 10);
    const auto fingerprintResult =
        std::from_chars(cursor.data() + first + 1U, cursor.data() + second, fingerprint, 16);
    const auto indexResult =
        std::from_chars(cursor.data() + second + 1U, cursor.data() + cursor.size(), index, 10);
    return generationResult.ec == std::errc{} && generationResult.ptr == cursor.data() + first &&
           fingerprintResult.ec == std::errc{} &&
           fingerprintResult.ptr == cursor.data() + second && indexResult.ec == std::errc{} &&
           indexResult.ptr == cursor.data() + cursor.size();
}

bool ParsePatchCursor(const std::string_view cursor, std::uint64_t& generation,
                      std::uint64_t& filterFingerprint,
                      std::uint64_t& snapshotFingerprint, std::size_t& index) {
    if (!cursor.starts_with("v3:") || cursor.size() > 160U) return false;
    const auto first = cursor.find(':', 3U);
    const auto second = first == std::string_view::npos
                            ? std::string_view::npos
                            : cursor.find(':', first + 1U);
    const auto third = second == std::string_view::npos
                           ? std::string_view::npos
                           : cursor.find(':', second + 1U);
    if (first == std::string_view::npos || second == std::string_view::npos ||
        third == std::string_view::npos) return false;
    const auto generationResult =
        std::from_chars(cursor.data() + 3U, cursor.data() + first, generation, 10);
    const auto filterResult = std::from_chars(cursor.data() + first + 1U,
                                              cursor.data() + second,
                                              filterFingerprint, 16);
    const auto snapshotResult = std::from_chars(cursor.data() + second + 1U,
                                                cursor.data() + third,
                                                snapshotFingerprint, 16);
    const auto indexResult = std::from_chars(cursor.data() + third + 1U,
                                             cursor.data() + cursor.size(), index, 10);
    return generationResult.ec == std::errc{} &&
           generationResult.ptr == cursor.data() + first &&
           filterResult.ec == std::errc{} && filterResult.ptr == cursor.data() + second &&
           snapshotResult.ec == std::errc{} && snapshotResult.ptr == cursor.data() + third &&
           indexResult.ec == std::errc{} && indexResult.ptr == cursor.data() + cursor.size();
}

bool ParseCursor(const std::string_view cursor, std::uint64_t& generation, std::size_t& index) {
    if (!cursor.starts_with("v1:") || cursor.size() > 64U) {
        return false;
    }
    const auto separator = cursor.find(':', 3U);
    if (separator == std::string_view::npos) {
        return false;
    }
    const auto generationResult =
        std::from_chars(cursor.data() + 3, cursor.data() + separator, generation, 10);
    const auto indexResult =
        std::from_chars(cursor.data() + separator + 1, cursor.data() + cursor.size(), index, 10);
    return generationResult.ec == std::errc{} && generationResult.ptr == cursor.data() + separator &&
           indexResult.ec == std::errc{} && indexResult.ptr == cursor.data() + cursor.size();
}

bool IsUuid(std::string_view value);

bool ParseTraceCursor(const std::string_view cursor, std::string& traceId,
                      std::uint64_t& fingerprint, std::size_t& index) {
    if (!cursor.starts_with("v4:") || cursor.size() > 160U) return false;
    const auto first = cursor.find(':', 3U);
    const auto second = first == std::string_view::npos
                            ? std::string_view::npos
                            : cursor.find(':', first + 1U);
    if (first == std::string_view::npos || second == std::string_view::npos) return false;
    traceId.assign(cursor.substr(3U, first - 3U));
    const auto fingerprintResult = std::from_chars(cursor.data() + first + 1U,
                                                   cursor.data() + second,
                                                   fingerprint, 16);
    const auto indexResult = std::from_chars(cursor.data() + second + 1U,
                                             cursor.data() + cursor.size(), index, 10);
    return IsUuid(traceId) && fingerprintResult.ec == std::errc{} &&
           fingerprintResult.ptr == cursor.data() + second &&
           indexResult.ec == std::errc{} && indexResult.ptr == cursor.data() + cursor.size();
}

bool IsCanonicalHex(json_t* value) {
    if (!json_is_string(value)) {
        return false;
    }
    const std::string_view text(json_string_value(value), json_string_length(value));
    if (!text.starts_with("0x") || text.size() < 3U || text.size() > 34U) {
        return false;
    }
    return std::all_of(text.begin() + 2, text.end(), [](const char character) {
        return (character >= '0' && character <= '9') ||
               (character >= 'a' && character <= 'f');
    });
}

bool ParseCanonicalHex(json_t* value, duint& output) {
    if (!IsCanonicalHex(value) || json_string_length(value) > sizeof(duint) * 2U + 2U) {
        return false;
    }
    const std::string_view text(json_string_value(value), json_string_length(value));
    const auto conversion =
        std::from_chars(text.data() + 2, text.data() + text.size(), output, 16);
    return conversion.ec == std::errc{} && conversion.ptr == text.data() + text.size();
}

bool ParseCanonicalHex64(json_t* value, std::uint64_t& output) {
    if (!IsCanonicalHex(value) || json_string_length(value) > 18U) return false;
    const std::string_view text(json_string_value(value), json_string_length(value));
    const auto conversion =
        std::from_chars(text.data() + 2, text.data() + text.size(), output, 16);
    return conversion.ec == std::errc{} && conversion.ptr == text.data() + text.size();
}

bool IsBoundedModuleName(json_t* value) {
    if (!json_is_string(value) || json_string_length(value) == 0U ||
        json_string_length(value) > 260U) {
        return false;
    }
    const std::string_view text(json_string_value(value), json_string_length(value));
    return std::none_of(text.begin(), text.end(), [](const char character) {
        const auto byte = static_cast<unsigned char>(character);
        return byte < 0x20U || byte == 0x7fU || character == '/' || character == '\\';
    });
}

bool ParseAddressReference(json_t* value, AddressReference& output) {
    duint absolute = 0;
    if (IsCanonicalHex(value)) {
        const bool valid = ParseCanonicalHex(value, absolute);
        output = AddressReference{AddressReferenceKind::absolute, absolute, {}, 0, valid};
        return true;
    }
    if (!json_is_object(value)) {
        return false;
    }
    if (json_object_size(value) == 1U) {
        json_t* absoluteValue = json_object_get(value, "absolute");
        if (absoluteValue != nullptr && IsCanonicalHex(absoluteValue)) {
            const bool valid = ParseCanonicalHex(absoluteValue, absolute);
            output =
                AddressReference{AddressReferenceKind::absolute, absolute, {}, 0, valid};
            return true;
        }
        return false;
    }
    if (json_object_size(value) != 2U) {
        return false;
    }
    json_t* module = json_object_get(value, "module");
    json_t* rvaValue = json_object_get(value, "rva");
    if (!IsBoundedModuleName(module) || !IsCanonicalHex(rvaValue)) {
        return false;
    }
    duint rva = 0;
    const bool valid = ParseCanonicalHex(rvaValue, rva);
    output = AddressReference{AddressReferenceKind::moduleRva, 0,
                              std::string(json_string_value(module), json_string_length(module)),
                              rva, valid};
    return true;
}

bool IsBoundedPathString(json_t* value) {
    if (!json_is_string(value) || json_string_length(value) < 3U ||
        json_string_length(value) > 32767U) {
        return false;
    }
    const std::string_view text(json_string_value(value), json_string_length(value));
    return std::none_of(text.begin(), text.end(), [](const char character) {
        return static_cast<unsigned char>(character) < 0x20U || character == 0x7f;
    });
}

std::optional<std::string> CanonicalUtf8Path(const std::string_view input,
                                             const bool requireDirectory) {
    try {
        const std::u8string encoded(reinterpret_cast<const char8_t*>(input.data()), input.size());
        const std::filesystem::path supplied(encoded);
        if (!supplied.is_absolute()) {
            return std::nullopt;
        }
        std::error_code error;
        const std::filesystem::path canonical = std::filesystem::canonical(supplied, error);
        if (error || (requireDirectory ? !std::filesystem::is_directory(canonical, error)
                                       : !std::filesystem::is_regular_file(canonical, error)) ||
            error) {
            return std::nullopt;
        }
        const std::u8string canonicalEncoded = canonical.u8string();
        std::string result(reinterpret_cast<const char*>(canonicalEncoded.data()),
                           canonicalEncoded.size());
        if (result.empty() || result.find('"') != std::string::npos ||
            std::any_of(result.begin(), result.end(), [](const char character) {
                return static_cast<unsigned char>(character) < 0x20U || character == 0x7f;
            })) {
            return std::nullopt;
        }
        std::replace(result.begin(), result.end(), '\\', '/');
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

bool IsUuid(const std::string_view value) {
    if (value.size() != 36U) {
        return false;
    }
    for (std::size_t index = 0; index < value.size(); ++index) {
        const bool separator = index == 8U || index == 13U || index == 18U || index == 23U;
        const char character = value[index];
        if (separator ? character != '-'
                      : !((character >= '0' && character <= '9') ||
                          (character >= 'a' && character <= 'f'))) {
            return false;
        }
    }
    return true;
}

std::optional<Request> ParseRequest(const std::string_view bytes) {
    json_error_t error{};
    JsonOwner root(json_loadb(bytes.data(), bytes.size(), JSON_REJECT_DUPLICATES, &error));
    if (!root || !json_is_object(root.get()) || json_object_size(root.get()) != 5U) {
        return std::nullopt;
    }
    json_t* requestId = json_object_get(root.get(), "request_id");
    json_t* deadline = json_object_get(root.get(), "deadline_unix_ms");
    json_t* operationId = json_object_get(root.get(), "operation_id");
    json_t* method = json_object_get(root.get(), "method");
    json_t* payload = json_object_get(root.get(), "payload");
    if (!json_is_string(requestId) || !json_is_integer(deadline) ||
        !(json_is_null(operationId) || json_is_string(operationId)) || !json_is_string(method) ||
        !json_is_object(payload)) {
        return std::nullopt;
    }
    const std::string_view requestIdValue(json_string_value(requestId),
                                          json_string_length(requestId));
    const std::string_view methodValue(json_string_value(method), json_string_length(method));
    if (!IsUuid(requestIdValue) || methodValue.empty() || methodValue.size() > 64U ||
        json_integer_value(deadline) <= 0) {
        return std::nullopt;
    }
    bool mutation = IsMutation(methodValue);
    if (methodValue == "scyllahide.profile") {
        json_t* action = json_object_get(payload, "action");
        mutation = json_is_string(action) &&
                   std::string_view(json_string_value(action), json_string_length(action)) ==
                       "set";
    }
    std::string operationIdValue;
    if (json_is_string(operationId)) {
        const std::string_view operationValue(json_string_value(operationId),
                                              json_string_length(operationId));
        if (!IsUuid(operationValue)) {
            return std::nullopt;
        }
        operationIdValue.assign(operationValue);
    }
    if (mutation != json_is_string(operationId)) {
        return std::nullopt;
    }
    std::string expression;
    std::string path;
    std::string workingDirectory;
    std::vector<std::string> launchArguments;
    std::uint32_t targetProcessId = 0U;
    AddressReference addressValue;
    std::size_t lengthValue = 0;
    std::vector<std::string> registerNames;
    std::size_t pageLimit = 100U;
    std::optional<std::uint64_t> cursorGeneration;
    std::size_t cursorIndex = 0U;
    std::size_t instructionCount = 32U;
    std::vector<unsigned char> writeBytes;
    std::uint64_t afterGeneration = 0;
    std::size_t waitTimeoutMs = 5000U;
    std::string moduleFilter;
    std::string query;
    std::string stringEncoding = "both";
    std::size_t minStringLength = 4U;
    std::size_t stringContextBytes = 64U;
    std::optional<std::uint64_t> cursorFingerprint;
    bool discoveryCursorInvalid = false;
    bool committedOnly = false;
    bool executableOnly = false;
    bool compact = false;
    std::string registerName;
    std::uint64_t registerWriteValue = 0U;
    std::string breakpointKind;
    std::string breakpointAccess;
    std::size_t breakpointSize = 0U;
    std::string instruction;
    std::vector<unsigned char> expectedBytes;
    std::vector<unsigned char> expectedOriginalBytes;
    bool fillNop = false;
    bool addressProvided = false;
    std::optional<std::uint32_t> targetThreadId;
    std::string symbolName;
    std::optional<std::uint64_t> cursorSnapshotFingerprint;
    std::uint64_t afterEventSequence = 0U;
    std::vector<EventKind> eventTypes;
    std::size_t runToTimeoutMs = 9000U;
    bool memorySearchModuleScope = false;
    MemoryPattern memoryPattern;
    std::uint32_t exceptionCode = 0U;
    std::string exceptionChance;
    std::string managedBreakpointId;
    ConditionalSpec conditionalSpec;
    std::string conditionalExpression;
    bool conditionalInvalid = false;
    std::string traceId;
    std::string traceMode;
    std::size_t traceMaxSteps = 0U;
    std::size_t traceTimeoutMs = 0U;
    bool traceCursorInvalid = false;
    std::vector<std::string> expressions;
    std::string callingConvention = "auto";
    std::size_t argumentCount = 8U;
    std::string scyllaAction;
    std::string scyllaProfile;
    std::string expectedConfigGeneration;
    std::string exceptionDisposition;
    std::vector<RegisterAssignment> exceptionRegisterOverrides;
    if (methodValue == "scyllahide.profile") {
        json_t* action = json_object_get(payload, "action");
        if (!json_is_string(action)) return std::nullopt;
        scyllaAction.assign(json_string_value(action), json_string_length(action));
        if (scyllaAction == "get") {
            if (json_object_size(payload) != 1U) return std::nullopt;
        } else if (scyllaAction == "set") {
            json_t* profile = json_object_get(payload, "profile");
            json_t* generation = json_object_get(payload, "expected_config_generation");
            json_t* payloadOperationId = json_object_get(payload, "operation_id");
            if (json_object_size(payload) != 4U || !json_is_string(profile) ||
                !json_is_string(generation) || !json_is_string(payloadOperationId) ||
                json_string_length(profile) < 1U || json_string_length(profile) > 128U ||
                json_string_length(generation) != 71U) {
                return std::nullopt;
            }
            scyllaProfile.assign(json_string_value(profile), json_string_length(profile));
            expectedConfigGeneration.assign(json_string_value(generation),
                                            json_string_length(generation));
            if (!expectedConfigGeneration.starts_with("sha256:") ||
                !std::all_of(expectedConfigGeneration.begin() + 7,
                             expectedConfigGeneration.end(), [](const unsigned char byte) {
                                 return (byte >= '0' && byte <= '9') ||
                                        (byte >= 'a' && byte <= 'f');
                             })) {
                return std::nullopt;
            }
        } else {
            return std::nullopt;
        }
    } else if (methodValue == "debugger.state") {
        if (json_object_size(payload) != 0U) {
            return std::nullopt;
        }
    } else if (methodValue == "events.list") {
        json_t* after = json_object_get(payload, "after_sequence");
        json_t* types = json_object_get(payload, "types");
        json_t* limit = json_object_get(payload, "limit");
        const std::size_t expectedFields = (after ? 1U : 0U) + (types ? 1U : 0U) +
                                           (limit ? 1U : 0U);
        if (json_object_size(payload) != expectedFields) return std::nullopt;
        if (after != nullptr) {
            if (!json_is_integer(after) || json_integer_value(after) < 0 ||
                json_integer_value(after) > 9007199254740991LL) return std::nullopt;
            afterEventSequence = static_cast<std::uint64_t>(json_integer_value(after));
        }
        if (types != nullptr) {
            if (!json_is_array(types) || json_array_size(types) < 1U ||
                json_array_size(types) > 19U) return std::nullopt;
            for (std::size_t index = 0U; index < json_array_size(types); ++index) {
                json_t* value = json_array_get(types, index);
                if (!json_is_string(value)) return std::nullopt;
                const auto parsedKind = ParseEventKind(std::string_view(
                    json_string_value(value), json_string_length(value)));
                if (!parsedKind || std::find(eventTypes.begin(), eventTypes.end(), *parsedKind) !=
                                       eventTypes.end()) return std::nullopt;
                eventTypes.push_back(*parsedKind);
            }
        }
        if (limit != nullptr) {
            if (!json_is_integer(limit) || json_integer_value(limit) < 1 ||
                json_integer_value(limit) > 256) return std::nullopt;
            pageLimit = static_cast<std::size_t>(json_integer_value(limit));
        }
    } else if (methodValue == "events.wait") {
        json_t* after = json_object_get(payload, "after_sequence");
        json_t* types = json_object_get(payload, "types");
        json_t* timeout = json_object_get(payload, "timeout_ms");
        const std::size_t expectedFields = timeout == nullptr ? 2U : 3U;
        if (json_object_size(payload) != expectedFields || !json_is_integer(after) ||
            json_integer_value(after) < 0 ||
            json_integer_value(after) > 9007199254740991LL || !json_is_array(types) ||
            json_array_size(types) < 1U || json_array_size(types) > 19U) {
            return std::nullopt;
        }
        afterEventSequence = static_cast<std::uint64_t>(json_integer_value(after));
        for (std::size_t index = 0U; index < json_array_size(types); ++index) {
            json_t* value = json_array_get(types, index);
            if (!json_is_string(value)) return std::nullopt;
            const auto parsedKind = ParseEventKind(std::string_view(
                json_string_value(value), json_string_length(value)));
            if (!parsedKind || std::find(eventTypes.begin(), eventTypes.end(), *parsedKind) !=
                                   eventTypes.end()) return std::nullopt;
            eventTypes.push_back(*parsedKind);
        }
        if (timeout != nullptr) {
            if (!json_is_integer(timeout) || json_integer_value(timeout) < 1 ||
                json_integer_value(timeout) > 9000) return std::nullopt;
            waitTimeoutMs = static_cast<std::size_t>(json_integer_value(timeout));
        }
    } else if (methodValue == "debugger.snapshot") {
        json_t* registers = json_object_get(payload, "registers");
        json_t* count = json_object_get(payload, "disassembly_count");
        json_t* thread = json_object_get(payload, "thread_id");
        const std::size_t expectedFields = (registers ? 1U : 0U) + (count ? 1U : 0U) +
                                           (thread ? 1U : 0U);
        if (json_object_size(payload) != expectedFields) return std::nullopt;
        instructionCount = 8U;
        if (registers != nullptr) {
            if (!json_is_array(registers) || json_array_size(registers) < 1U ||
                json_array_size(registers) > 16U) return std::nullopt;
            for (std::size_t index = 0; index < json_array_size(registers); ++index) {
                json_t* name = json_array_get(registers, index);
                if (!json_is_string(name) || json_string_length(name) == 0U ||
                    json_string_length(name) > 32U) return std::nullopt;
                std::string value(json_string_value(name), json_string_length(name));
                if (std::find(registerNames.begin(), registerNames.end(), value) !=
                    registerNames.end()) return std::nullopt;
                registerNames.push_back(std::move(value));
            }
        }
        if (count != nullptr) {
            if (!json_is_integer(count) || json_integer_value(count) < 0 ||
                json_integer_value(count) > 64) return std::nullopt;
            instructionCount = static_cast<std::size_t>(json_integer_value(count));
        }
        if (thread != nullptr) {
            std::uint64_t parsedThread = 0U;
            if (!ParseCanonicalHex64(thread, parsedThread) || parsedThread == 0U ||
                parsedThread > 0xffffffffULL) return std::nullopt;
            targetThreadId = static_cast<std::uint32_t>(parsedThread);
        }
    } else if (methodValue == "debugger.wait_for_pause") {
        json_t* after = json_object_get(payload, "after_generation");
        json_t* timeout = json_object_get(payload, "timeout_ms");
        const std::size_t expectedFields = timeout == nullptr ? 1U : 2U;
        if (json_object_size(payload) != expectedFields || !json_is_integer(after) ||
            json_integer_value(after) < 0 ||
            json_integer_value(after) > 9007199254740991LL) {
            return std::nullopt;
        }
        afterGeneration = static_cast<std::uint64_t>(json_integer_value(after));
        if (timeout != nullptr) {
            if (!json_is_integer(timeout) || json_integer_value(timeout) < 1 ||
                json_integer_value(timeout) > 9000) {
                return std::nullopt;
            }
            waitTimeoutMs = static_cast<std::size_t>(json_integer_value(timeout));
        }
    } else if (methodValue == "debuggee.launch") {
        json_t* pathValue = json_object_get(payload, "path");
        json_t* directoryValue = json_object_get(payload, "working_directory");
        json_t* argumentsValue = json_object_get(payload, "arguments");
        const std::size_t expectedFields = 2U + (directoryValue ? 1U : 0U) +
                                           (argumentsValue ? 1U : 0U);
        if (json_object_size(payload) != expectedFields ||
            !json_is_string(json_object_get(payload, "operation_id")) ||
            !IsBoundedPathString(pathValue) ||
            (directoryValue != nullptr && !IsBoundedPathString(directoryValue))) {
            return std::nullopt;
        }
        path.assign(json_string_value(pathValue), json_string_length(pathValue));
        if (directoryValue != nullptr) {
            workingDirectory.assign(json_string_value(directoryValue),
                                    json_string_length(directoryValue));
        }
        if (argumentsValue != nullptr) {
            if (!json_is_array(argumentsValue) ||
                json_array_size(argumentsValue) > kMaxLaunchArguments) {
                return std::nullopt;
            }
            std::size_t totalBytes = 0U;
            for (std::size_t index = 0U; index < json_array_size(argumentsValue); ++index) {
                json_t* argument = json_array_get(argumentsValue, index);
                if (!json_is_string(argument)) return std::nullopt;
                const std::string_view value(json_string_value(argument),
                                             json_string_length(argument));
                if (!ValidLaunchArgument(value) ||
                    value.size() > kMaxLaunchArgumentTotalBytes - totalBytes) {
                    return std::nullopt;
                }
                totalBytes += value.size();
                launchArguments.emplace_back(value);
            }
        }
    } else if (methodValue == "debuggee.launch_dll") {
        json_t* pathValue = json_object_get(payload, "path");
        json_t* directoryValue = json_object_get(payload, "working_directory");
        const std::size_t expectedFields = 2U + (directoryValue ? 1U : 0U);
        if (json_object_size(payload) != expectedFields ||
            !json_is_string(json_object_get(payload, "operation_id")) ||
            !IsBoundedPathString(pathValue) ||
            (directoryValue != nullptr && !IsBoundedPathString(directoryValue))) {
            return std::nullopt;
        }
        path.assign(json_string_value(pathValue), json_string_length(pathValue));
        if (directoryValue != nullptr) {
            workingDirectory.assign(json_string_value(directoryValue),
                                    json_string_length(directoryValue));
        }
    } else if (methodValue == "debuggee.attach") {
        json_t* process = json_object_get(payload, "process_id");
        if (json_object_size(payload) != 2U ||
            !json_is_string(json_object_get(payload, "operation_id")) ||
            !json_is_integer(process) || json_integer_value(process) < 1 ||
            json_integer_value(process) > 4294967295LL) {
            return std::nullopt;
        }
        targetProcessId = static_cast<std::uint32_t>(json_integer_value(process));
    } else if (methodValue == "debuggee.detach") {
        if (json_object_size(payload) != 1U ||
            !json_is_string(json_object_get(payload, "operation_id"))) {
            return std::nullopt;
        }
    } else if (methodValue == "trace.start") {
        json_t* mode = json_object_get(payload, "mode");
        json_t* maxSteps = json_object_get(payload, "max_steps");
        json_t* timeout = json_object_get(payload, "timeout_ms");
        if (json_object_size(payload) != 4U ||
            !json_is_string(json_object_get(payload, "operation_id")) ||
            !json_is_string(mode) || !json_is_integer(maxSteps) ||
            json_integer_value(maxSteps) < 1 || json_integer_value(maxSteps) > 4096 ||
            !json_is_integer(timeout) || json_integer_value(timeout) < 100 ||
            json_integer_value(timeout) > 30000) return std::nullopt;
        traceMode.assign(json_string_value(mode), json_string_length(mode));
        if (traceMode != "into" && traceMode != "over") return std::nullopt;
        traceMaxSteps = static_cast<std::size_t>(json_integer_value(maxSteps));
        traceTimeoutMs = static_cast<std::size_t>(json_integer_value(timeout));
    } else if (methodValue == "trace.status") {
        json_t* id = json_object_get(payload, "trace_id");
        if (json_object_size(payload) != 1U || !json_is_string(id)) return std::nullopt;
        traceId.assign(json_string_value(id), json_string_length(id));
        if (!IsUuid(traceId)) return std::nullopt;
    } else if (methodValue == "trace.cancel") {
        json_t* id = json_object_get(payload, "trace_id");
        if (json_object_size(payload) != 2U ||
            !json_is_string(json_object_get(payload, "operation_id")) ||
            !json_is_string(id)) return std::nullopt;
        traceId.assign(json_string_value(id), json_string_length(id));
        if (!IsUuid(traceId)) return std::nullopt;
    } else if (methodValue == "trace.results") {
        json_t* id = json_object_get(payload, "trace_id");
        json_t* limit = json_object_get(payload, "limit");
        json_t* cursor = json_object_get(payload, "cursor");
        const std::size_t expectedFields = 1U + (limit ? 1U : 0U) + (cursor ? 1U : 0U);
        if (json_object_size(payload) != expectedFields || !json_is_string(id)) {
            return std::nullopt;
        }
        traceId.assign(json_string_value(id), json_string_length(id));
        if (!IsUuid(traceId)) return std::nullopt;
        if (limit != nullptr) {
            if (!json_is_integer(limit) || json_integer_value(limit) < 1 ||
                json_integer_value(limit) > 256) return std::nullopt;
            pageLimit = static_cast<std::size_t>(json_integer_value(limit));
        }
        if (cursor != nullptr) {
            if (!json_is_string(cursor)) return std::nullopt;
            std::string cursorTraceId;
            std::uint64_t fingerprint = 0U;
            const std::string_view text(json_string_value(cursor), json_string_length(cursor));
            if (!ParseTraceCursor(text, cursorTraceId, fingerprint, cursorIndex) ||
                cursorTraceId != traceId) {
                traceCursorInvalid = true;
            } else {
                cursorSnapshotFingerprint = fingerprint;
            }
        }
    } else if (methodValue == "expression.evaluate") {
        json_t* value = json_object_get(payload, "expression");
        if (json_object_size(payload) != 1U || !json_is_string(value) ||
            json_string_length(value) == 0U || json_string_length(value) > 1024U) {
            return std::nullopt;
        }
        const std::string_view expressionValue(json_string_value(value),
                                               json_string_length(value));
        if (std::any_of(expressionValue.begin(), expressionValue.end(), [](const char character) {
                const auto byte = static_cast<unsigned char>(character);
                return byte < 0x20U || byte == 0x7fU;
            })) {
            return std::nullopt;
        }
        expression.assign(expressionValue);
    } else if (methodValue == "expressions.evaluate_batch") {
        json_t* values = json_object_get(payload, "expressions");
        if (json_object_size(payload) != 1U || !json_is_array(values) ||
            json_array_size(values) < 1U || json_array_size(values) > 32U) {
            return std::nullopt;
        }
        std::size_t totalBytes = 0U;
        for (std::size_t index = 0U; index < json_array_size(values); ++index) {
            json_t* value = json_array_get(values, index);
            if (!json_is_string(value) || json_string_length(value) == 0U ||
                json_string_length(value) > 1024U) return std::nullopt;
            const std::string_view text(json_string_value(value), json_string_length(value));
            if (std::any_of(text.begin(), text.end(), [](const char character) {
                    const auto byte = static_cast<unsigned char>(character);
                    return byte < 0x20U || byte == 0x7fU;
                }) || text.size() > 8192U - totalBytes) {
                return std::nullopt;
            }
            totalBytes += text.size();
            expressions.emplace_back(text);
        }
    } else if (methodValue == "process.peb") {
        if (json_object_size(payload) != 0U) return std::nullopt;
    } else if (methodValue == "context.arguments") {
        json_t* count = json_object_get(payload, "count");
        json_t* convention = json_object_get(payload, "calling_convention");
        json_t* thread = json_object_get(payload, "thread_id");
        const std::size_t expectedFields = (count ? 1U : 0U) +
                                           (convention ? 1U : 0U) +
                                           (thread ? 1U : 0U);
        if (json_object_size(payload) != expectedFields) return std::nullopt;
        if (count != nullptr) {
            if (!json_is_integer(count) || json_integer_value(count) < 1 ||
                json_integer_value(count) > 16) return std::nullopt;
            argumentCount = static_cast<std::size_t>(json_integer_value(count));
        }
        if (convention != nullptr) {
            if (!json_is_string(convention)) return std::nullopt;
            callingConvention.assign(json_string_value(convention),
                                     json_string_length(convention));
            if (callingConvention != "auto" && callingConvention != "windows_x64" &&
                callingConvention != "cdecl" && callingConvention != "stdcall" &&
                callingConvention != "fastcall" && callingConvention != "thiscall") {
                return std::nullopt;
            }
        }
        if (thread != nullptr) {
            std::uint64_t parsedThread = 0U;
            if (!ParseCanonicalHex64(thread, parsedThread) || parsedThread == 0U ||
                parsedThread > 0xffffffffULL) return std::nullopt;
            targetThreadId = static_cast<std::uint32_t>(parsedThread);
        }
    } else if (methodValue == "address.resolve") {
        if (json_object_size(payload) != 1U ||
            !ParseAddressReference(json_object_get(payload, "address"), addressValue)) {
            return std::nullopt;
        }
        addressProvided = true;
    } else if (methodValue == "functions.at") {
        if (json_object_size(payload) != 1U ||
            !ParseAddressReference(json_object_get(payload, "address"), addressValue)) {
            return std::nullopt;
        }
        addressProvided = true;
    } else if (methodValue == "symbols.resolve") {
        json_t* address = json_object_get(payload, "address");
        json_t* module = json_object_get(payload, "module");
        json_t* name = json_object_get(payload, "name");
        if (address != nullptr) {
            if (json_object_size(payload) != 1U || module != nullptr || name != nullptr ||
                !ParseAddressReference(address, addressValue)) return std::nullopt;
            addressProvided = true;
        } else {
            if (json_object_size(payload) != 2U || !IsBoundedModuleName(module) ||
                !json_is_string(name) || json_string_length(name) == 0U ||
                json_string_length(name) > 256U) return std::nullopt;
            const std::string_view nameValue(json_string_value(name), json_string_length(name));
            if (std::any_of(nameValue.begin(), nameValue.end(), [](const char character) {
                    const auto byte = static_cast<unsigned char>(character);
                    return byte < 0x20U || byte == 0x7fU;
                })) return std::nullopt;
            moduleFilter.assign(json_string_value(module), json_string_length(module));
            symbolName.assign(nameValue);
        }
    } else if (methodValue == "analysis.function") {
        if (json_object_size(payload) != 2U ||
            !json_is_string(json_object_get(payload, "operation_id")) ||
            !ParseAddressReference(json_object_get(payload, "address"), addressValue)) {
            return std::nullopt;
        }
    } else if (methodValue == "memory.read") {
        json_t* address = json_object_get(payload, "address");
        json_t* length = json_object_get(payload, "length");
        if (json_object_size(payload) != 2U ||
            !ParseAddressReference(address, addressValue) ||
            !json_is_integer(length) || json_integer_value(length) < 1 ||
            json_integer_value(length) > 65536) {
            return std::nullopt;
        }
        lengthValue = static_cast<std::size_t>(json_integer_value(length));
    } else if (methodValue == "registers.read") {
        json_t* names = json_object_get(payload, "names");
        json_t* thread = json_object_get(payload, "thread_id");
        const std::size_t expectedFields = (names ? 1U : 0U) + (thread ? 1U : 0U);
        if (json_object_size(payload) != expectedFields) return std::nullopt;
        if (names != nullptr) {
            if (!json_is_array(names) || json_array_size(names) > 64U) {
                return std::nullopt;
            }
            for (std::size_t index = 0; index < json_array_size(names); ++index) {
                json_t* name = json_array_get(names, index);
                if (!json_is_string(name) || json_string_length(name) == 0U ||
                    json_string_length(name) > 32U) {
                    return std::nullopt;
                }
                std::string value(json_string_value(name), json_string_length(name));
                if (std::find(registerNames.begin(), registerNames.end(), value) !=
                    registerNames.end()) {
                    return std::nullopt;
                }
                registerNames.push_back(std::move(value));
            }
        }
        if (thread != nullptr) {
            std::uint64_t parsedThread = 0U;
            if (!ParseCanonicalHex64(thread, parsedThread) || parsedThread == 0U ||
                parsedThread > 0xffffffffULL) return std::nullopt;
            targetThreadId = static_cast<std::uint32_t>(parsedThread);
        }
    } else if (methodValue == "registers.write") {
        json_t* name = json_object_get(payload, "name");
        json_t* thread = json_object_get(payload, "thread_id");
        const std::size_t expectedFields = thread == nullptr ? 3U : 4U;
        if (json_object_size(payload) != expectedFields ||
            !json_is_string(json_object_get(payload, "operation_id")) ||
            !json_is_string(name) || json_string_length(name) < 2U ||
            json_string_length(name) > 6U ||
            !ParseCanonicalHex64(json_object_get(payload, "value"), registerWriteValue)) {
            return std::nullopt;
        }
        registerName.assign(json_string_value(name), json_string_length(name));
        if (thread != nullptr) {
            std::uint64_t parsedThread = 0U;
            if (!ParseCanonicalHex64(thread, parsedThread) || parsedThread == 0U ||
                parsedThread > 0xffffffffULL) return std::nullopt;
            targetThreadId = static_cast<std::uint32_t>(parsedThread);
        }
    } else if (methodValue == "memory.map") {
        json_t* module = json_object_get(payload, "module");
        json_t* committed = json_object_get(payload, "committed_only");
        json_t* executable = json_object_get(payload, "executable_only");
        json_t* compactValue = json_object_get(payload, "compact");
        json_t* limit = json_object_get(payload, "limit");
        json_t* cursor = json_object_get(payload, "cursor");
        const std::size_t expectedFields = (module ? 1U : 0U) + (committed ? 1U : 0U) +
                                           (executable ? 1U : 0U) +
                                           (compactValue ? 1U : 0U) + (limit ? 1U : 0U) +
                                           (cursor ? 1U : 0U);
        if (json_object_size(payload) != expectedFields ||
            (module != nullptr && !IsBoundedModuleName(module)) ||
            (committed != nullptr && !json_is_boolean(committed)) ||
            (executable != nullptr && !json_is_boolean(executable)) ||
            (compactValue != nullptr && !json_is_boolean(compactValue))) return std::nullopt;
        if (module != nullptr) {
            moduleFilter.assign(json_string_value(module), json_string_length(module));
        }
        committedOnly = json_is_true(committed);
        executableOnly = json_is_true(executable);
        compact = json_is_true(compactValue);
        if (limit != nullptr) {
            if (!json_is_integer(limit) || json_integer_value(limit) < 1 ||
                json_integer_value(limit) > 256) return std::nullopt;
            pageLimit = static_cast<std::size_t>(json_integer_value(limit));
        }
        const std::uint64_t expectedFingerprint = DiscoveryFingerprint(
            methodValue, moduleFilter, committedOnly ? "1" : "0",
            executableOnly ? "1" : "0", compact ? 1U : 0U);
        cursorFingerprint = expectedFingerprint;
        if (cursor != nullptr) {
            if (!json_is_string(cursor)) return std::nullopt;
            std::uint64_t cursorGenerationValue = 0U;
            std::uint64_t fingerprintValue = 0U;
            const std::string_view cursorText(json_string_value(cursor), json_string_length(cursor));
            if (!ParseDiscoveryCursor(cursorText, cursorGenerationValue, fingerprintValue,
                                      cursorIndex)) {
                discoveryCursorInvalid = true;
            } else {
                cursorGeneration = cursorGenerationValue;
                discoveryCursorInvalid = fingerprintValue != expectedFingerprint;
            }
        }
    } else if (methodValue == "memory.search") {
        json_t* scope = json_object_get(payload, "scope");
        json_t* patternValue = json_object_get(payload, "pattern_hex");
        json_t* maskValue = json_object_get(payload, "mask");
        json_t* limit = json_object_get(payload, "limit");
        json_t* cursor = json_object_get(payload, "cursor");
        const std::size_t expectedFields = 3U + (limit ? 1U : 0U) + (cursor ? 1U : 0U);
        if (json_object_size(payload) != expectedFields || !json_is_object(scope) ||
            !json_is_string(patternValue) || !json_is_string(maskValue)) {
            return std::nullopt;
        }
        json_t* module = json_object_get(scope, "module");
        json_t* start = json_object_get(scope, "start");
        json_t* length = json_object_get(scope, "length");
        if (module != nullptr) {
            if (json_object_size(scope) != 1U || !IsBoundedModuleName(module)) {
                return std::nullopt;
            }
            memorySearchModuleScope = true;
            moduleFilter.assign(json_string_value(module), json_string_length(module));
        } else {
            if (json_object_size(scope) != 2U || !ParseAddressReference(start, addressValue) ||
                !json_is_integer(length) || json_integer_value(length) < 1 ||
                json_integer_value(length) > 16 * 1024 * 1024) {
                return std::nullopt;
            }
            lengthValue = static_cast<std::size_t>(json_integer_value(length));
        }
        const std::string_view patternText(json_string_value(patternValue),
                                           json_string_length(patternValue));
        const std::string_view maskText(json_string_value(maskValue),
                                        json_string_length(maskValue));
        const auto parsedPattern = ParseMemoryPattern(patternText, maskText);
        if (!parsedPattern) return std::nullopt;
        memoryPattern = *parsedPattern;
        if (limit != nullptr) {
            if (!json_is_integer(limit) || json_integer_value(limit) < 1 ||
                json_integer_value(limit) > 256) {
                return std::nullopt;
            }
            pageLimit = static_cast<std::size_t>(json_integer_value(limit));
        }
        std::string scopeKey;
        if (memorySearchModuleScope) {
            scopeKey = "module:" + moduleFilter;
        } else if (addressValue.kind == AddressReferenceKind::absolute) {
            scopeKey = "absolute:" + std::to_string(static_cast<std::uint64_t>(
                                         addressValue.absolute)) +
                       ':' + std::to_string(lengthValue);
        } else {
            scopeKey = "module_rva:" + addressValue.module + ':' +
                       std::to_string(static_cast<std::uint64_t>(addressValue.rva)) + ':' +
                       std::to_string(lengthValue);
        }
        const std::uint64_t expectedFingerprint = DiscoveryFingerprint(
            methodValue, scopeKey, patternText, maskText, pageLimit);
        cursorFingerprint = expectedFingerprint;
        if (cursor != nullptr) {
            if (!json_is_string(cursor)) return std::nullopt;
            std::uint64_t cursorGenerationValue = 0U;
            std::uint64_t fingerprintValue = 0U;
            const std::string_view cursorText(json_string_value(cursor),
                                              json_string_length(cursor));
            if (!ParseDiscoveryCursor(cursorText, cursorGenerationValue, fingerprintValue,
                                      cursorIndex)) {
                discoveryCursorInvalid = true;
            } else {
                cursorGeneration = cursorGenerationValue;
                discoveryCursorInvalid = fingerprintValue != expectedFingerprint;
            }
        }
    } else if (methodValue == "callstack.read") {
        json_t* thread = json_object_get(payload, "thread_id");
        json_t* limit = json_object_get(payload, "limit");
        const std::size_t expectedFields = (thread ? 1U : 0U) + (limit ? 1U : 0U);
        if (json_object_size(payload) != expectedFields) return std::nullopt;
        pageLimit = 32U;
        if (thread != nullptr) {
            std::uint64_t parsedThread = 0U;
            if (!ParseCanonicalHex64(thread, parsedThread) || parsedThread == 0U ||
                parsedThread > 0xffffffffULL) {
                return std::nullopt;
            }
            targetThreadId = static_cast<std::uint32_t>(parsedThread);
        }
        if (limit != nullptr) {
            if (!json_is_integer(limit) || json_integer_value(limit) < 1 ||
                json_integer_value(limit) > 50) return std::nullopt;
            pageLimit = static_cast<std::size_t>(json_integer_value(limit));
        }
    } else if (methodValue == "patches.list") {
        json_t* module = json_object_get(payload, "module");
        json_t* limit = json_object_get(payload, "limit");
        json_t* cursor = json_object_get(payload, "cursor");
        const std::size_t expectedFields = (module ? 1U : 0U) + (limit ? 1U : 0U) +
                                           (cursor ? 1U : 0U);
        if (json_object_size(payload) != expectedFields ||
            (module != nullptr && !IsBoundedModuleName(module))) return std::nullopt;
        if (module != nullptr) {
            moduleFilter.assign(json_string_value(module), json_string_length(module));
        }
        if (limit != nullptr) {
            if (!json_is_integer(limit) || json_integer_value(limit) < 1 ||
                json_integer_value(limit) > 256) return std::nullopt;
            pageLimit = static_cast<std::size_t>(json_integer_value(limit));
        }
        const std::uint64_t expectedFingerprint =
            DiscoveryFingerprint(methodValue, moduleFilter, "", "", 0U);
        cursorFingerprint = expectedFingerprint;
        if (cursor != nullptr) {
            if (!json_is_string(cursor) || json_string_length(cursor) == 0U ||
                json_string_length(cursor) > 512U) return std::nullopt;
            std::uint64_t cursorGenerationValue = 0U;
            std::uint64_t filterFingerprint = 0U;
            std::uint64_t snapshotFingerprint = 0U;
            const std::string_view cursorText(json_string_value(cursor),
                                              json_string_length(cursor));
            if (!ParsePatchCursor(cursorText, cursorGenerationValue, filterFingerprint,
                                  snapshotFingerprint, cursorIndex)) {
                discoveryCursorInvalid = true;
            } else {
                cursorGeneration = cursorGenerationValue;
                cursorSnapshotFingerprint = snapshotFingerprint;
                discoveryCursorInvalid = filterFingerprint != expectedFingerprint;
            }
        }
    } else if (IsDiscoveryMethod(methodValue)) {
        json_t* module = json_object_get(payload, "module");
        json_t* queryValue = json_object_get(payload, "query");
        json_t* encoding = json_object_get(payload, "encoding");
        json_t* minimum = json_object_get(payload, "min_length");
        json_t* context = json_object_get(payload, "context_bytes");
        json_t* limit = json_object_get(payload, "limit");
        json_t* cursor = json_object_get(payload, "cursor");
        json_t* address = json_object_get(payload, "address");
        const bool references = methodValue == "references.to";
        const std::size_t expectedFields = 1U + (queryValue ? 1U : 0U) +
                                           (encoding ? 1U : 0U) + (minimum ? 1U : 0U) +
                                           (context ? 1U : 0U) +
                                           (limit ? 1U : 0U) + (cursor ? 1U : 0U);
        if (json_object_size(payload) != expectedFields ||
            (references ? !ParseAddressReference(address, addressValue)
                        : !IsBoundedModuleName(module)) ||
            (references && module != nullptr) || (!references && address != nullptr) ||
            (references && queryValue != nullptr) ||
            (methodValue != "strings.search" &&
             (encoding != nullptr || minimum != nullptr || context != nullptr)) ||
            (context != nullptr && queryValue == nullptr)) {
            return std::nullopt;
        }
        if (!references) {
            moduleFilter.assign(json_string_value(module), json_string_length(module));
        }
        if (queryValue != nullptr) {
            const std::size_t maxQueryBytes =
                (methodValue == "imports.list" || methodValue == "exports.list" ||
                 methodValue == "sections.list") ? 128U : 256U;
            if (!json_is_string(queryValue) || json_string_length(queryValue) == 0U ||
                json_string_length(queryValue) > maxQueryBytes) return std::nullopt;
            const std::string_view text(json_string_value(queryValue),
                                        json_string_length(queryValue));
            if (std::any_of(text.begin(), text.end(), [](const char character) {
                    const auto byte = static_cast<unsigned char>(character);
                    return byte < 0x20U || byte == 0x7fU;
                })) return std::nullopt;
            query.assign(text);
        }
        if (encoding != nullptr) {
            if (!json_is_string(encoding)) return std::nullopt;
            const std::string_view value(json_string_value(encoding), json_string_length(encoding));
            if (value != "ascii_utf8" && value != "utf16le" && value != "both") {
                return std::nullopt;
            }
            stringEncoding.assign(value);
        }
        if (minimum != nullptr) {
            if (!json_is_integer(minimum) || json_integer_value(minimum) < 4 ||
                json_integer_value(minimum) > 256) return std::nullopt;
            minStringLength = static_cast<std::size_t>(json_integer_value(minimum));
        }
        if (context != nullptr) {
            if (!json_is_integer(context) || json_integer_value(context) < 0 ||
                json_integer_value(context) > 128) return std::nullopt;
            stringContextBytes = static_cast<std::size_t>(json_integer_value(context));
        }
        if (limit != nullptr) {
            if (!json_is_integer(limit) || json_integer_value(limit) < 1 ||
                json_integer_value(limit) > 256) return std::nullopt;
            pageLimit = static_cast<std::size_t>(json_integer_value(limit));
        }
        const std::uint64_t expectedFingerprint = DiscoveryFingerprint(
            methodValue, moduleFilter, query, stringEncoding, minStringLength,
            query.empty() ? 0U : stringContextBytes);
        if (cursor != nullptr) {
            if (!json_is_string(cursor)) return std::nullopt;
            std::uint64_t cursorGenerationValue = 0;
            std::uint64_t fingerprintValue = 0;
            const std::string_view cursorText(json_string_value(cursor), json_string_length(cursor));
            if (!ParseDiscoveryCursor(cursorText, cursorGenerationValue, fingerprintValue,
                                      cursorIndex)) {
                discoveryCursorInvalid = true;
            } else {
                cursorGeneration = cursorGenerationValue;
                discoveryCursorInvalid = fingerprintValue != expectedFingerprint;
            }
            cursorFingerprint = expectedFingerprint;
        } else {
            cursorFingerprint = expectedFingerprint;
        }
    } else if (IsPageMethod(methodValue)) {
        json_t* limit = json_object_get(payload, "limit");
        json_t* cursor = json_object_get(payload, "cursor");
        const std::size_t expectedFields = (limit == nullptr ? 0U : 1U) +
                                           (cursor == nullptr ? 0U : 1U);
        if (json_object_size(payload) != expectedFields) {
            return std::nullopt;
        }
        if (limit != nullptr) {
            if (!json_is_integer(limit) || json_integer_value(limit) < 1 ||
                json_integer_value(limit) > 256) {
                return std::nullopt;
            }
            pageLimit = static_cast<std::size_t>(json_integer_value(limit));
        }
        if (cursor != nullptr) {
            if (!json_is_string(cursor) || json_string_length(cursor) == 0U ||
                json_string_length(cursor) > 64U) {
                return std::nullopt;
            }
            std::uint64_t cursorGenerationValue = 0;
            const std::string_view cursorText(json_string_value(cursor), json_string_length(cursor));
            if (!ParseCursor(cursorText, cursorGenerationValue, cursorIndex)) {
                return std::nullopt;
            }
            cursorGeneration = cursorGenerationValue;
        }
    } else if (methodValue == "disassembly.read") {
        json_t* address = json_object_get(payload, "address");
        json_t* count = json_object_get(payload, "count");
        const std::size_t expectedFields = count == nullptr ? 1U : 2U;
        if (json_object_size(payload) != expectedFields ||
            !ParseAddressReference(address, addressValue)) {
            return std::nullopt;
        }
        if (count != nullptr) {
            if (!json_is_integer(count) || json_integer_value(count) < 1 ||
                json_integer_value(count) > 256) {
                return std::nullopt;
            }
            instructionCount = static_cast<std::size_t>(json_integer_value(count));
        }
    } else if (methodValue == "assembly.preview" || methodValue == "assembly.patch") {
        json_t* instructionValue = json_object_get(payload, "instruction");
        const bool patch = methodValue == "assembly.patch";
        const std::size_t expectedFields = patch ? 5U : 2U;
        if (json_object_size(payload) != expectedFields ||
            !ParseAddressReference(json_object_get(payload, "address"), addressValue) ||
            !json_is_string(instructionValue)) return std::nullopt;
        instruction.assign(json_string_value(instructionValue),
                           json_string_length(instructionValue));
        if (!SafeInstruction(instruction)) return std::nullopt;
        if (patch) {
            json_t* expected = json_object_get(payload, "expected_bytes_hex");
            json_t* fill = json_object_get(payload, "fill_nop");
            if (!json_is_string(json_object_get(payload, "operation_id")) ||
                !json_is_string(expected) || !json_is_boolean(fill)) return std::nullopt;
            const auto parsedBytes = ParsePatchBytes(std::string_view(
                json_string_value(expected), json_string_length(expected)));
            if (!parsedBytes) return std::nullopt;
            expectedBytes = *parsedBytes;
            fillNop = json_is_true(fill);
        }
    } else if (methodValue == "patches.restore") {
        json_t* patched = json_object_get(payload, "expected_patched_bytes_hex");
        json_t* original = json_object_get(payload, "expected_original_bytes_hex");
        if (json_object_size(payload) != 4U ||
            !json_is_string(json_object_get(payload, "operation_id")) ||
            !ParseAddressReference(json_object_get(payload, "address"), addressValue) ||
            !json_is_string(patched) || !json_is_string(original)) return std::nullopt;
        const auto parsedPatched = ParsePatchBytes(std::string_view(
            json_string_value(patched), json_string_length(patched)));
        const auto parsedOriginal = ParsePatchBytes(std::string_view(
            json_string_value(original), json_string_length(original)));
        if (!parsedPatched || !parsedOriginal || parsedPatched->size() != parsedOriginal->size() ||
            *parsedPatched == *parsedOriginal) return std::nullopt;
        expectedBytes = *parsedPatched;
        expectedOriginalBytes = *parsedOriginal;
    } else if (methodValue == "debugger.run_to_address") {
        json_t* timeout = json_object_get(payload, "timeout_ms");
        const std::size_t expectedFields = timeout == nullptr ? 2U : 3U;
        if (json_object_size(payload) != expectedFields ||
            !json_is_string(json_object_get(payload, "operation_id")) ||
            !ParseAddressReference(json_object_get(payload, "address"), addressValue) ||
            (timeout != nullptr &&
             (!json_is_integer(timeout) || json_integer_value(timeout) < 100 ||
              json_integer_value(timeout) > 20000))) {
            return std::nullopt;
        }
        if (timeout != nullptr) {
            runToTimeoutMs = static_cast<std::size_t>(json_integer_value(timeout));
        }
    } else if (methodValue == "debugger.continue_exception") {
        json_t* disposition = json_object_get(payload, "disposition");
        json_t* overrides = json_object_get(payload, "register_overrides");
        const std::size_t expectedFields = overrides == nullptr ? 2U : 3U;
        if (json_object_size(payload) != expectedFields ||
            !json_is_string(json_object_get(payload, "operation_id")) ||
            !json_is_string(disposition) ||
            (overrides != nullptr && (!json_is_array(overrides) ||
                                      json_array_size(overrides) < 1U ||
                                      json_array_size(overrides) > 4U))) {
            return std::nullopt;
        }
        exceptionDisposition.assign(json_string_value(disposition),
                                    json_string_length(disposition));
        if (exceptionDisposition != "handled" && exceptionDisposition != "not_handled") {
            return std::nullopt;
        }
        if (overrides != nullptr) {
            const std::size_t count = json_array_size(overrides);
            for (std::size_t index = 0U; index < count; ++index) {
                json_t* overrideValue = json_array_get(overrides, index);
                json_t* name = json_is_object(overrideValue)
                                   ? json_object_get(overrideValue, "name")
                                   : nullptr;
                std::uint64_t value = 0U;
                if (!json_is_object(overrideValue) || json_object_size(overrideValue) != 2U ||
                    !json_is_string(name) || json_string_length(name) < 2U ||
                    json_string_length(name) > 6U ||
                    !ParseCanonicalHex64(json_object_get(overrideValue, "value"), value)) {
                    return std::nullopt;
                }
                std::string parsedName(json_string_value(name), json_string_length(name));
                if (std::find_if(exceptionRegisterOverrides.begin(),
                                 exceptionRegisterOverrides.end(),
                                 [&parsedName](const RegisterAssignment& item) {
                                     return item.name == parsedName;
                                 }) != exceptionRegisterOverrides.end()) {
                    return std::nullopt;
                }
                exceptionRegisterOverrides.push_back(
                    RegisterAssignment{std::move(parsedName), value});
            }
        }
    } else if (methodValue == "debugger.pause" || methodValue == "debugger.resume" ||
               methodValue == "debugger.step_into" || methodValue == "debugger.step_over" ||
               methodValue == "debugger.step_out" || methodValue == "debugger.stop") {
        json_t* thread = json_object_get(payload, "thread_id");
        const bool supportsThread = methodValue == "debugger.step_into" ||
                                    methodValue == "debugger.step_over";
        const std::size_t expectedFields = supportsThread && thread != nullptr ? 2U : 1U;
        if (json_object_size(payload) != expectedFields ||
            !json_is_string(json_object_get(payload, "operation_id"))) {
            return std::nullopt;
        }
        if (thread != nullptr) {
            std::uint64_t parsedThread = 0U;
            if (!supportsThread || !ParseCanonicalHex64(thread, parsedThread) ||
                parsedThread == 0U || parsedThread > 0xffffffffULL) return std::nullopt;
            targetThreadId = static_cast<std::uint32_t>(parsedThread);
        }
    } else if (methodValue == "breakpoints.enable" ||
               methodValue == "breakpoints.disable") {
        json_t* selector = json_object_get(payload, "selector");
        json_t* kind = json_is_object(selector) ? json_object_get(selector, "kind") : nullptr;
        if (json_object_size(payload) != 2U ||
            !json_is_string(json_object_get(payload, "operation_id")) ||
            !json_is_object(selector) || !json_is_string(kind)) {
            return std::nullopt;
        }
        breakpointKind.assign(json_string_value(kind), json_string_length(kind));
        if (breakpointKind == "software") {
            if (json_object_size(selector) != 2U ||
                !ParseAddressReference(json_object_get(selector, "address"), addressValue)) {
                return std::nullopt;
            }
        } else if (breakpointKind == "hardware" || breakpointKind == "memory") {
            json_t* access = json_object_get(selector, "access");
            json_t* size = json_object_get(selector, "size");
            if (json_object_size(selector) != 4U ||
                !ParseAddressReference(json_object_get(selector, "address"), addressValue) ||
                !json_is_string(access) || json_string_length(access) < 4U ||
                json_string_length(access) > 10U || !json_is_integer(size) ||
                json_integer_value(size) < 1 || json_integer_value(size) > 65536) {
                return std::nullopt;
            }
            breakpointAccess.assign(json_string_value(access), json_string_length(access));
            breakpointSize = static_cast<std::size_t>(json_integer_value(size));
            if ((breakpointKind == "hardware" &&
                 (!ParseHardwareAccess(breakpointAccess) || breakpointSize > 8U)) ||
                (breakpointKind == "memory" && !ParseMemoryAccess(breakpointAccess))) {
                return std::nullopt;
            }
        } else if (breakpointKind == "conditional") {
            json_t* managed = json_object_get(selector, "managed_id");
            if (json_object_size(selector) != 3U ||
                !ParseAddressReference(json_object_get(selector, "address"), addressValue) ||
                !json_is_string(managed)) {
                return std::nullopt;
            }
            managedBreakpointId.assign(json_string_value(managed), json_string_length(managed));
            if (ManagedBreakpointName("conditional", managedBreakpointId).empty()) {
                return std::nullopt;
            }
        } else if (breakpointKind == "exception") {
            json_t* code = json_object_get(selector, "code");
            json_t* chance = json_object_get(selector, "chance");
            json_t* managed = json_object_get(selector, "managed_id");
            std::uint64_t parsedCode = 0U;
            if (json_object_size(selector) != 4U ||
                !ParseCanonicalHex64(code, parsedCode) || parsedCode > 0xffffffffULL ||
                !json_is_string(chance) || !json_is_string(managed)) {
                return std::nullopt;
            }
            exceptionCode = static_cast<std::uint32_t>(parsedCode);
            exceptionChance.assign(json_string_value(chance), json_string_length(chance));
            managedBreakpointId.assign(json_string_value(managed), json_string_length(managed));
            if (!ParseExceptionChance(exceptionChance) ||
                ManagedBreakpointName("exception", managedBreakpointId).empty()) {
                return std::nullopt;
            }
        } else {
            return std::nullopt;
        }
    } else if (methodValue == "breakpoints.hardware.set" ||
               methodValue == "breakpoints.hardware.remove" ||
               methodValue == "breakpoints.memory.set" ||
               methodValue == "breakpoints.memory.remove") {
        json_t* access = json_object_get(payload, "access");
        json_t* size = json_object_get(payload, "size");
        if (json_object_size(payload) != 4U ||
            !json_is_string(json_object_get(payload, "operation_id")) ||
            !ParseAddressReference(json_object_get(payload, "address"), addressValue) ||
            !json_is_string(access) || json_string_length(access) < 4U ||
            json_string_length(access) > 10U || !json_is_integer(size) ||
            json_integer_value(size) < 1 || json_integer_value(size) > 65536) {
            return std::nullopt;
        }
        breakpointAccess.assign(json_string_value(access), json_string_length(access));
        breakpointSize = static_cast<std::size_t>(json_integer_value(size));
    } else if (methodValue == "breakpoints.set" || methodValue == "breakpoints.remove") {
        if (json_object_size(payload) != 2U ||
            !json_is_string(json_object_get(payload, "operation_id")) ||
            !ParseAddressReference(json_object_get(payload, "address"), addressValue)) {
            return std::nullopt;
        }
    } else if (methodValue == "breakpoints.exception.set" ||
               methodValue == "breakpoints.exception.remove") {
        const bool removing = methodValue == "breakpoints.exception.remove";
        json_t* code = json_object_get(payload, "code");
        json_t* chance = json_object_get(payload, "chance");
        json_t* managed = json_object_get(payload, "managed_id");
        std::uint64_t parsedCode = 0U;
        if (json_object_size(payload) != (removing ? 4U : 3U) ||
            !json_is_string(json_object_get(payload, "operation_id")) ||
            !ParseCanonicalHex64(code, parsedCode) || parsedCode > 0xffffffffULL ||
            !json_is_string(chance) || (removing && !json_is_string(managed)) ||
            (!removing && managed != nullptr)) {
            return std::nullopt;
        }
        exceptionCode = static_cast<std::uint32_t>(parsedCode);
        exceptionChance.assign(json_string_value(chance), json_string_length(chance));
        if (!ParseExceptionChance(exceptionChance)) return std::nullopt;
        if (removing) {
            managedBreakpointId.assign(json_string_value(managed), json_string_length(managed));
            if (ManagedBreakpointName("exception", managedBreakpointId).empty()) {
                return std::nullopt;
            }
        } else {
            managedBreakpointId.assign(operationIdValue);
        }
    } else if (methodValue == "breakpoints.conditional.set" ||
               methodValue == "breakpoints.conditional.remove") {
        const bool removing = methodValue == "breakpoints.conditional.remove";
        json_t* managed = json_object_get(payload, "managed_id");
        if (json_object_size(payload) != 3U ||
            !json_is_string(json_object_get(payload, "operation_id")) ||
            !ParseAddressReference(json_object_get(payload, "address"), addressValue) ||
            (removing && !json_is_string(managed)) || (!removing && managed != nullptr)) {
            return std::nullopt;
        }
        if (removing) {
            managedBreakpointId.assign(json_string_value(managed), json_string_length(managed));
            if (ManagedBreakpointName("conditional", managedBreakpointId).empty()) {
                return std::nullopt;
            }
        } else {
            json_t* condition = json_object_get(payload, "condition");
            json_t* mode = json_is_object(condition) ? json_object_get(condition, "mode") : nullptr;
            json_t* predicates =
                json_is_object(condition) ? json_object_get(condition, "predicates") : nullptr;
            if (!json_is_object(condition) || json_object_size(condition) != 2U ||
                !json_is_string(mode) || !json_is_array(predicates) ||
                json_array_size(predicates) < 1U || json_array_size(predicates) > 4U) {
                return std::nullopt;
            }
            const std::string_view modeText(json_string_value(mode), json_string_length(mode));
            if (modeText == "all") {
                conditionalSpec.mode = ConditionalMode::all;
            } else if (modeText == "any") {
                conditionalSpec.mode = ConditionalMode::any;
            } else {
                return std::nullopt;
            }
            std::size_t index = 0U;
            json_t* predicateValue = nullptr;
            json_array_foreach(predicates, index, predicateValue) {
                if (!json_is_object(predicateValue)) return std::nullopt;
                json_t* sourceValue = json_object_get(predicateValue, "source");
                json_t* operatorValue = json_object_get(predicateValue, "operator");
                json_t* value = json_object_get(predicateValue, "value");
                if (!json_is_string(sourceValue) || !json_is_string(operatorValue)) {
                    return std::nullopt;
                }
                const std::string_view source(json_string_value(sourceValue),
                                              json_string_length(sourceValue));
                const std::string_view operation(json_string_value(operatorValue),
                                                 json_string_length(operatorValue));
                const auto parsedOperation = ParseConditionalOperator(operation);
                if (!parsedOperation) return std::nullopt;
                ConditionalPredicate predicate;
                predicate.operation = *parsedOperation;
                if (source == "register") {
                    json_t* registerValue = json_object_get(predicateValue, "register");
                    std::uint64_t parsedValue = 0U;
                    if (json_object_size(predicateValue) != 4U ||
                        !json_is_string(registerValue) ||
                        !ParseCanonicalHex64(value, parsedValue)) {
                        return std::nullopt;
                    }
                    predicate.source = ConditionalSource::registerValue;
                    predicate.registerName.assign(json_string_value(registerValue),
                                                  json_string_length(registerValue));
                    predicate.value = parsedValue;
                } else if (source == "thread_id") {
                    std::uint64_t parsedValue = 0U;
                    if (json_object_size(predicateValue) != 3U ||
                        !ParseCanonicalHex64(value, parsedValue)) {
                        return std::nullopt;
                    }
                    predicate.source = ConditionalSource::threadId;
                    predicate.value = parsedValue;
                } else if (source == "hit_count") {
                    if (json_object_size(predicateValue) != 3U || !json_is_integer(value) ||
                        json_integer_value(value) < 1 ||
                        static_cast<std::uint64_t>(json_integer_value(value)) > 0xffffffffULL) {
                        return std::nullopt;
                    }
                    predicate.source = ConditionalSource::hitCount;
                    predicate.value =
                        static_cast<std::uint64_t>(json_integer_value(value));
                } else {
                    return std::nullopt;
                }
                conditionalSpec.predicates.push_back(std::move(predicate));
            }
            const auto compiled = CompileConditionalExpression(conditionalSpec);
            if (compiled) {
                conditionalExpression = *compiled;
            } else {
                // Keep architecture-specific policy failures inside the normal
                // request path so x32 returns a structured error instead of
                // treating a schema-valid 64-bit register value as malformed IPC.
                conditionalInvalid = true;
            }
            managedBreakpointId.assign(operationIdValue);
        }
    } else if (methodValue == "memory.write") {
        json_t* data = json_object_get(payload, "data_hex");
        if (json_object_size(payload) != 3U ||
            !json_is_string(json_object_get(payload, "operation_id")) ||
            !ParseAddressReference(json_object_get(payload, "address"), addressValue) ||
            !json_is_string(data) || json_string_length(data) < 2U ||
            json_string_length(data) > 8192U || json_string_length(data) % 2U != 0U) {
            return std::nullopt;
        }
        const std::string_view encoded(json_string_value(data), json_string_length(data));
        writeBytes.reserve(encoded.size() / 2U);
        for (std::size_t index = 0; index < encoded.size(); index += 2U) {
            unsigned int byte = 0;
            const auto conversion =
                std::from_chars(encoded.data() + index, encoded.data() + index + 2U, byte, 16);
            if (conversion.ec != std::errc{} || conversion.ptr != encoded.data() + index + 2U ||
                byte > 0xffU) {
                return std::nullopt;
            }
            writeBytes.push_back(static_cast<unsigned char>(byte));
        }
    }
    if (mutation) {
        json_t* payloadOperationId = json_object_get(payload, "operation_id");
        if (!json_is_string(payloadOperationId) ||
            std::string_view(json_string_value(payloadOperationId),
                             json_string_length(payloadOperationId)) != operationIdValue) {
            return std::nullopt;
        }
    }
    return Request{std::string(requestIdValue), std::string(methodValue),
                   static_cast<std::uint64_t>(json_integer_value(deadline)), mutation,
                   std::move(expression), std::move(path), std::move(workingDirectory),
                   std::move(launchArguments), targetProcessId, addressValue, lengthValue,
                   std::move(registerNames), pageLimit,
                   cursorGeneration, cursorIndex, instructionCount,
                   std::move(writeBytes), afterGeneration, waitTimeoutMs,
                   std::move(moduleFilter), std::move(query), std::move(stringEncoding),
                   minStringLength, stringContextBytes, cursorFingerprint, discoveryCursorInvalid,
                   committedOnly, executableOnly, compact, std::move(registerName),
                   registerWriteValue, std::move(breakpointKind),
                   std::move(breakpointAccess), breakpointSize,
                   std::move(instruction), std::move(expectedBytes),
                   std::move(expectedOriginalBytes), fillNop, addressProvided,
                   targetThreadId, std::move(symbolName), cursorSnapshotFingerprint,
                   afterEventSequence, std::move(eventTypes), std::move(operationIdValue),
                   runToTimeoutMs, memorySearchModuleScope, std::move(memoryPattern),
                   exceptionCode, std::move(exceptionChance),
                   std::move(managedBreakpointId), std::move(conditionalSpec),
                   std::move(conditionalExpression), conditionalInvalid,
                   std::move(traceId), std::move(traceMode), traceMaxSteps,
                   traceTimeoutMs, traceCursorInvalid, std::move(expressions),
                   std::move(callingConvention), argumentCount,
                   std::move(scyllaAction), std::move(scyllaProfile),
                   std::move(expectedConfigGeneration), std::move(exceptionDisposition),
                   std::move(exceptionRegisterOverrides)};
}

bool IsCanonicalUuid(const std::string_view value) {
    if (value.size() != 36U) return false;
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index == 8U || index == 13U || index == 18U || index == 23U) {
            if (value[index] != '-') return false;
        } else if (!((value[index] >= '0' && value[index] <= '9') ||
                     (value[index] >= 'a' && value[index] <= 'f'))) {
            return false;
        }
    }
    return true;
}

std::optional<std::string> AcceptedHandshakeInstanceId(const std::string_view bytes) {
    json_error_t error{};
    JsonOwner root(json_loadb(bytes.data(), bytes.size(), JSON_REJECT_DUPLICATES, &error));
    if (!root || !json_is_object(root.get()) || json_object_size(root.get()) != 5U) {
        return std::nullopt;
    }
    json_t* major = json_object_get(root.get(), "protocol_major");
    json_t* minor = json_object_get(root.get(), "protocol_minor");
    json_t* accepted = json_object_get(root.get(), "accepted");
    json_t* errorCode = json_object_get(root.get(), "error_code");
    json_t* instanceId = json_object_get(root.get(), "instance_id");
    if (!json_is_integer(major) || json_integer_value(major) != 1 ||
        !json_is_integer(minor) || json_integer_value(minor) != 1 ||
        !json_is_true(accepted) || !json_is_null(errorCode) || !json_is_string(instanceId)) {
        return std::nullopt;
    }
    const std::string value(json_string_value(instanceId), json_string_length(instanceId));
    return IsCanonicalUuid(value) ? std::optional<std::string>(value) : std::nullopt;
}

std::string HexValue(const std::uint64_t value) {
    std::ostringstream formatted;
    formatted << "0x" << std::hex << std::nouppercase << value;
    return formatted.str();
}

std::optional<std::string> RandomUuid() {
    std::array<unsigned char, 16> bytes{};
    if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return std::nullopt;
    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0fU) | 0x40U);
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3fU) | 0x80U);
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(36U);
    for (std::size_t index = 0U; index < bytes.size(); ++index) {
        if (index == 4U || index == 6U || index == 8U || index == 10U) result.push_back('-');
        result.push_back(digits[bytes[index] >> 4U]);
        result.push_back(digits[bytes[index] & 0x0fU]);
    }
    return result;
}

std::uint64_t TraceFingerprint(const TracePolicy& trace) noexcept {
    std::uint64_t hash = 14695981039346656037ULL;
    const auto addByte = [&hash](const unsigned char byte) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    };
    for (const unsigned char byte : trace.Id()) addByte(byte);
    addByte(static_cast<unsigned char>(trace.Mode()));
    for (const TracePoint point : trace.Points()) {
        for (unsigned int shift = 0U; shift < 64U; shift += 8U) {
            addByte(static_cast<unsigned char>((point.address >> shift) & 0xffU));
        }
    }
    return hash;
}

std::string TraceCursor(const TracePolicy& trace, const std::uint64_t fingerprint,
                        const std::size_t index) {
    std::ostringstream cursor;
    cursor << "v4:" << trace.Id() << ':' << std::hex << std::nouppercase << fingerprint
           << ':' << std::dec << index;
    return cursor.str();
}

std::string TraceStatusJson(const TracePolicy& trace, const std::uint64_t generation) {
    return "{\"trace_id\":" + JsonString(trace.Id()) +
           ",\"mode\":" + JsonString(TraceModeName(trace.Mode())) +
           ",\"state\":" + JsonString(TraceStateName(trace.State())) +
           ",\"reason\":" +
           (trace.Active() ? std::string("null") : JsonString(TraceReasonName(trace.Reason()))) +
           ",\"max_steps\":" + std::to_string(trace.MaxSteps()) +
           ",\"steps_executed\":" + std::to_string(trace.StepsExecuted()) +
           ",\"points_retained\":" + std::to_string(trace.Points().size()) +
           ",\"state_generation\":" + std::to_string(generation) + "}";
}

const char* ConditionalOperatorName(const ConditionalOperator operation) noexcept {
    switch (operation) {
    case ConditionalOperator::equal: return "eq";
    case ConditionalOperator::notEqual: return "ne";
    case ConditionalOperator::less: return "lt";
    case ConditionalOperator::lessEqual: return "le";
    case ConditionalOperator::greater: return "gt";
    case ConditionalOperator::greaterEqual: return "ge";
    case ConditionalOperator::multipleOf: return "multiple_of";
    }
    return "unknown";
}

std::string ConditionalSpecJson(const ConditionalSpec& condition) {
    std::string predicates = "[";
    for (std::size_t index = 0U; index < condition.predicates.size(); ++index) {
        if (index != 0U) predicates.push_back(',');
        const ConditionalPredicate& predicate = condition.predicates[index];
        predicates += "{\"source\":";
        switch (predicate.source) {
        case ConditionalSource::registerValue:
            predicates += JsonString("register") + ",\"register\":" +
                          JsonString(predicate.registerName);
            break;
        case ConditionalSource::threadId: predicates += JsonString("thread_id"); break;
        case ConditionalSource::hitCount: predicates += JsonString("hit_count"); break;
        }
        predicates += ",\"operator\":" +
                      JsonString(ConditionalOperatorName(predicate.operation)) + ",\"value\":";
        if (predicate.source == ConditionalSource::hitCount) {
            predicates += std::to_string(predicate.value);
        } else {
            predicates += JsonString(HexValue(predicate.value));
        }
        predicates.push_back('}');
    }
    predicates.push_back(']');
    return "{\"mode\":" +
           JsonString(condition.mode == ConditionalMode::all ? "all" : "any") +
           ",\"predicates\":" + predicates + "}";
}

std::string PauseReasonJson(const PauseObservation& pause) {
    const char* kind = "unknown";
    switch (pause.kind) {
    case PauseReasonKind::processCreated: kind = "process_created"; break;
    case PauseReasonKind::systemBreakpoint: kind = "system_breakpoint"; break;
    case PauseReasonKind::breakpoint: kind = "breakpoint"; break;
    case PauseReasonKind::exception: kind = "exception"; break;
    case PauseReasonKind::step: kind = "step"; break;
    case PauseReasonKind::userPause: kind = "user_pause"; break;
    case PauseReasonKind::unknown: break;
    }
    std::string result = "{\"kind\":" + JsonString(kind);
    if (pause.hasAddress) {
        result += ",\"address\":" + JsonString(HexValue(pause.address));
    }
    if (pause.kind == PauseReasonKind::breakpoint) {
        const char* type = "unknown";
        switch (pause.breakpointType) {
        case 1U: type = "software"; break;
        case 2U: type = "hardware"; break;
        case 4U: type = "memory"; break;
        case 8U: type = "dll"; break;
        case 16U: type = "exception"; break;
        default: break;
        }
        result += ",\"breakpoint_type\":" + JsonString(type) +
                  ",\"hit_count\":" + std::to_string(pause.hitCount);
    }
    if (pause.kind == PauseReasonKind::exception && pause.hasExceptionCode) {
        result += ",\"code\":" + JsonString(HexValue(pause.exceptionCode)) +
                  ",\"first_chance\":" +
                  std::string(pause.firstChance ? "true" : "false");
    }
    return result + "}";
}

const char* EventKindName(const EventKind kind) noexcept {
    switch (kind) {
    case EventKind::debugInitialized: return "debug_initialized";
    case EventKind::processCreated: return "process_created";
    case EventKind::systemBreakpoint: return "system_breakpoint";
    case EventKind::breakpoint: return "breakpoint";
    case EventKind::exception: return "exception";
    case EventKind::paused: return "paused";
    case EventKind::stepped: return "stepped";
    case EventKind::resumed: return "resumed";
    case EventKind::attached: return "attached";
    case EventKind::detached: return "detached";
    case EventKind::stopping: return "stopping";
    case EventKind::processExited: return "process_exited";
    case EventKind::debugStopped: return "debug_stopped";
    case EventKind::threadCreated: return "thread_created";
    case EventKind::threadExited: return "thread_exited";
    case EventKind::dllLoaded: return "dll_loaded";
    case EventKind::dllUnloaded: return "dll_unloaded";
    case EventKind::debugString: return "debug_string";
    case EventKind::rip: return "rip";
    }
    return "unknown";
}

std::optional<EventKind> ParseEventKind(const std::string_view value) noexcept {
    constexpr EventKind values[] = {
        EventKind::debugInitialized, EventKind::processCreated,
        EventKind::systemBreakpoint, EventKind::breakpoint, EventKind::exception,
        EventKind::paused, EventKind::stepped, EventKind::resumed, EventKind::attached,
        EventKind::detached, EventKind::stopping, EventKind::processExited,
        EventKind::debugStopped, EventKind::threadCreated, EventKind::threadExited,
        EventKind::dllLoaded, EventKind::dllUnloaded, EventKind::debugString, EventKind::rip};
    for (const EventKind kind : values) {
        if (value == EventKindName(kind)) return kind;
    }
    return std::nullopt;
}

std::string EventJson(const EventRecord& event) {
    std::string result = "{\"sequence\":" + std::to_string(event.sequence) +
                         ",\"type\":" + JsonString(EventKindName(event.kind)) +
                         ",\"state_generation\":" + std::to_string(event.generation);
    if (event.hasProcessId) {
        result += ",\"process_id\":" + JsonString(HexValue(event.processId));
    }
    if (event.hasThreadId) {
        result += ",\"thread_id\":" + JsonString(HexValue(event.threadId));
    }
    if (event.hasAddress) {
        result += ",\"address\":" + JsonString(HexValue(event.address));
    }
    if (event.hasCode) {
        result += ",\"code\":" + JsonString(HexValue(event.code));
    }
    if (event.kind == EventKind::breakpoint) {
        const char* type = "unknown";
        switch (event.breakpointType) {
        case 1U: type = "software"; break;
        case 2U: type = "hardware"; break;
        case 4U: type = "memory"; break;
        case 8U: type = "dll"; break;
        case 16U: type = "exception"; break;
        default: break;
        }
        result += ",\"breakpoint_type\":" + JsonString(type) +
                  ",\"hit_count\":" + std::to_string(event.auxiliary);
    } else if (event.kind == EventKind::exception) {
        result += ",\"first_chance\":" +
                  std::string(event.firstChance ? "true" : "false");
    } else if (event.kind == EventKind::threadExited ||
               event.kind == EventKind::processExited || event.kind == EventKind::rip) {
        result += ",\"status\":" + JsonString(HexValue(event.auxiliary));
    } else if (event.kind == EventKind::debugString) {
        result += ",\"length\":" + std::to_string(event.auxiliary) +
                  ",\"unicode\":" + std::string(event.firstChance ? "true" : "false");
    }
    return result + "}";
}

#ifndef MCP_LIFECYCLE_HARNESS
struct ResolvedLocation {
    duint address{0};
    std::optional<std::string> module;
    std::optional<duint> moduleBase;
    std::optional<duint> rva;
};

struct ModuleRecord {
    duint base{0};
    duint size{0};
    std::string name;
};

struct AddressResolution {
    std::optional<ResolvedLocation> location;
    const char* code{"INTERNAL"};
    const char* message{"address resolution failed"};
    bool retryable{false};
};

AddressResolution ResolveAddress(const AddressReference& reference) {
    if (!reference.pointerWidthValid) {
        return AddressResolution{std::nullopt, "INVALID_ARGUMENT",
                                 "address exceeds debugger pointer width", false};
    }
    ResolvedLocation resolved{};
    if (reference.kind == AddressReferenceKind::absolute) {
        resolved.address = reference.absolute;
    }

    ListInfo list{};
    if (!Script::Module::GetList(&list)) {
        if (reference.kind == AddressReferenceKind::absolute) {
            return AddressResolution{std::move(resolved), nullptr, nullptr, false};
        }
        return AddressResolution{std::nullopt, "INTERNAL", "module list is unavailable", true};
    }
    struct ModuleListGuard {
        void* value;
        ~ModuleListGuard() {
            if (value != nullptr) BridgeFree(value);
        }
    } guard{list.data};
    if (list.count < 0 || (list.count > 0 && list.data == nullptr) || list.count > 65536 ||
        list.size != static_cast<std::size_t>(list.count) *
                         sizeof(Script::Module::ModuleInfo)) {
        if (reference.kind == AddressReferenceKind::absolute) {
            return AddressResolution{std::move(resolved), nullptr, nullptr, false};
        }
        return AddressResolution{std::nullopt, "INTERNAL", "module list is invalid", false};
    }
    const auto* modules = static_cast<const Script::Module::ModuleInfo*>(list.data);
    const Script::Module::ModuleInfo* match = nullptr;
    std::size_t matches = 0;
    for (int index = 0; index < list.count; ++index) {
        const auto& module = modules[index];
        if (reference.kind == AddressReferenceKind::moduleRva) {
            const std::size_t nameLength = strnlen_s(module.name, sizeof(module.name));
            const std::string name(module.name, nameLength);
            if (Utf8OrdinalEqualsIgnoreCase(name, reference.module)) {
                match = &module;
                ++matches;
            }
        } else if (reference.absolute >= module.base &&
                   reference.absolute - module.base < module.size) {
            match = &module;
            ++matches;
        }
    }
    if (reference.kind == AddressReferenceKind::moduleRva) {
        if (matches == 0U) {
            return AddressResolution{std::nullopt, "INVALID_ARGUMENT",
                                     "module is not loaded", false};
        }
        if (matches != 1U) {
            return AddressResolution{std::nullopt, "INVALID_ARGUMENT",
                                     "module name is ambiguous", false};
        }
        if (match == nullptr || reference.rva >= match->size) {
            return AddressResolution{std::nullopt, "INVALID_ARGUMENT",
                                     "rva is outside the module", false};
        }
        if (match->base > (std::numeric_limits<duint>::max)() - reference.rva) {
            return AddressResolution{std::nullopt, "INVALID_ARGUMENT",
                                     "module-relative address overflows", false};
        }
        resolved.address = match->base + reference.rva;
    } else if (matches != 1U) {
        return AddressResolution{std::move(resolved), nullptr, nullptr, false};
    }

    if (match != nullptr) {
        const std::size_t nameLength = strnlen_s(match->name, sizeof(match->name));
        resolved.module = std::string(match->name, nameLength);
        resolved.moduleBase = match->base;
        resolved.rva = resolved.address - match->base;
    }
    return AddressResolution{std::move(resolved), nullptr, nullptr, false};
}

std::string LocationJson(const ResolvedLocation& location, const std::uint64_t generation) {
    return "{\"address\":" + JsonString(HexValue(location.address)) + ",\"module\":" +
           (location.module ? JsonString(*location.module) : "null") + ",\"module_base\":" +
           (location.moduleBase ? JsonString(HexValue(*location.moduleBase)) : "null") +
           ",\"rva\":" + (location.rva ? JsonString(HexValue(*location.rva)) : "null") +
           ",\"state_generation\":" + std::to_string(generation) + "}";
}

std::optional<std::vector<ModuleRecord>> CaptureModuleRecords() {
    ListInfo list{};
    if (!Script::Module::GetList(&list)) return std::nullopt;
    struct Guard {
        void* value;
        ~Guard() { if (value != nullptr) BridgeFree(value); }
    } guard{list.data};
    if (list.count < 0 || list.count > 65536 || (list.count > 0 && list.data == nullptr) ||
        list.size != static_cast<std::size_t>(list.count) * sizeof(Script::Module::ModuleInfo)) {
        return std::nullopt;
    }
    const auto* source = static_cast<const Script::Module::ModuleInfo*>(list.data);
    std::vector<ModuleRecord> result;
    result.reserve(static_cast<std::size_t>(list.count));
    for (int index = 0; index < list.count; ++index) {
        const auto& module = source[index];
        result.push_back(ModuleRecord{module.base, module.size,
                                      std::string(module.name,
                                                  strnlen_s(module.name, sizeof(module.name)))});
    }
    return result;
}

std::optional<ModuleRecord> UniqueModule(const std::vector<ModuleRecord>& modules,
                                         const std::string_view name) {
    std::optional<ModuleRecord> match;
    for (const auto& module : modules) {
        if (Utf8OrdinalEqualsIgnoreCase(module.name, name)) {
            if (match) return std::nullopt;
            match = module;
        }
    }
    return match;
}

ResolvedLocation LocationFromModules(const duint address,
                                     const std::vector<ModuleRecord>& modules) {
    ResolvedLocation result{};
    result.address = address;
    const ModuleRecord* match = nullptr;
    for (const auto& module : modules) {
        if (address >= module.base && address - module.base < module.size) {
            if (match != nullptr) return result;
            match = &module;
        }
    }
    if (match != nullptr) {
        result.module = match->name;
        result.moduleBase = match->base;
        result.rva = address - match->base;
    }
    return result;
}

std::string DiscoveryCursor(const Request& request, const std::uint64_t generation,
                            const std::size_t index) {
    std::ostringstream cursor;
    cursor << "v2:" << generation << ':' << std::hex << std::nouppercase
           << request.cursorFingerprint.value_or(0U) << ':' << std::dec << index;
    return cursor.str();
}

std::string PatchCursor(const Request& request, const std::uint64_t generation,
                        const std::uint64_t snapshotFingerprint, const std::size_t index) {
    std::ostringstream cursor;
    cursor << "v3:" << generation << ':' << std::hex << std::nouppercase
           << request.cursorFingerprint.value_or(0U) << ':' << snapshotFingerprint << ':'
           << std::dec << index;
    return cursor.str();
}

struct StringCandidate {
    std::size_t offset{0};
    std::size_t byteLength{0};
    std::string text;
    const char* encoding{"ascii_utf8"};
    bool truncated{false};
    std::size_t key{0};
    std::size_t matchOffset{0};
    std::size_t textOffset{0};
    std::string before;
    std::string match;
    std::string after;
    bool hasMatch{false};
};

struct StringContext {
    std::string text;
    std::size_t offset{0};
    bool truncated{false};
};

StringContext ContextAroundUtf8Match(const std::string_view value,
                                     const std::size_t matchOffset) {
    constexpr std::size_t kMaxBytes = 512U;
    constexpr std::size_t kPrefixBytes = 128U;
    std::size_t start = matchOffset > kPrefixBytes ? matchOffset - kPrefixBytes : 0U;
    while (start < value.size() &&
           (static_cast<unsigned char>(value[start]) & 0xc0U) == 0x80U) ++start;
    std::size_t end = (std::min)(value.size(), start + kMaxBytes);
    while (end > start && !IsValidUtf8(value.substr(start, end - start))) --end;
    return {std::string(value.substr(start, end - start)), start,
            start != 0U || end != value.size()};
}

std::optional<std::string> Utf16ToUtf8(const std::span<const wchar_t> value) {
    if (value.empty() || value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        return std::nullopt;
    const int inputLength = static_cast<int>(value.size());
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                              inputLength, nullptr, 0, nullptr, nullptr);
    if (required <= 0) return std::nullopt;
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), inputLength,
                            result.data(), required, nullptr, nullptr) != required) return std::nullopt;
    return result;
}

std::optional<duint> RegisterValue(const REGISTERCONTEXT_AVX512& context,
                                   const std::string_view name) {
    if (name == "cip") return context.cip;
    if (name == "csp") return context.csp;
    if (name == "cbp") return context.cbp;
    if (name == "eflags") return context.eflags;
#ifdef _WIN64
    if (name == "rax") return context.cax;
    if (name == "rbx") return context.cbx;
    if (name == "rcx") return context.ccx;
    if (name == "rdx") return context.cdx;
    if (name == "rsp") return context.csp;
    if (name == "rbp") return context.cbp;
    if (name == "rsi") return context.csi;
    if (name == "rdi") return context.cdi;
    if (name == "rip") return context.cip;
    if (name == "r8") return context.r8;
    if (name == "r9") return context.r9;
    if (name == "r10") return context.r10;
    if (name == "r11") return context.r11;
    if (name == "r12") return context.r12;
    if (name == "r13") return context.r13;
    if (name == "r14") return context.r14;
    if (name == "r15") return context.r15;
#else
    if (name == "eax") return context.cax;
    if (name == "ebx") return context.cbx;
    if (name == "ecx") return context.ccx;
    if (name == "edx") return context.cdx;
    if (name == "esp") return context.csp;
    if (name == "ebp") return context.cbp;
    if (name == "esi") return context.csi;
    if (name == "edi") return context.cdi;
    if (name == "eip") return context.cip;
#endif
    return std::nullopt;
}

enum class ThreadContextStatus : std::uint8_t {
    ok,
    invalidList,
    missing,
    unavailable,
    changed
};

struct CapturedThreadContext {
    REGISTERCONTEXT_AVX512 registers{};
    std::uint32_t threadId{0U};
    std::uint32_t activeThreadId{0U};
    bool current{false};
};

struct ThreadContextCapture {
    ThreadContextStatus status{ThreadContextStatus::unavailable};
    CapturedThreadContext value;
};

std::optional<std::uint32_t> SelectedThreadId() {
    THREADLIST list{};
    DbgGetThreadList(&list);
    struct ThreadListGuard {
        THREADALLINFO* value;
        ~ThreadListGuard() { if (value != nullptr) BridgeFree(value); }
    } guard{list.list};
    if (list.count <= 0 || list.count > 65536 || list.list == nullptr ||
        list.CurrentThread < 0 || list.CurrentThread >= list.count) {
        return std::nullopt;
    }
    const THREADALLINFO& selected = list.list[list.CurrentThread];
    const HANDLE selectedHandle = DbgGetThreadHandle();
    if (selected.BasicInfo.ThreadId == 0U || selected.BasicInfo.Handle == nullptr ||
        selected.BasicInfo.Handle == INVALID_HANDLE_VALUE ||
        selectedHandle != selected.BasicInfo.Handle) {
        return std::nullopt;
    }
    return selected.BasicInfo.ThreadId;
}

ThreadContextCapture CaptureThreadContext(
    const std::optional<std::uint32_t> requestedThreadId) {
    THREADLIST list{};
    DbgGetThreadList(&list);
    struct ThreadListGuard {
        THREADALLINFO* value;
        ~ThreadListGuard() { if (value != nullptr) BridgeFree(value); }
    } guard{list.list};
    if (list.count < 0 || list.count > 65536 ||
        (list.count > 0 && list.list == nullptr) || list.CurrentThread < 0 ||
        list.CurrentThread >= list.count) {
        return {ThreadContextStatus::invalidList, {}};
    }
    const std::uint32_t activeBefore =
        list.list[list.CurrentThread].BasicInfo.ThreadId;
    const std::uint32_t requested = requestedThreadId.value_or(activeBefore);
    if (activeBefore == 0U || requested == 0U ||
        DbgGetThreadHandle() != list.list[list.CurrentThread].BasicInfo.Handle) {
        return {ThreadContextStatus::changed, {}};
    }
    const THREADALLINFO* match = nullptr;
    int matchIndex = -1;
    for (int index = 0; index < list.count; ++index) {
        if (list.list[index].BasicInfo.ThreadId == requested) {
            if (match != nullptr) return {ThreadContextStatus::invalidList, {}};
            match = &list.list[index];
            matchIndex = index;
        }
    }
    if (match == nullptr || match->BasicInfo.Handle == nullptr ||
        match->BasicInfo.Handle == INVALID_HANDLE_VALUE) {
        return {ThreadContextStatus::missing, {}};
    }
    const bool current = requested == activeBefore;
    if ((matchIndex == list.CurrentThread) != current) {
        return {ThreadContextStatus::changed, {}};
    }

    REGISTERCONTEXT_AVX512 registers{};
    if (current) {
        REGDUMP_AVX512 dump{};
        if (!DbgGetRegDumpEx(&dump, sizeof(dump))) {
            return {ThreadContextStatus::unavailable, {}};
        }
        registers = dump.regcontext;
    } else {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (GetThreadContext(match->BasicInfo.Handle, &context) == FALSE) {
            return {ThreadContextStatus::unavailable, {}};
        }
        registers = CoreRegisterContext(context);
    }
    if (registers.cip != match->ThreadCip || SelectedThreadId() != activeBefore) {
        return {ThreadContextStatus::changed, {}};
    }
    return {ThreadContextStatus::ok,
            {registers, requested, activeBefore, current}};
}

ThreadContextStatus MutateThreadContext(
    const std::uint32_t requestedThreadId,
    const std::vector<RegisterAssignment>& assignments) {
    if (requestedThreadId == 0U || assignments.empty()) {
        return ThreadContextStatus::missing;
    }
    THREADLIST list{};
    DbgGetThreadList(&list);
    struct ThreadListGuard {
        THREADALLINFO* value;
        ~ThreadListGuard() { if (value != nullptr) BridgeFree(value); }
    } guard{list.list};
    if (list.count < 0 || list.count > 65536 ||
        (list.count > 0 && list.list == nullptr)) {
        return ThreadContextStatus::invalidList;
    }
    HANDLE threadHandle = nullptr;
    for (int index = 0; index < list.count; ++index) {
        if (list.list[index].BasicInfo.ThreadId == requestedThreadId) {
            if (threadHandle != nullptr) return ThreadContextStatus::invalidList;
            threadHandle = list.list[index].BasicInfo.Handle;
        }
    }
    if (threadHandle == nullptr || threadHandle == INVALID_HANDLE_VALUE) {
        return ThreadContextStatus::missing;
    }
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (GetThreadContext(threadHandle, &context) == FALSE ||
        !ApplyRegisterAssignments(context, assignments) ||
        SetThreadContext(threadHandle, &context) == FALSE) {
        return ThreadContextStatus::unavailable;
    }
    CONTEXT observed{};
    observed.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (GetThreadContext(threadHandle, &observed) == FALSE) {
        return ThreadContextStatus::unavailable;
    }
    const REGISTERCONTEXT_AVX512 registers = CoreRegisterContext(observed);
    for (const RegisterAssignment& assignment : assignments) {
        const std::optional<duint> value = RegisterValue(registers, assignment.name);
        if (!value || *value != static_cast<duint>(assignment.value)) {
            return ThreadContextStatus::changed;
        }
    }
    return ThreadContextStatus::ok;
}
#endif

std::chrono::steady_clock::time_point SteadyDeadline(const std::uint64_t unixMs) {
    using namespace std::chrono;
    const auto nowSystem = system_clock::now();
    const auto requested = system_clock::time_point(milliseconds(unixMs));
    if (requested <= nowSystem) {
        return steady_clock::now();
    }
    return steady_clock::now() + duration_cast<steady_clock::duration>(requested - nowSystem);
}

std::string ErrorResponseForId(const std::string_view requestId, const std::string_view code,
                               const std::string_view message, const bool retryable,
                               const bool unknown) {
    return "{\"request_id\":" + JsonString(requestId) +
           ",\"state_generation\":0,\"status\":\"error\",\"error\":{\"code\":" +
           JsonString(code) + ",\"message\":" + JsonString(message) +
           ",\"retryable\":" + (retryable ? "true" : "false") +
           ",\"details\":" + (unknown ? "{\"outcome\":\"unknown\"}" : "{}") + "}}";
}

std::string ErrorResponse(const Request& request, const std::string_view code,
                          const std::string_view message, const bool retryable,
                          const bool unknown) {
    return ErrorResponseForId(request.requestId, code, message, retryable, unknown);
}

#ifndef MCP_LIFECYCLE_HARNESS
std::string ThreadContextErrorResponse(const Request& request,
                                       const ThreadContextStatus status) {
    switch (status) {
    case ThreadContextStatus::invalidList:
        return ErrorResponse(request, "INTERNAL", "thread snapshot is invalid", false, false);
    case ThreadContextStatus::missing:
        return request.targetThreadId
                   ? ErrorResponse(request, "INVALID_ARGUMENT",
                                   "thread_id is not present in this debuggee", false, false)
                   : ErrorResponse(request, "INVALID_DEBUGGER_STATE",
                                   "no current debugger thread is available", false, false);
    case ThreadContextStatus::unavailable:
        return ErrorResponse(request, "ACCESS_DENIED", "thread context is unavailable", false,
                             false);
    case ThreadContextStatus::changed:
        return ErrorResponse(request, "BUSY", "thread selection or context changed during capture",
                             true, false);
    case ThreadContextStatus::ok: break;
    }
    return ErrorResponse(request, "INTERNAL", "thread context status is invalid", false, false);
}
#endif

std::string ErrorResponseWithDetails(const Request& request, const std::string_view code,
                                     const std::string_view message, const bool retryable,
                                     const std::string_view details) {
    return "{\"request_id\":" + JsonString(request.requestId) +
           ",\"state_generation\":0,\"status\":\"error\",\"error\":{\"code\":" +
           JsonString(code) + ",\"message\":" + JsonString(message) +
           ",\"retryable\":" + (retryable ? "true" : "false") +
           ",\"details\":" + std::string(details) + "}}";
}

std::filesystem::path ModuleDirectory() {
    HMODULE module = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&ModuleDirectory), &module) == FALSE) {
        return {};
    }
    std::wstring path(32768U, L'\0');
    const DWORD length = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0U || length >= path.size()) {
        return {};
    }
    path.resize(length);
    return std::filesystem::path(path).parent_path();
}

std::filesystem::path ScyllaHideConfigPath() {
    return ModuleDirectory() / L"scylla_hide.ini";
}

std::optional<std::string> ReadScyllaHideConfig() {
    const std::filesystem::path path = ScyllaHideConfigPath();
    std::error_code error;
    const std::uintmax_t size = std::filesystem::file_size(path, error);
    if (error || size == 0U || size > 1024U * 1024U) return std::nullopt;
    std::ifstream input(path, std::ios::binary);
    if (!input) return std::nullopt;
    std::string text(static_cast<std::size_t>(size), '\0');
    input.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (!input || input.gcount() != static_cast<std::streamsize>(text.size())) return std::nullopt;
    return text;
}

std::optional<std::string> ConfigGeneration(const std::string_view text) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0U) < 0) {
        return std::nullopt;
    }
    std::array<unsigned char, 32> digest{};
    const NTSTATUS status = BCryptHash(
        algorithm, nullptr, 0U,
        reinterpret_cast<PUCHAR>(const_cast<char*>(text.data())),
        static_cast<ULONG>(text.size()), digest.data(), static_cast<ULONG>(digest.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0U);
    if (status < 0) return std::nullopt;
    return "sha256:" + Hex(digest);
}

bool AtomicReplaceScyllaHideConfig(const std::string_view text) {
    const std::filesystem::path path = ScyllaHideConfigPath();
    const std::filesystem::path temporary =
        path.parent_path() /
        (L".scylla-hide-mcp-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
         std::to_wstring(GetTickCount64()) + L".tmp");
    HANDLE output = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (output == INVALID_HANDLE_VALUE) return false;
    const bool writeOk = text.size() <= std::numeric_limits<DWORD>::max() &&
                         WriteAll(output, text.data(), static_cast<DWORD>(text.size())) &&
                         FlushFileBuffers(output) != FALSE;
    CloseHandle(output);
    if (!writeOk || MoveFileExW(temporary.c_str(), path.c_str(),
                                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
        DeleteFileW(temporary.c_str());
        return false;
    }
    return true;
}
} // namespace

Runtime::~Runtime() { Stop(); }

bool Runtime::IsReady() const noexcept { return pluginState_.load() == PluginState::ready; }

#ifdef MCP_LIFECYCLE_HARNESS
DWORD Runtime::SidecarProcessIdForTesting() const noexcept {
    return sidecarProcess_ == nullptr ? 0U : GetProcessId(sidecarProcess_);
}

PauseObservation Runtime::PauseForTesting() noexcept {
    std::lock_guard lock(stateMutex_);
    return latestPause_;
}

std::optional<std::uint64_t> Runtime::BeginPausedSnapshotForTesting() noexcept {
    return BeginPausedSnapshot();
}

bool Runtime::PausedSnapshotCurrentForTesting(const std::uint64_t generation) noexcept {
    return PausedSnapshotCurrent(generation);
}

SessionOrigin Runtime::SessionOriginForTesting() const noexcept {
    return sessionOrigin_.load();
}

std::vector<EventRecord> Runtime::EventsForTesting() noexcept {
    std::lock_guard lock(stateMutex_);
    std::vector<EventRecord> events;
    events.reserve(eventCount_);
    for (std::size_t index = 0U; index < eventCount_; ++index) {
        events.push_back(eventRing_[(eventStart_ + index) % kEventCapacity]);
    }
    return events;
}

bool Runtime::StartTraceForTesting() noexcept {
    std::lock_guard lock(traceMutex_);
    const bool started = trace_.Start(
        "00000000-0000-4000-8000-000000000001", TraceMode::over,
        TracePolicy::kMaxSteps, std::chrono::steady_clock::now() + std::chrono::seconds(30),
        0x401000U, {});
    if (started) {
        tracePauseSubmitted_ = false;
        traceChanged_.notify_all();
    }
    return started;
}

TraceReason Runtime::TraceReasonForTesting() noexcept {
    std::lock_guard lock(traceMutex_);
    return trace_.Reason();
}
#endif

bool Runtime::Start() {
    PluginState expected = PluginState::stopped;
    if (!pluginState_.compare_exchange_strong(expected, PluginState::starting)) {
        return false;
    }
    startupScyllaGeneration_.clear();
    startupScyllaProfile_.clear();
    if (const auto text = ReadScyllaHideConfig()) {
        startupScyllaGeneration_ = ConfigGeneration(*text).value_or("");
        std::string error;
        if (const auto config = control::ParseScyllaHideConfig(*text, error)) {
            startupScyllaProfile_ = config->currentProfile;
        }
    }
    std::wstring mutexName = std::wstring(L"Local\\x64dbg-mcp-backend-") + kBackend;
#ifdef MCP_LIFECYCLE_HARNESS
    // A lifecycle harness is an isolated backend instance. Keep its ownership
    // check independent from a debugger the developer may already be running.
    mutexName += L"-test-" + std::to_wstring(GetCurrentProcessId());
#endif
    instanceMutex_ = CreateMutexW(nullptr, FALSE, mutexName.c_str());
    if (instanceMutex_ == nullptr || GetLastError() == ERROR_ALREADY_EXISTS || !executor_.Start() ||
        !commandFence_.Start() || !CreateEndpoint() || !LaunchSidecar()) {
        Stop();
        return false;
    }
    try {
        {
            std::lock_guard lock(traceMutex_);
            traceSupervisorStopping_ = false;
            tracePauseSubmitted_ = false;
        }
        traceSupervisor_ = std::thread(&Runtime::TraceSupervisor, this);
        worker_ = std::thread(&Runtime::Worker, this);
    } catch (...) {
        Stop();
        return false;
    }
    return true;
}

bool Runtime::CreateEndpoint() {
    std::array<unsigned char, 32> random{};
    if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        return false;
    }
    nonce_ = Hex(random);
    pipeName_ = std::wstring(L"\\\\.\\pipe\\x64dbg-mcp-") + kBackend + L"-" +
                std::wstring(nonce_.begin(), nonce_.begin() + 24);

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;OW)(A;;GA;;;SY)", SDDL_REVISION_1, &descriptor, nullptr) == FALSE) {
        return false;
    }
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    pipe_ = CreateNamedPipeW(pipeName_.c_str(),
                             PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                             PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                             1U, kMaxFrameBytes, kMaxFrameBytes, 5000U, &attributes);
    LocalFree(descriptor);
    return pipe_ != INVALID_HANDLE_VALUE;
}

bool Runtime::LaunchSidecar() {
    SECURITY_ATTRIBUTES inheritable{sizeof(inheritable), nullptr, TRUE};
    HANDLE nonceReader = nullptr;
    if (CreatePipe(&nonceReader, &nonceWriter_, &inheritable, 256U) == FALSE ||
        SetHandleInformation(nonceWriter_, HANDLE_FLAG_INHERIT, 0U) == FALSE) {
        CloseHandleValue(nonceReader);
        return false;
    }
    HANDLE nullOutput = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    &inheritable, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (nullOutput == INVALID_HANDLE_VALUE) {
        CloseHandleValue(nonceReader);
        return false;
    }

    std::wstring configured(32768U, L'\0');
    DWORD configuredLength = GetEnvironmentVariableW(
        L"X64DBG_MCP_SERVER_PATH", configured.data(), static_cast<DWORD>(configured.size()));
    std::filesystem::path executable;
    if (configuredLength != 0U && configuredLength < configured.size()) {
        configured.resize(configuredLength);
        executable = configured;
    } else {
        executable = ModuleDirectory() / L".." / L".." / L"mcp" / L"x96dbg-mcp-server.exe";
    }
    executable = std::filesystem::absolute(executable).lexically_normal();
    if (!std::filesystem::is_regular_file(executable)) {
        CloseHandleValue(nonceReader);
        CloseHandle(nullOutput);
        return false;
    }

    sidecarJob_ = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobLimits{};
    jobLimits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (sidecarJob_ == nullptr ||
        SetInformationJobObject(sidecarJob_, JobObjectExtendedLimitInformation, &jobLimits,
                                sizeof(jobLimits)) == FALSE) {
        CloseHandleValue(sidecarJob_);
        CloseHandleValue(nonceReader);
        CloseHandle(nullOutput);
        return false;
    }

    SIZE_T attributeBytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1U, 0U, &attributeBytes);
    std::vector<std::byte> storage(attributeBytes);
    auto* attributes = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if (InitializeProcThreadAttributeList(attributes, 1U, 0U, &attributeBytes) == FALSE) {
        CloseHandleValue(sidecarJob_);
        CloseHandleValue(nonceReader);
        CloseHandle(nullOutput);
        return false;
    }
    const std::array<HANDLE, 2> inherited{nonceReader, nullOutput};
    const bool attributeOk = UpdateProcThreadAttribute(
                                 attributes, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                 const_cast<HANDLE*>(inherited.data()), sizeof(inherited), nullptr,
                                 nullptr) != FALSE;
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = nonceReader;
    startup.StartupInfo.hStdOutput = nullOutput;
    startup.StartupInfo.hStdError = nullOutput;
    startup.lpAttributeList = attributes;
    std::wstring command = L"\"" + executable.wstring() + L"\" --pipe \"" + pipeName_ + L"\"";
    const std::filesystem::path backendConfig =
        executable.parent_path() /
        (std::wstring(L"x64dbg-mcp-server-") + kConfigBackend + L".toml");
    if (std::filesystem::is_regular_file(backendConfig)) {
        command += L" --config \"" + backendConfig.wstring() + L"\"";
        PluginLog("[x64dbg-mcp-backend] using installed per-backend configuration");
    } else {
        PluginLog(
            "[x64dbg-mcp-backend] installed per-backend configuration not found; using environment configuration");
    }
    PROCESS_INFORMATION process{};
    const BOOL created = attributeOk
                             ? CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr,
                                              TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW |
                                                        CREATE_SUSPENDED,
                                              nullptr, executable.parent_path().c_str(),
                                              &startup.StartupInfo, &process)
                             : FALSE;
    DeleteProcThreadAttributeList(attributes);
    CloseHandleValue(nonceReader);
    CloseHandle(nullOutput);
    if (created == FALSE) {
        CloseHandleValue(sidecarJob_);
        return false;
    }
    if (AssignProcessToJobObject(sidecarJob_, process.hProcess) == FALSE ||
        ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
        TerminateProcess(process.hProcess, ERROR_PROCESS_ABORTED);
        WaitForSingleObject(process.hProcess, 1000U);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        CloseHandleValue(sidecarJob_);
        return false;
    }
    CloseHandle(process.hThread);
    sidecarProcess_ = process.hProcess;
    const std::string line = nonce_ + "\n";
    return WriteAll(nonceWriter_, line.data(), static_cast<DWORD>(line.size()));
}

void Runtime::Worker() noexcept {
    const BOOL connected = ConnectNamedPipe(pipe_, nullptr);
    if (connected == FALSE && GetLastError() != ERROR_PIPE_CONNECTED) {
        PluginLog("[x64dbg-mcp-backend] sidecar IPC connection failed");
        return;
    }
    std::ostringstream handshake;
    handshake << "{\"protocol_major\":1,\"protocol_minor\":1,\"backend\":\""
              << kBackendUtf8 << "\",\"plugin_pid\":" << GetCurrentProcessId()
              << ",\"nonce\":" << JsonString(nonce_) << "}";
    std::string ack;
    if (!WriteFrame(pipe_, handshake.str()) || !ReadFrame(pipe_, ack)) {
        PluginLog("[x64dbg-mcp-backend] sidecar IPC handshake failed");
        return;
    }
    const std::optional<std::string> instanceId = AcceptedHandshakeInstanceId(ack);
    if (!instanceId) {
        PluginLog("[x64dbg-mcp-backend] sidecar IPC handshake failed");
        return;
    }
    {
        std::lock_guard lock(stateMutex_);
        instanceId_ = *instanceId;
        pluginState_.store(PluginState::ready);
        generation_.fetch_add(1U);
    }
    PluginLog("[x64dbg-mcp-backend] sidecar ready");
    for (;;) {
        std::string request;
        if (!ReadFrame(pipe_, request) || pluginState_.load() != PluginState::ready) {
            break;
        }
        const std::optional<Request> parsed = ParseRequest(request);
        if (!parsed) {
            break;
        }
        const auto requestDeadline = SteadyDeadline(parsed->deadlineUnixMs);
        if (parsed->method == "scyllahide.profile") {
            const std::string response =
                std::chrono::steady_clock::now() >= requestDeadline
                    ? ErrorResponse(*parsed, "TIMEOUT", "operation deadline elapsed",
                                    !parsed->mutation, false)
                    : ScyllaHideProfileResponse(
                          parsed->requestId, parsed->operationId, parsed->scyllaAction,
                          parsed->scyllaProfile, parsed->expectedConfigGeneration);
            if (!WriteFrame(pipe_, response)) break;
            continue;
        }
        const ExecutionResult execution = executor_.Execute(
            [this, parsed, requestDeadline] {
                const auto submitFencedCommand = [this, requestDeadline](
                                                      const std::string& command) {
                    std::uint64_t fenceToken = 0U;
                    for (int attempt = 0; attempt < 4 && fenceToken == 0U; ++attempt) {
                        if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&fenceToken),
                                            static_cast<ULONG>(sizeof(fenceToken)),
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
                            fenceToken = 0U;
                        }
                    }
                    if (fenceToken == 0U || !commandFence_.Arm(fenceToken)) return 1;
                    if (!DbgCmdExec(command.c_str())) {
                        commandFence_.Cancel(fenceToken);
                        return 1;
                    }
                    std::ostringstream fenceText;
                    fenceText << "x64dbg_mcp_fence_internal " << std::hex << std::nouppercase
                              << std::setw(16) << std::setfill('0') << fenceToken;
                    if (!DbgCmdExec(fenceText.str().c_str())) {
                        commandFence_.Cancel(fenceToken);
                        return 2;
                    }
                    return commandFence_.Wait(fenceToken, requestDeadline) ==
                                   CommandFenceWait::completed
                               ? 0
                               : 2;
                };
                if (parsed->method == "debugger.state") {
                    return StateResponse(parsed->requestId);
                }
                if (parsed->method == "events.list") {
                    std::array<EventRecord, Runtime::kEventCapacity> copied{};
                    std::size_t copiedCount = 0U;
                    std::uint64_t oldest = 0U;
                    std::uint64_t latest = 0U;
                    bool hasMore = false;
                    bool overflowed = false;
                    {
                        std::lock_guard lock(stateMutex_);
                        if (eventCount_ != 0U) {
                            oldest = eventRing_[eventStart_].sequence;
                            latest = eventRing_[(eventStart_ + eventCount_ - 1U) %
                                                kEventCapacity].sequence;
                            overflowed = oldest > 1U && parsed->afterEventSequence < oldest - 1U;
                        }
                        for (std::size_t offset = 0U; offset < eventCount_; ++offset) {
                            const EventRecord& event =
                                eventRing_[(eventStart_ + offset) % kEventCapacity];
                            if (event.sequence <= parsed->afterEventSequence ||
                                (!parsed->eventTypes.empty() &&
                                 std::find(parsed->eventTypes.begin(), parsed->eventTypes.end(),
                                           event.kind) == parsed->eventTypes.end())) {
                                continue;
                            }
                            if (copiedCount < parsed->pageLimit) {
                                copied[copiedCount++] = event;
                            } else {
                                hasMore = true;
                                break;
                            }
                        }
                    }
                    std::string items = "[";
                    for (std::size_t index = 0U; index < copiedCount; ++index) {
                        if (index != 0U) items.push_back(',');
                        items += EventJson(copied[index]);
                    }
                    items += "]";
                    const std::string next = copiedCount == 0U
                                                 ? "null"
                                                 : std::to_string(copied[copiedCount - 1U].sequence);
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(generation_.load()) +
                           ",\"status\":\"ok\",\"result\":{\"oldest_sequence\":" +
                           std::to_string(oldest) + ",\"latest_sequence\":" +
                           std::to_string(latest) + ",\"overflowed\":" +
                           (overflowed ? "true" : "false") + ",\"has_more\":" +
                           (hasMore ? "true" : "false") + ",\"next_after_sequence\":" +
                           next + ",\"items\":" + items + "}}";
                }
                if (parsed->method == "events.wait") {
                    const auto waitDeadline = (std::min)(
                        requestDeadline, std::chrono::steady_clock::now() +
                                             std::chrono::milliseconds(parsed->waitTimeoutMs));
                    EventRecord matched;
                    std::uint64_t oldest = 0U;
                    std::uint64_t latest = 0U;
                    bool overflowed = false;
                    bool found = false;
                    {
                        std::unique_lock lock(stateMutex_);
                        const auto findMatch = [this, parsed, &matched, &oldest, &latest,
                                                &overflowed, &found] {
                            oldest = 0U;
                            latest = 0U;
                            overflowed = false;
                            found = false;
                            if (eventCount_ != 0U) {
                                oldest = eventRing_[eventStart_].sequence;
                                latest = eventRing_[(eventStart_ + eventCount_ - 1U) %
                                                    kEventCapacity].sequence;
                                overflowed = oldest > 1U &&
                                             parsed->afterEventSequence < oldest - 1U;
                            }
                            for (std::size_t offset = 0U; offset < eventCount_; ++offset) {
                                const EventRecord& event =
                                    eventRing_[(eventStart_ + offset) % kEventCapacity];
                                if (event.sequence > parsed->afterEventSequence &&
                                    std::find(parsed->eventTypes.begin(),
                                              parsed->eventTypes.end(), event.kind) !=
                                        parsed->eventTypes.end()) {
                                    matched = event;
                                    found = true;
                                    return true;
                                }
                            }
                            return pluginState_.load() != PluginState::ready;
                        };
                        if (!findMatch()) {
                            stateChanged_.wait_until(lock, waitDeadline, findMatch);
                            findMatch();
                        }
                    }
                    if (pluginState_.load() != PluginState::ready) {
                        return ErrorResponse(*parsed, "CANCELLED", "plugin is draining", true,
                                             false);
                    }
                    if (!found) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "no matching debugger event was observed", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" +
                           std::to_string(matched.generation) +
                           ",\"status\":\"ok\",\"result\":{\"oldest_sequence\":" +
                           std::to_string(oldest) + ",\"latest_sequence\":" +
                           std::to_string(latest) + ",\"overflowed\":" +
                           (overflowed ? "true" : "false") + ",\"event\":" +
                           EventJson(matched) + "}}";
                }
                if (parsed->method == "trace.status") {
                    TracePolicy copied;
                    {
                        std::lock_guard lock(traceMutex_);
                        if (!trace_.Matches(parsed->traceId)) {
                            return ErrorResponse(*parsed, "NOT_FOUND",
                                                 "trace_id is not retained", false, false);
                        }
                        copied = trace_;
                    }
                    const std::uint64_t generation = generation_.load();
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(generation) +
                           ",\"status\":\"ok\",\"result\":" +
                           TraceStatusJson(copied, generation) + "}";
                }
                if (parsed->method == "trace.results") {
                    TracePolicy copied;
                    {
                        std::lock_guard lock(traceMutex_);
                        if (!trace_.Matches(parsed->traceId)) {
                            return ErrorResponse(*parsed, "NOT_FOUND",
                                                 "trace_id is not retained", false, false);
                        }
                        if (!trace_.Terminal()) {
                            return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                                 "trace results require a terminal session",
                                                 false, false);
                        }
                        copied = trace_;
                    }
                    const std::uint64_t fingerprint = TraceFingerprint(copied);
                    if (parsed->traceCursorInvalid ||
                        (parsed->cursorSnapshotFingerprint &&
                         *parsed->cursorSnapshotFingerprint != fingerprint)) {
                        return ErrorResponse(*parsed, "STALE_CURSOR",
                                             "trace result cursor does not match this snapshot",
                                             false, false);
                    }
                    if (parsed->cursorIndex > copied.Points().size()) {
                        return ErrorResponse(*parsed, "STALE_CURSOR",
                                             "trace result cursor is outside this snapshot",
                                             false, false);
                    }
                    const std::size_t end = (std::min)(
                        copied.Points().size(), parsed->cursorIndex + parsed->pageLimit);
                    std::string items = "[";
                    for (std::size_t index = parsed->cursorIndex; index < end; ++index) {
                        if (index != parsed->cursorIndex) items.push_back(',');
                        const std::uint64_t address = copied.Points()[index].address;
                        const TraceModule* match = nullptr;
                        for (const TraceModule& module : copied.Modules()) {
                            if (address >= module.base && address - module.base < module.size) {
                                if (match != nullptr) {
                                    match = nullptr;
                                    break;
                                }
                                match = &module;
                            }
                        }
                        items += "{\"sequence\":" + std::to_string(index) +
                                 ",\"address\":" + JsonString(HexValue(address)) +
                                 ",\"module\":" +
                                 (match ? JsonString(match->name) : std::string("null")) +
                                 ",\"rva\":" +
                                 (match ? JsonString(HexValue(address - match->base))
                                        : std::string("null")) + "}";
                    }
                    items += "]";
                    const std::string next = end < copied.Points().size()
                        ? JsonString(TraceCursor(copied, fingerprint, end))
                        : "null";
                    const std::uint64_t generation = generation_.load();
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(generation) +
                           ",\"status\":\"ok\",\"result\":{\"trace\":" +
                           TraceStatusJson(copied, generation) + ",\"items\":" + items +
                           ",\"next_cursor\":" + next + "}}";
                }
                if (parsed->method == "debugger.wait_for_pause") {
                    if (debuggeeState_.load() == DebuggeeState::absent ||
                        debuggeeState_.load() == DebuggeeState::exited) {
                        return ErrorResponse(*parsed, "NO_DEBUGGEE",
                                             "there is no active debuggee", false, false);
                    }
                    const auto waitDeadline = (std::min)(
                        requestDeadline, std::chrono::steady_clock::now() +
                                             std::chrono::milliseconds(parsed->waitTimeoutMs));
                    PauseObservation pause;
                    std::uint64_t snapshotGeneration = 0;
                    {
                        std::unique_lock lock(stateMutex_);
                        const bool observed = stateChanged_.wait_until(
                            lock, waitDeadline, [this, parsed] {
                                const DebuggeeState state = debuggeeState_.load();
                                return pluginState_.load() != PluginState::ready ||
                                       pausedGeneration_.load() > parsed->afterGeneration ||
                                       state == DebuggeeState::absent ||
                                       state == DebuggeeState::exited ||
                                       state == DebuggeeState::stopping;
                            });
                        if (pluginState_.load() != PluginState::ready) {
                            return ErrorResponse(*parsed, "CANCELLED", "plugin is draining", true,
                                                 false);
                        }
                        const DebuggeeState state = debuggeeState_.load();
                        if (state == DebuggeeState::absent || state == DebuggeeState::exited ||
                            state == DebuggeeState::stopping) {
                            return ErrorResponse(*parsed, "NO_DEBUGGEE",
                                                 "debuggee stopped while waiting", false, false);
                        }
                        if (!observed || pausedGeneration_.load() <= parsed->afterGeneration) {
                            return ErrorResponse(*parsed, "TIMEOUT",
                                                 "no newer pause was observed", true, false);
                        }
                        pause = latestPause_;
                        snapshotGeneration = generation_.load();
                    }
                    if (pause.generation == 0U || pause.generation <= parsed->afterGeneration) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "pause observation changed before capture", true,
                                             false);
                    }
                    std::string instructionPointer = "null";
                    std::uint32_t threadId = activeThreadId_.load();
#ifndef MCP_LIFECYCLE_HARNESS
                    if (!DbgIsDebugging() || debuggeeState_.load() != DebuggeeState::paused) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debuggee resumed before snapshot capture", true,
                                             false);
                    }
                    REGDUMP_AVX512 dump{};
                    if (!DbgGetRegDumpEx(&dump, sizeof(dump))) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "paused register snapshot is unavailable", true,
                                             false);
                    }
                    instructionPointer = JsonString(HexValue(dump.regcontext.cip));
                    threadId = DbgGetThreadId();
#endif
                    if (!PauseObservationCurrent(snapshotGeneration, pause.generation)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "pause changed during snapshot capture", true, false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(snapshotGeneration) +
                           ",\"status\":\"ok\",\"result\":{\"debuggee_state\":\"paused\"" +
                           std::string(",\"state_generation\":") +
                           std::to_string(snapshotGeneration) + ",\"instruction_pointer\":" +
                           instructionPointer + ",\"active_thread_id\":" +
                           (threadId == 0U ? "null" : JsonString(HexValue(threadId))) +
                           ",\"pause_reason\":" + PauseReasonJson(pause) + "}}";
                }
#ifndef MCP_LIFECYCLE_HARNESS
                if (parsed->method == "trace.start") {
                    {
                        std::lock_guard lock(traceMutex_);
                        if (trace_.Active()) {
                            return ErrorResponse(*parsed, "BUSY",
                                                 "another trace session is active", true, false);
                        }
                    }
                    const auto snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "trace start requires a paused debuggee", false,
                                             false);
                    }
                    REGDUMP_AVX512 registers{};
                    const auto modules = CaptureModuleRecords();
                    if (!DbgGetRegDumpEx(&registers, sizeof(registers)) || !modules ||
                        registers.regcontext.cip == 0U) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "trace start snapshot is unavailable", true, false);
                    }
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed before trace admission", true,
                                             false);
                    }
                    const auto id = RandomUuid();
                    if (!id) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "trace identity generation failed", false, false);
                    }
                    std::vector<TraceModule> traceModules;
                    try {
                        traceModules.reserve(modules->size());
                        for (const ModuleRecord& module : *modules) {
                            traceModules.push_back({static_cast<std::uint64_t>(module.base),
                                                    static_cast<std::uint64_t>(module.size),
                                                    module.name});
                        }
                    } catch (...) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "trace module snapshot allocation failed", false,
                                             false);
                    }
                    const TraceMode mode = parsed->traceMode == "into"
                                               ? TraceMode::into
                                               : TraceMode::over;
                    const auto traceDeadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(parsed->traceTimeoutMs);
                    {
                        std::lock_guard lock(traceMutex_);
                        if (!trace_.Start(*id, mode, parsed->traceMaxSteps, traceDeadline,
                                          registers.regcontext.cip,
                                          std::move(traceModules))) {
                            return ErrorResponse(*parsed, "BUSY",
                                                 "trace session could not be admitted", true,
                                                 false);
                        }
                        tracePauseSubmitted_ = false;
                    }
                    traceChanged_.notify_all();
                    const std::string command =
                        std::string(mode == TraceMode::into ? "TraceIntoConditional 0, ."
                                                           : "TraceOverConditional 0, .") +
                        std::to_string(parsed->traceMaxSteps);
                    if (!DbgCmdExec(command.c_str())) {
                        {
                            std::lock_guard lock(traceMutex_);
                            (void)trace_.Finalize(TraceReason::interrupted);
                        }
                        traceChanged_.notify_all();
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger command queue rejected trace start", true,
                                             false);
                    }
                    TracePolicy copied;
                    {
                        std::unique_lock lock(traceMutex_);
                        const auto admissionDeadline = (std::min)(
                            requestDeadline,
                            (std::min)(traceDeadline,
                                       std::chrono::steady_clock::now() +
                                           std::chrono::milliseconds(2000)));
                        const bool observed = traceChanged_.wait_until(
                            lock, admissionDeadline, [this, &id] {
                                return pluginState_.load() != PluginState::ready ||
                                       !trace_.Matches(*id) ||
                                       trace_.State() != TraceState::starting;
                            });
                        if (!observed || !trace_.Matches(*id) ||
                            trace_.State() == TraceState::starting) {
                            return ErrorResponse(*parsed, "TIMEOUT",
                                                 "trace admission outcome is unknown", false,
                                                 true);
                        }
                        copied = trace_;
                    }
                    const std::uint64_t generation = generation_.load();
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(generation) +
                           ",\"status\":\"ok\",\"result\":" +
                           TraceStatusJson(copied, generation) + "}";
                }
                if (parsed->method == "trace.cancel") {
                    bool submitPause = false;
                    {
                        std::lock_guard lock(traceMutex_);
                        if (!trace_.Matches(parsed->traceId)) {
                            return ErrorResponse(*parsed, "NOT_FOUND",
                                                 "trace_id is not retained", false, false);
                        }
                        if (trace_.Terminal()) {
                            const TracePolicy copied = trace_;
                            const std::uint64_t generation = generation_.load();
                            return "{\"request_id\":" + JsonString(parsed->requestId) +
                                   ",\"state_generation\":" +
                                   std::to_string(generation) +
                                   ",\"status\":\"ok\",\"result\":" +
                                   TraceStatusJson(copied, generation) + "}";
                        }
                        (void)trace_.RequestStop(TraceReason::cancelled);
                        submitPause = !tracePauseSubmitted_;
                        tracePauseSubmitted_ = true;
                    }
                    traceChanged_.notify_all();
                    if (submitPause) {
                        std::lock_guard lock(traceMutex_);
                        if (trace_.Active() && trace_.Matches(parsed->traceId) &&
                            !DbgCmdExec("pause")) {
                            return ErrorResponse(*parsed, "OUTCOME_UNKNOWN",
                                                 "trace cancellation pause was rejected", false,
                                                 true);
                        }
                    }
                    TracePolicy copied;
                    {
                        std::unique_lock lock(traceMutex_);
                        const bool terminal = traceChanged_.wait_until(
                            lock, requestDeadline, [this, parsed] {
                                return pluginState_.load() != PluginState::ready ||
                                       !trace_.Matches(parsed->traceId) || trace_.Terminal();
                            });
                        if (!terminal || !trace_.Matches(parsed->traceId) || !trace_.Terminal()) {
                            return ErrorResponse(*parsed, "TIMEOUT",
                                                 "trace cancellation outcome is unknown", false,
                                                 true);
                        }
                        copied = trace_;
                    }
                    const std::uint64_t generation = generation_.load();
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(generation) +
                           ",\"status\":\"ok\",\"result\":" +
                           TraceStatusJson(copied, generation) + "}";
                }
                if (parsed->method == "debugger.snapshot") {
                    const auto snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false,
                                             false);
                    }
                    PauseObservation pause;
                    {
                        std::lock_guard lock(stateMutex_);
                        if (generation_.load() != *snapshot ||
                            debuggeeState_.load() != DebuggeeState::paused) {
                            return ErrorResponse(*parsed, "BUSY",
                                                 "pause changed before snapshot capture", true,
                                                 false);
                        }
                        pause = latestPause_;
                    }
                    const ThreadContextCapture captured =
                        CaptureThreadContext(parsed->targetThreadId);
                    if (captured.status != ThreadContextStatus::ok) {
                        return ThreadContextErrorResponse(*parsed, captured.status);
                    }
                    std::vector<std::string> names = parsed->registerNames;
                    if (names.empty()) names = {"cip", "csp", "cbp", "eflags"};
                    std::string registers = "{";
                    for (std::size_t index = 0; index < names.size(); ++index) {
                        const auto value = RegisterValue(captured.value.registers, names[index]);
                        if (!value) {
                            return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                                 "unknown register name", false, false);
                        }
                        if (index != 0U) registers.push_back(',');
                        registers += JsonString(names[index]) + ":" +
                                     JsonString(HexValue(*value));
                    }
                    registers += "}";
                    const auto modules = CaptureModuleRecords();
                    if (!modules) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "module snapshot is invalid", true, false);
                    }
                    const duint instructionPointer = captured.value.registers.cip;
                    const auto location = LocationFromModules(instructionPointer, *modules);
                    std::string disassembly = "[";
                    duint address = instructionPointer;
                    for (std::size_t index = 0; index < parsed->instructionCount; ++index) {
                        if (std::chrono::steady_clock::now() >= requestDeadline) {
                            return ErrorResponse(*parsed, "TIMEOUT",
                                                 "compact snapshot exceeded its deadline", true,
                                                 false);
                        }
                        DISASM_INSTR instruction{};
                        DbgDisasmAt(address, &instruction);
                        if (instruction.instr_size <= 0 || instruction.instr_size > 15) {
                            return ErrorResponse(*parsed, "ACCESS_DENIED",
                                                 "instruction bytes are not decodable", false,
                                                 false);
                        }
                        const duint size = static_cast<duint>(instruction.instr_size);
                        if (address > (std::numeric_limits<duint>::max)() - size) {
                            return ErrorResponse(*parsed, "INTERNAL",
                                                 "instruction address overflow", false, false);
                        }
                        if (index != 0U) disassembly.push_back(',');
                        const std::size_t textLength =
                            strnlen_s(instruction.instruction, sizeof(instruction.instruction));
                        disassembly += "{\"address\":" + JsonString(HexValue(address)) +
                                       ",\"size\":" + std::to_string(size) +
                                       ",\"text\":" +
                                       JsonString(std::string_view(instruction.instruction,
                                                                   textLength)) +
                                       "}";
                        address += size;
                    }
                    disassembly += "]";
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during compact snapshot", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(*snapshot) +
                           ",\"status\":\"ok\",\"result\":{\"debuggee_state\":\"paused\"" +
                           std::string(",\"state_generation\":") +
                           std::to_string(*snapshot) + ",\"pause_reason\":" +
                           PauseReasonJson(pause) + ",\"active_thread_id\":" +
                           JsonString(HexValue(captured.value.activeThreadId)) +
                           ",\"thread_id\":" +
                           JsonString(HexValue(captured.value.threadId)) +
                           ",\"current\":" +
                           (captured.value.current ? "true" : "false") +
                           ",\"instruction_pointer\":" + LocationJson(location, *snapshot) +
                           ",\"registers\":" + registers +
                           ",\"disassembly\":" + disassembly + "}}";
                }
                if ((parsed->method == "breakpoints.enable" ||
                     parsed->method == "breakpoints.disable") &&
                    parsed->breakpointKind == "exception") {
                    const auto snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false, false);
                    }
                    const auto chance = ParseExceptionChance(parsed->exceptionChance);
                    const DBGFUNCTIONS* functions = DbgFunctions();
                    if (!chance || functions == nullptr || functions->GetBridgeBp == nullptr) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "typed exception breakpoint API is unavailable",
                                             false, false);
                    }
                    BRIDGEBP before{};
                    if (!functions->GetBridgeBp(
                            bp_exception, static_cast<duint>(parsed->exceptionCode), &before)) {
                        return ErrorResponse(*parsed, "NOT_FOUND",
                                             "exception breakpoint does not exist", false, false);
                    }
                    if (!ExceptionBreakpointOwned(before, parsed->exceptionCode, *chance,
                                                  parsed->managedBreakpointId)) {
                        return ErrorResponse(*parsed, "CONFLICT",
                                             "exception breakpoint is foreign or was modified",
                                             false, false);
                    }
                    const bool enable = parsed->method == "breakpoints.enable";
                    const bool changed = before.enabled != enable;
                    if (changed) {
                        const int status = submitFencedCommand(BreakpointToggleCommand(
                            BreakpointTransitionKind::exception,
                            static_cast<duint>(parsed->exceptionCode), enable));
                        if (status == 1) {
                            return ErrorResponse(*parsed, "BUSY",
                                                 "debugger command queue rejected breakpoint transition",
                                                 true, false);
                        }
                        if (status == 2) {
                            return ErrorResponse(*parsed, "TIMEOUT",
                                                 "breakpoint transition was admitted without confirmation",
                                                 false, true);
                        }
                    }
                    BRIDGEBP after{};
                    if (!functions->GetBridgeBp(
                            bp_exception, static_cast<duint>(parsed->exceptionCode), &after) ||
                        after.enabled != enable ||
                        !ExceptionBreakpointOwned(after, parsed->exceptionCode, *chance,
                                                  parsed->managedBreakpointId) ||
                        !BreakpointConfigurationUnchanged(before, after, false)) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "exception breakpoint transition could not be exactly confirmed",
                                             false, changed);
                    }
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during breakpoint transition",
                                             false, changed);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(*snapshot) +
                           ",\"status\":\"ok\",\"result\":{\"kind\":\"exception\",\"code\":" +
                           JsonString(HexValue(parsed->exceptionCode)) + ",\"chance\":" +
                           JsonString(ExceptionChanceName(*chance)) + ",\"managed_id\":" +
                           JsonString(parsed->managedBreakpointId) + ",\"enabled\":" +
                           (enable ? "true" : "false") + ",\"changed\":" +
                           (changed ? "true" : "false") + "}}";
                }
                if (parsed->method == "breakpoints.exception.set" ||
                    parsed->method == "breakpoints.exception.remove") {
                    const auto snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false, false);
                    }
                    const auto chance = ParseExceptionChance(parsed->exceptionChance);
                    const DBGFUNCTIONS* functions = DbgFunctions();
                    if (!chance || functions == nullptr || functions->GetBridgeBp == nullptr ||
                        functions->BpRefException == nullptr ||
                        functions->BpRefExists == nullptr ||
                        functions->BpSetFieldText == nullptr) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "typed exception breakpoint API is unavailable",
                                             false, false);
                    }
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed before exception breakpoint mutation",
                                             true, false);
                    }
                    const std::string ownedName = ManagedBreakpointName(
                        "exception", parsed->managedBreakpointId);
                    BRIDGEBP before{};
                    const bool beforePresent = functions->GetBridgeBp(
                        bp_exception, static_cast<duint>(parsed->exceptionCode), &before);
                    const bool setting = parsed->method == "breakpoints.exception.set";
                    if (setting && beforePresent) {
                        return ErrorResponse(*parsed, "ALREADY_EXISTS",
                                             "an exception breakpoint already exists for this code",
                                             false, false);
                    }
                    if (!setting) {
                        if (!beforePresent) {
                            return ErrorResponse(*parsed, "NOT_FOUND",
                                                 "exception breakpoint does not exist", false,
                                                 false);
                        }
                        if (!ExceptionBreakpointMatches(before, parsed->exceptionCode, *chance,
                                                        parsed->managedBreakpointId)) {
                            return ErrorResponse(*parsed, "CONFLICT",
                                                 "exception breakpoint is foreign or was modified",
                                                 false, false);
                        }
                    }
                    const auto cleanupCreated = [&]() {
                        BRIDGEBP current{};
                        if (!functions->GetBridgeBp(
                                bp_exception, static_cast<duint>(parsed->exceptionCode),
                                &current)) {
                            return 0;
                        }
                        const std::size_t nameLength =
                            strnlen_s(current.name, sizeof(current.name));
                        if (nameLength >= sizeof(current.name)) return 1;
                        const std::string_view name(
                            current.name, nameLength);
                        if (current.type != bp_exception ||
                            current.addr != static_cast<duint>(parsed->exceptionCode) ||
                            current.typeEx != static_cast<unsigned char>(
                                *chance == ExceptionChance::first
                                    ? ex_firstchance
                                    : (*chance == ExceptionChance::second ? ex_secondchance
                                                                          : ex_all)) ||
                            (name != ownedName && !name.empty())) {
                            return 1;
                        }
                        const int cleanupStatus = submitFencedCommand(
                            "DeleteExceptionBPX " + HexValue(parsed->exceptionCode));
                        if (cleanupStatus != 0) return 2;
                        BRIDGEBP remaining{};
                        return functions->GetBridgeBp(
                                   bp_exception,
                                   static_cast<duint>(parsed->exceptionCode), &remaining)
                                   ? 2
                                   : 0;
                    };
                    const std::string command =
                        setting
                            ? "SetExceptionBPX " + HexValue(parsed->exceptionCode) + ", " +
                                  ExceptionChanceCommand(*chance)
                            : "DeleteExceptionBPX " + HexValue(parsed->exceptionCode);
                    const int commandStatus = submitFencedCommand(command);
                    if (commandStatus == 1) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger command queue rejected exception breakpoint mutation",
                                             true, false);
                    }
                    if (commandStatus == 2) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "exception breakpoint mutation was admitted without confirmation",
                                             false, true);
                    }
                    if (setting) {
                        BP_REF reference{};
                        functions->BpRefException(&reference, parsed->exceptionCode);
                        if (!functions->BpRefExists(&reference) ||
                            !functions->BpSetFieldText(&reference, bpf_name,
                                                       ownedName.c_str())) {
                            const int cleanup = cleanupCreated();
                            return ErrorResponse(
                                *parsed, cleanup == 1 ? "CONFLICT" : "INTERNAL",
                                "exception breakpoint ownership could not be assigned", false,
                                cleanup == 2);
                        }
                        BRIDGEBP installed{};
                        if (!functions->GetBridgeBp(
                                bp_exception, static_cast<duint>(parsed->exceptionCode),
                                &installed) ||
                            !ExceptionBreakpointMatches(installed, parsed->exceptionCode, *chance,
                                                        parsed->managedBreakpointId)) {
                            const int cleanup = cleanupCreated();
                            return ErrorResponse(
                                *parsed, cleanup == 1 ? "CONFLICT" : "INTERNAL",
                                "exception breakpoint setup could not be verified", false,
                                cleanup == 2);
                        }
                    } else {
                        BRIDGEBP remaining{};
                        if (functions->GetBridgeBp(
                                bp_exception, static_cast<duint>(parsed->exceptionCode),
                                &remaining)) {
                            return ErrorResponse(*parsed, "TIMEOUT",
                                                 "exception breakpoint removal could not be confirmed",
                                                 false, true);
                        }
                    }
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during exception breakpoint mutation",
                                             false, true);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(*snapshot) +
                           ",\"status\":\"ok\",\"result\":{\"code\":" +
                           JsonString(HexValue(parsed->exceptionCode)) + ",\"chance\":" +
                           JsonString(ExceptionChanceName(*chance)) + ",\"managed_id\":" +
                           JsonString(parsed->managedBreakpointId) + ",\"present\":" +
                           (setting ? "true" : "false") + "}}";
                }
                const bool addressMethod = parsed->method == "address.resolve" ||
                                           parsed->method == "functions.at" ||
                                           (parsed->method == "symbols.resolve" &&
                                            parsed->addressProvided) ||
                                           parsed->method == "analysis.function" ||
                                           parsed->method == "debugger.run_to_address" ||
                                           parsed->method == "memory.read" ||
                                           parsed->method == "memory.write" ||
                                           parsed->method == "breakpoints.set" ||
                                           parsed->method == "breakpoints.remove" ||
                                           parsed->method == "breakpoints.hardware.set" ||
                                           parsed->method == "breakpoints.hardware.remove" ||
                                           parsed->method == "breakpoints.memory.set" ||
                                           parsed->method == "breakpoints.memory.remove" ||
                                           parsed->method == "breakpoints.conditional.set" ||
                                           parsed->method == "breakpoints.conditional.remove" ||
                                           ((parsed->method == "breakpoints.enable" ||
                                             parsed->method == "breakpoints.disable") &&
                                            parsed->breakpointKind != "exception") ||
                                           parsed->method == "assembly.preview" ||
                                           parsed->method == "assembly.patch" ||
                                           parsed->method == "patches.restore" ||
                                           parsed->method == "disassembly.read" ||
                                           parsed->method == "references.to";
                std::optional<ResolvedLocation> resolvedLocation;
                std::uint64_t resolvedGeneration = 0;
                if (addressMethod) {
                    const std::optional<std::uint64_t> snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false, false);
                    }
                    AddressResolution resolution = ResolveAddress(parsed->address);
                    if (!resolution.location) {
                        return ErrorResponse(*parsed, resolution.code, resolution.message,
                                             resolution.retryable, false);
                    }
                    resolvedLocation = std::move(resolution.location);
                    resolvedGeneration = *snapshot;
                    if (!PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during address resolution", true,
                                             false);
                    }
                }
                if (parsed->discoveryCursorInvalid) {
                    return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                         "cursor does not match the discovery filters", false,
                                         false);
                }
                if (parsed->method == "memory.search") {
                    const std::optional<std::uint64_t> snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false,
                                             false);
                    }
                    if (parsed->cursorGeneration && *parsed->cursorGeneration != *snapshot) {
                        return ErrorResponse(*parsed, "STALE_CURSOR", "cursor generation is stale",
                                             false, false);
                    }
                    const auto modules = CaptureModuleRecords();
                    if (!modules) {
                        return ErrorResponse(*parsed, "INTERNAL", "module snapshot is invalid",
                                             true, false);
                    }

                    duint scopeStart = 0U;
                    std::size_t scopeLength = 0U;
                    if (parsed->memorySearchModuleScope) {
                        const auto module = UniqueModule(*modules, parsed->module);
                        if (!module) {
                            return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                                 "module is missing or ambiguous", false, false);
                        }
                        constexpr duint kMaxModuleBytes = 128U * 1024U * 1024U;
                        if (module->size == 0U || module->size > kMaxModuleBytes ||
                            module->size > (std::numeric_limits<std::size_t>::max)()) {
                            return ErrorResponse(*parsed, "OUTPUT_LIMIT_EXCEEDED",
                                                 "module exceeds the 128 MiB search scope", false,
                                                 false);
                        }
                        scopeStart = module->base;
                        scopeLength = static_cast<std::size_t>(module->size);
                    } else {
                        AddressResolution resolution = ResolveAddress(parsed->address);
                        if (!resolution.location) {
                            return ErrorResponse(*parsed, resolution.code, resolution.message,
                                                 resolution.retryable, false);
                        }
                        scopeStart = resolution.location->address;
                        scopeLength = parsed->length;
                    }
                    if (scopeLength == 0U ||
                        scopeStart > (std::numeric_limits<duint>::max)() -
                                         static_cast<duint>(scopeLength - 1U)) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "memory search scope overflows pointer width", false,
                                             false);
                    }
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during search scope resolution",
                                             true, false);
                    }

                    const std::size_t patternLength = parsed->memoryPattern.bytes.size();
                    const std::size_t totalCandidates =
                        patternLength <= scopeLength ? scopeLength - patternLength + 1U : 0U;
                    if (parsed->cursorIndex > totalCandidates) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT", "cursor is invalid",
                                             false, false);
                    }
                    constexpr std::size_t kCandidateWindow = 1024U * 1024U;
                    constexpr std::size_t kPageBytes = 4096U;
                    const std::size_t remainingCandidates = totalCandidates - parsed->cursorIndex;
                    const std::size_t candidateCount =
                        (std::min)(remainingCandidates, kCandidateWindow);
                    const std::size_t readLength = candidateCount == 0U
                                                       ? 0U
                                                       : candidateCount + patternLength - 1U;
                    std::vector<std::uint8_t> bytes(readLength);
                    std::vector<std::uint8_t> readable(readLength, 0U);
                    const duint readStart =
                        scopeStart + static_cast<duint>(parsed->cursorIndex);
                    for (std::size_t offset = 0U; offset < readLength;) {
                        if (std::chrono::steady_clock::now() >= requestDeadline) {
                            return ErrorResponse(*parsed, "TIMEOUT",
                                                 "memory search exceeded its deadline", true,
                                                 false);
                        }
                        const duint address = readStart + static_cast<duint>(offset);
                        const std::size_t pageRemaining =
                            kPageBytes - static_cast<std::size_t>(address & (kPageBytes - 1U));
                        const std::size_t chunk =
                            (std::min)(pageRemaining, readLength - offset);
                        if (DbgMemRead(address, bytes.data() + offset,
                                       static_cast<duint>(chunk))) {
                            std::fill(readable.begin() + static_cast<std::ptrdiff_t>(offset),
                                      readable.begin() +
                                          static_cast<std::ptrdiff_t>(offset + chunk),
                                      1U);
                        }
                        offset += chunk;
                        if (!PausedSnapshotCurrent(*snapshot)) {
                            return ErrorResponse(*parsed, "BUSY",
                                                 "debugger changed during memory search", true,
                                                 false);
                        }
                    }
                    if (std::chrono::steady_clock::now() >= requestDeadline) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "memory search exceeded its deadline", true, false);
                    }
                    const MemorySearchMatches matches = FindMemoryPattern(
                        bytes, readable, parsed->memoryPattern, candidateCount,
                        parsed->pageLimit);
                    const std::size_t nextOffset = parsed->cursorIndex + matches.nextCandidate;
                    const bool scanComplete = nextOffset >= totalCandidates;
                    const std::size_t consideredReadLength = matches.nextCandidate == 0U
                                                                 ? 0U
                                                                 : (std::min)(
                                                                       readLength,
                                                                       matches.nextCandidate +
                                                                           patternLength - 1U);
                    const std::size_t unreadableBytes = static_cast<std::size_t>(std::count(
                        readable.begin(),
                        readable.begin() + static_cast<std::ptrdiff_t>(consideredReadLength),
                        std::uint8_t{0U}));
                    std::string items = "[";
                    for (std::size_t index = 0U; index < matches.offsets.size(); ++index) {
                        if (index != 0U) items.push_back(',');
                        const duint address = readStart + static_cast<duint>(matches.offsets[index]);
                        items += "{\"location\":" +
                                 LocationJson(LocationFromModules(address, *modules), *snapshot) +
                                 "}";
                    }
                    items += "]";
                    std::string mask;
                    mask.reserve(parsed->memoryPattern.exact.size());
                    for (const std::uint8_t exact : parsed->memoryPattern.exact) {
                        mask.push_back(exact != 0U ? 'x' : '?');
                    }
                    const std::string next =
                        scanComplete
                            ? "null"
                            : JsonString(DiscoveryCursor(*parsed, *snapshot, nextOffset));
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during memory search", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(*snapshot) +
                           ",\"status\":\"ok\",\"result\":{\"scope\":{\"start\":" +
                           LocationJson(LocationFromModules(scopeStart, *modules), *snapshot) +
                           ",\"length\":" + std::to_string(scopeLength) +
                           "},\"pattern_hex\":" + JsonString(Hex(parsed->memoryPattern.bytes)) +
                           ",\"mask\":" + JsonString(mask) + ",\"items\":" + items +
                           ",\"next_cursor\":" + next +
                           ",\"scan_complete\":" + (scanComplete ? "true" : "false") +
                           ",\"read_completeness\":" +
                           JsonString(unreadableBytes == 0U ? "complete"
                                                            : "partial_unreadable") +
                           ",\"bytes_scanned\":" +
                           std::to_string(matches.nextCandidate) +
                           ",\"unreadable_bytes\":" + std::to_string(unreadableBytes) +
                           ",\"state_generation\":" + std::to_string(*snapshot) + "}}";
                }
                if (parsed->method == "address.resolve") {
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(resolvedGeneration) +
                           ",\"status\":\"ok\",\"result\":" +
                           LocationJson(*resolvedLocation, resolvedGeneration) + "}";
                }
                if (parsed->method == "functions.at") {
                    const auto modules = CaptureModuleRecords();
                    if (!modules) {
                        return ErrorResponse(*parsed, "INTERNAL", "module snapshot is invalid",
                                             true, false);
                    }
                    Script::Function::FunctionInfo function{};
                    const bool found = Script::Function::GetInfo(resolvedLocation->address,
                                                                  &function);
                    std::string functionJson = "null";
                    if (found) {
                        const std::string functionModule(
                            function.mod, strnlen_s(function.mod, sizeof(function.mod)));
                        const auto owner = UniqueModule(*modules, functionModule);
                        if (!owner || function.rvaStart > function.rvaEnd ||
                            function.rvaEnd >= owner->size ||
                            owner->base > (std::numeric_limits<duint>::max)() -
                                              function.rvaEnd) {
                            return ErrorResponse(*parsed, "INTERNAL",
                                                 "function record is outside its module", false,
                                                 false);
                        }
                        const duint startAddress = owner->base + function.rvaStart;
                        const duint endAddress = owner->base + function.rvaEnd;
                        if (resolvedLocation->address < startAddress ||
                            resolvedLocation->address > endAddress) {
                            return ErrorResponse(*parsed, "INTERNAL",
                                                 "function record does not contain the query",
                                                 false, false);
                        }
                        functionJson =
                            "{\"start\":" +
                            LocationJson(LocationFromModules(startAddress, *modules),
                                         resolvedGeneration) +
                            ",\"end_inclusive\":" +
                            LocationJson(LocationFromModules(endAddress, *modules),
                                         resolvedGeneration) +
                            ",\"instruction_count\":" +
                            std::to_string(function.instructioncount) + ",\"manual\":" +
                            (function.manual ? "true" : "false") +
                            ",\"contains_query\":true}";
                    }
                    if (!PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during function lookup", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(resolvedGeneration) +
                           ",\"status\":\"ok\",\"result\":{\"query\":" +
                           LocationJson(*resolvedLocation, resolvedGeneration) +
                           ",\"found\":" + (found ? "true" : "false") +
                           ",\"function\":" + functionJson +
                           ",\"completeness\":\"known_only\",\"state_generation\":" +
                           std::to_string(resolvedGeneration) + "}}";
                }
                if (parsed->method == "assembly.preview" ||
                    parsed->method == "assembly.patch" ||
                    parsed->method == "patches.restore") {
                    const duint address = resolvedLocation->address;
                    const DBGFUNCTIONS* functions = DbgFunctions();
                    const bool preview = parsed->method == "assembly.preview";
                    const bool patch = parsed->method == "assembly.patch";
                    if (functions == nullptr ||
                        (preview && functions->Assemble == nullptr) ||
                        (patch &&
                         (functions->Assemble == nullptr || functions->PatchInRange == nullptr ||
                          functions->PatchGetEx == nullptr || functions->MemPatch == nullptr)) ||
                        (!preview && !patch &&
                         (functions->PatchInRange == nullptr ||
                          functions->PatchGetEx == nullptr ||
                          functions->PatchRestoreRange == nullptr))) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "assembler or patch APIs are unavailable", false,
                                             false);
                    }
                    std::array<unsigned char, 16> assembled{};
                    int assembledSize = 0;
                    if (parsed->method != "patches.restore") {
                        std::array<char, MAX_ERROR_SIZE> nativeError{};
                        if (!functions->Assemble(address, assembled.data(), &assembledSize,
                                                 parsed->instruction.c_str(),
                                                 nativeError.data()) ||
                            assembledSize < 1 || assembledSize > 16) {
                            const std::string boundedError = BoundedNativeError(nativeError);
                            const std::string message = boundedError.empty()
                                ? "instruction could not be assembled"
                                : "instruction could not be assembled: " + boundedError;
                            return ErrorResponse(*parsed, "INVALID_ARGUMENT", message, false,
                                                 false);
                        }
                    }
                    if (parsed->method == "assembly.preview") {
                        if (!PausedSnapshotCurrent(resolvedGeneration)) {
                            return ErrorResponse(*parsed, "BUSY",
                                                 "debugger changed during assembly preview", true,
                                                 false);
                        }
                        const std::span<const unsigned char> bytes(
                            assembled.data(), static_cast<std::size_t>(assembledSize));
                        return "{\"request_id\":" + JsonString(parsed->requestId) +
                               ",\"state_generation\":" +
                               std::to_string(resolvedGeneration) +
                               ",\"status\":\"ok\",\"result\":{\"address\":" +
                               JsonString(HexValue(address)) + ",\"location\":" +
                               LocationJson(*resolvedLocation, resolvedGeneration) +
                               ",\"instruction\":" + JsonString(parsed->instruction) +
                               ",\"bytes_hex\":" + JsonString(Hex(bytes)) +
                               ",\"byte_count\":" + std::to_string(bytes.size()) +
                               ",\"state_generation\":" +
                               std::to_string(resolvedGeneration) + "}}";
                    }
                    const std::size_t spanSize = parsed->expectedBytes.size();
                    if (!PatchRangeValid(address, spanSize)) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "patch span is invalid for this architecture", false,
                                             false);
                    }
                    if (!PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed after patch address resolution",
                                             true, false);
                    }
                    const duint end = address + static_cast<duint>(spanSize - 1U);
                    std::vector<unsigned char> current(spanSize);
                    if (!DbgMemRead(address, current.data(), static_cast<duint>(spanSize))) {
                        return ErrorResponse(*parsed, "ACCESS_DENIED",
                                             "patch span is not fully readable", false, false);
                    }
                    if (parsed->method == "assembly.patch") {
                        if (functions->PatchInRange(address, end)) {
                            return ErrorResponse(*parsed, "CONFLICT",
                                                 "patch span already contains tracked patches",
                                                 false, false);
                        }
                        if (current != parsed->expectedBytes) {
                            return ErrorResponse(*parsed, "CONFLICT",
                                                 "current memory does not match expected bytes",
                                                 false, false);
                        }
                        const std::span<const unsigned char> instructionBytes(
                            assembled.data(), static_cast<std::size_t>(assembledSize));
                        const auto finalBytes = PreparePatchBytes(
                            instructionBytes, parsed->expectedBytes, parsed->fillNop);
                        if (!finalBytes) {
                            return ErrorResponse(
                                *parsed, "INVALID_ARGUMENT",
                                "assembled instruction does not fit the expected span or requires fill_nop",
                                false, false);
                        }
                        if (*finalBytes == parsed->expectedBytes) {
                            return ErrorResponse(*parsed, "CONFLICT",
                                                 "assembled patch would not change memory", false,
                                                 false);
                        }
                        if (!functions->MemPatch(address, finalBytes->data(),
                                                 static_cast<duint>(finalBytes->size()))) {
                            return ErrorResponse(*parsed, "ACCESS_DENIED",
                                                 "x64dbg rejected the tracked patch", false,
                                                 false);
                        }
                        std::vector<unsigned char> verified(spanSize);
                        if (!DbgMemRead(address, verified.data(), static_cast<duint>(spanSize)) ||
                            verified != *finalBytes) {
                            return ErrorResponse(*parsed, "INTERNAL",
                                                 "tracked patch read-back did not match", false,
                                                 true);
                        }
                        std::size_t changed = 0U;
                        for (std::size_t index = 0; index < spanSize; ++index) {
                            DBGPATCHINFO record{};
                            const bool present = functions->PatchGetEx(
                                address + static_cast<duint>(index), &record);
                            if ((*finalBytes)[index] != parsed->expectedBytes[index]) {
                                ++changed;
                                if (!present || !PatchRecordMatches(
                                                    record, address + static_cast<duint>(index),
                                                    parsed->expectedBytes[index],
                                                    (*finalBytes)[index])) {
                                    return ErrorResponse(*parsed, "INTERNAL",
                                                         "tracked patch metadata did not match",
                                                         false, true);
                                }
                            } else if (present) {
                                return ErrorResponse(*parsed, "INTERNAL",
                                                     "unexpected patch metadata appeared", false,
                                                     true);
                            }
                        }
                        if (!functions->PatchInRange(address, end) ||
                            !PausedSnapshotCurrent(resolvedGeneration)) {
                            return ErrorResponse(*parsed, "INTERNAL",
                                                 "tracked patch postcondition was not stable",
                                                 false, true);
                        }
                        return "{\"request_id\":" + JsonString(parsed->requestId) +
                               ",\"state_generation\":" +
                               std::to_string(resolvedGeneration) +
                               ",\"status\":\"ok\",\"result\":{\"address\":" +
                               JsonString(HexValue(address)) + ",\"location\":" +
                               LocationJson(*resolvedLocation, resolvedGeneration) +
                               ",\"instruction\":" + JsonString(parsed->instruction) +
                               ",\"original_bytes_hex\":" +
                               JsonString(Hex(parsed->expectedBytes)) +
                               ",\"assembled_bytes_hex\":" + JsonString(Hex(instructionBytes)) +
                               ",\"patched_bytes_hex\":" + JsonString(Hex(*finalBytes)) +
                               ",\"assembled_length\":" +
                               std::to_string(instructionBytes.size()) +
                               ",\"span_length\":" + std::to_string(spanSize) +
                               ",\"nop_padding\":" +
                               std::to_string(spanSize - instructionBytes.size()) +
                               ",\"changed_bytes\":" + std::to_string(changed) +
                               ",\"patch_tracked\":true,\"state_generation\":" +
                               std::to_string(resolvedGeneration) + "}}";
                    }
                    if (current != parsed->expectedBytes) {
                        return ErrorResponse(*parsed, "CONFLICT",
                                             "current memory does not match expected patched bytes",
                                             false, false);
                    }
                    for (std::size_t index = 0; index < spanSize; ++index) {
                        DBGPATCHINFO record{};
                        const bool present = functions->PatchGetEx(
                            address + static_cast<duint>(index), &record);
                        if (parsed->expectedBytes[index] !=
                            parsed->expectedOriginalBytes[index]) {
                            if (!present || !PatchRecordMatches(
                                                record, address + static_cast<duint>(index),
                                                parsed->expectedOriginalBytes[index],
                                                parsed->expectedBytes[index])) {
                                return ErrorResponse(*parsed, "CONFLICT",
                                                     "patch metadata does not match expected bytes",
                                                     false, false);
                            }
                        } else if (present) {
                            return ErrorResponse(*parsed, "CONFLICT",
                                                 "patch span contains unexpected metadata", false,
                                                 false);
                        }
                    }
                    functions->PatchRestoreRange(address, end);
                    std::vector<unsigned char> restored(spanSize);
                    if (!DbgMemRead(address, restored.data(), static_cast<duint>(spanSize)) ||
                        restored != parsed->expectedOriginalBytes ||
                        functions->PatchInRange(address, end) ||
                        !PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "patch restore postcondition did not match", false,
                                             true);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(resolvedGeneration) +
                           ",\"status\":\"ok\",\"result\":{\"address\":" +
                           JsonString(HexValue(address)) + ",\"location\":" +
                           LocationJson(*resolvedLocation, resolvedGeneration) +
                           ",\"restored_bytes_hex\":" +
                           JsonString(Hex(parsed->expectedOriginalBytes)) +
                           ",\"bytes_restored\":" + std::to_string(spanSize) +
                           ",\"patch_tracked\":false,\"state_generation\":" +
                           std::to_string(resolvedGeneration) + "}}";
                }
                if (parsed->method == "debugger.run_to_address") {
                    const duint target = resolvedLocation->address;
                    if (!PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed before run-to validation", true,
                                             false);
                    }
                    REGDUMP_AVX512 initial{};
                    if (!DbgGetRegDumpEx(&initial, sizeof(initial))) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "register snapshot is unavailable", true, false);
                    }
                    DISASM_INSTR targetInstruction{};
                    DbgDisasmAt(target, &targetInstruction);
                    if (targetInstruction.instr_size <= 0 || targetInstruction.instr_size > 15) {
                        return ErrorResponse(*parsed, "ACCESS_DENIED",
                                             "run-to target is not decodable", false, false);
                    }
                    if ((DbgGetBpxTypeAt(target) & bp_normal) != 0) {
                        return ErrorResponse(*parsed, "CONFLICT",
                                             "run-to target already has a software breakpoint",
                                             false, false);
                    }
                    if (initial.regcontext.cip == target) {
                        PauseObservation pause;
                        {
                            std::lock_guard lock(stateMutex_);
                            pause = latestPause_;
                        }
                        return "{\"request_id\":" + JsonString(parsed->requestId) +
                               ",\"state_generation\":" +
                               std::to_string(resolvedGeneration) +
                               ",\"status\":\"ok\",\"result\":{\"completed\":true," +
                               "\"resumed\":false,\"target\":" +
                               LocationJson(*resolvedLocation, resolvedGeneration) +
                               ",\"debuggee_state\":\"paused\",\"pause_reason\":" +
                               PauseReasonJson(pause) +
                               ",\"instruction_pointer\":" + JsonString(HexValue(target)) +
                               ",\"interruption\":null,\"temporary_breakpoint_cleaned\":true," +
                               "\"state_generation\":" +
                               std::to_string(resolvedGeneration) + "}}";
                    }

                    const DBGFUNCTIONS* functions = DbgFunctions();
                    if (functions == nullptr || functions->GetBridgeBp == nullptr) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "software breakpoint read-back is unavailable",
                                             false, false);
                    }
                    const std::string ownedName = RunToBreakpointName(parsed->operationId);
                    const auto ownsBreakpoint = [&ownedName, target](const BRIDGEBP& breakpoint) {
                        return RunToBreakpointOwned(breakpoint, target, ownedName);
                    };
                    const auto cleanupOwned = [this, functions, target, &ownsBreakpoint](
                                                  const auto deadline) {
                        BRIDGEBP current{};
                        if (!functions->GetBridgeBp(bp_normal, target, &current)) {
                            return (DbgGetBpxTypeAt(target) & bp_normal) == 0 ? 0 : 2;
                        }
                        if (!ownsBreakpoint(current)) return 1;
                        const std::string command = "bc " + HexValue(target);
                        if (!DbgCmdExec(command.c_str())) return 2;
                        while (pluginState_.load() == PluginState::ready &&
                               std::chrono::steady_clock::now() < deadline) {
                            BRIDGEBP observed{};
                            if (!functions->GetBridgeBp(bp_normal, target, &observed)) {
                                return (DbgGetBpxTypeAt(target) & bp_normal) == 0 ? 0 : 2;
                            }
                            if (!ownsBreakpoint(observed)) return 1;
                            std::this_thread::sleep_for(std::chrono::milliseconds(5));
                        }
                        return 2;
                    };

                    std::uint64_t fenceToken = 0U;
                    for (int attempt = 0; attempt < 4 && fenceToken == 0U; ++attempt) {
                        if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&fenceToken),
                                            static_cast<ULONG>(sizeof(fenceToken)),
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
                            fenceToken = 0U;
                        }
                    }
                    if (fenceToken == 0U || !commandFence_.Arm(fenceToken)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "run-to command fence is unavailable", true, false);
                    }
                    const std::string setCommand =
                        RunToBreakpointSetCommand(target, ownedName);
                    if (!DbgCmdExec(setCommand.c_str())) {
                        commandFence_.Cancel(fenceToken);
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger command queue rejected run-to setup", true,
                                             false);
                    }
                    std::ostringstream fenceText;
                    fenceText << "x64dbg_mcp_fence_internal " << std::hex << std::nouppercase
                              << std::setw(16) << std::setfill('0') << fenceToken;
                    if (!DbgCmdExec(fenceText.str().c_str())) {
                        commandFence_.Cancel(fenceToken);
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "run-to setup was admitted without a completion fence",
                                             false, true);
                    }
                    if (commandFence_.Wait(fenceToken, requestDeadline) !=
                        CommandFenceWait::completed) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "run-to setup was not command-queue confirmed", false,
                                             true);
                    }
                    BRIDGEBP installed{};
                    const bool installedPresent =
                        functions->GetBridgeBp(bp_normal, target, &installed);
                    if (!installedPresent || !ownsBreakpoint(installed) || !installed.enabled ||
                        !installed.active) {
                        const int cleanup = cleanupOwned(requestDeadline);
                        const std::size_t installedNameLength =
                            installedPresent
                                ? strnlen_s(installed.name, sizeof(installed.name))
                                : 0U;
                        const std::string installedName =
                            installedPresent
                                ? BoundedNativeError(std::span<const char>(
                                      installed.name,
                                      (std::min)(installedNameLength, sizeof(installed.name))))
                                : std::string{};
                        const std::string details =
                            std::string("{\"phase\":\"setup_readback\",\"present\":") +
                            (installedPresent ? "true" : "false") +
                            ",\"name\":" +
                            (installedPresent ? JsonString(installedName) : "null") +
                            ",\"type\":" + std::to_string(installed.type) +
                            ",\"enabled\":" + (installed.enabled ? "true" : "false") +
                            ",\"active\":" + (installed.active ? "true" : "false") +
                            ",\"singleshoot\":" +
                            (installed.singleshoot ? "true" : "false") +
                            ",\"cleanup\":" + std::to_string(cleanup) +
                            (cleanup == 2 ? ",\"outcome\":\"unknown\"}" : "}");
                        return ErrorResponseWithDetails(
                            *parsed, cleanup == 1 ? "CONFLICT" : "INTERNAL",
                            "run-to breakpoint setup could not be verified", false, details);
                    }
                    if (!PausedSnapshotCurrent(resolvedGeneration)) {
                        const int cleanup = cleanupOwned(requestDeadline);
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during run-to setup", false,
                                             cleanup != 0);
                    }

                    const std::uint64_t beforeRun = generation_.load();
                    if (!DbgCmdExec("run")) {
                        const int cleanup = cleanupOwned(requestDeadline);
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger command queue rejected run-to execution",
                                             false, cleanup != 0);
                    }
                    const auto now = std::chrono::steady_clock::now();
                    const auto requestedDeadline =
                        now + std::chrono::milliseconds(parsed->runToTimeoutMs);
                    const auto actionDeadline =
                        (std::min)(requestedDeadline,
                                   requestDeadline - std::chrono::seconds(3));
                    bool timedOut = false;
                    bool processExited = false;
                    PauseObservation finalPause;
                    std::uint64_t finalGeneration = 0U;
                    {
                        std::unique_lock lock(stateMutex_);
                        const bool terminal = stateChanged_.wait_until(
                            lock, actionDeadline, [this, beforeRun] {
                                const DebuggeeState state = debuggeeState_.load();
                                return pluginState_.load() != PluginState::ready ||
                                       pausedGeneration_.load() > beforeRun ||
                                       absentGeneration_.load() > beforeRun ||
                                       state == DebuggeeState::exited;
                            });
                        if (pluginState_.load() != PluginState::ready) {
                            return ErrorResponse(*parsed, "CANCELLED",
                                                 "plugin drained during run-to", true, true);
                        }
                        const DebuggeeState state = debuggeeState_.load();
                        processExited = absentGeneration_.load() > beforeRun ||
                                        state == DebuggeeState::absent ||
                                        state == DebuggeeState::exited;
                        if (pausedGeneration_.load() > beforeRun) {
                            finalPause = latestPause_;
                            finalGeneration = pausedGeneration_.load();
                        } else if (!processExited && !terminal) {
                            timedOut = true;
                        }
                    }
                    if (processExited) {
                        if (!WaitForState(DebuggeeState::absent, beforeRun, requestDeadline) &&
                            debuggeeState_.load() != DebuggeeState::absent) {
                            return ErrorResponse(*parsed, "TIMEOUT",
                                                 "debuggee exited before run-to cleanup was confirmed",
                                                 false, true);
                        }
                        const std::uint64_t stoppedGeneration = absentGeneration_.load();
                        return "{\"request_id\":" + JsonString(parsed->requestId) +
                               ",\"state_generation\":" +
                               std::to_string(stoppedGeneration) +
                               ",\"status\":\"ok\",\"result\":{\"completed\":false," +
                               "\"resumed\":true,\"target\":" +
                               LocationJson(*resolvedLocation, resolvedGeneration) +
                               ",\"debuggee_state\":\"absent\",\"pause_reason\":null," +
                               "\"instruction_pointer\":null,\"interruption\":\"process_exited\"," +
                               "\"temporary_breakpoint_cleaned\":true,\"state_generation\":" +
                               std::to_string(stoppedGeneration) + "}}";
                    }
                    if (timedOut) {
                        const std::uint64_t beforePause = generation_.load();
                        if (!DbgCmdExec("pause") ||
                            !WaitForState(DebuggeeState::paused, beforePause, requestDeadline)) {
                            return ErrorResponse(*parsed, "TIMEOUT",
                                                 "run-to timeout could not be paused for cleanup",
                                                 false, true);
                        }
                        {
                            std::lock_guard lock(stateMutex_);
                            finalPause = latestPause_;
                            finalGeneration = pausedGeneration_.load();
                        }
                    }
                    if (finalGeneration == 0U || debuggeeState_.load() != DebuggeeState::paused) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "run-to outcome was not callback-confirmed", false,
                                             true);
                    }
                    const bool completed =
                        !timedOut && finalPause.kind == PauseReasonKind::breakpoint &&
                        finalPause.hasAddress && finalPause.address == target &&
                        finalPause.breakpointType == bp_normal;
                    const int cleanup = cleanupOwned(requestDeadline);
                    if (cleanup != 0) {
                        return ErrorResponse(*parsed, cleanup == 1 ? "CONFLICT" : "TIMEOUT",
                                             cleanup == 1
                                                 ? "run-to target breakpoint ownership changed"
                                                 : "run-to temporary breakpoint cleanup was not confirmed",
                                             false, true);
                    }
                    REGDUMP_AVX512 finalDump{};
                    if (!DbgGetRegDumpEx(&finalDump, sizeof(finalDump)) ||
                        !PauseObservationCurrent(finalGeneration, finalPause.generation)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed after run-to cleanup", true, false);
                    }
                    const char* interruption = nullptr;
                    if (!completed) {
                        if (timedOut) {
                            interruption = "timeout";
                        } else {
                            switch (finalPause.kind) {
                            case PauseReasonKind::breakpoint: interruption = "breakpoint"; break;
                            case PauseReasonKind::exception: interruption = "exception"; break;
                            case PauseReasonKind::step: interruption = "step"; break;
                            case PauseReasonKind::userPause: interruption = "user_pause"; break;
                            case PauseReasonKind::processCreated:
                            case PauseReasonKind::systemBreakpoint:
                            case PauseReasonKind::unknown: interruption = "unknown"; break;
                            }
                        }
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(finalGeneration) +
                           ",\"status\":\"ok\",\"result\":{\"completed\":" +
                           (completed ? "true" : "false") +
                           ",\"resumed\":true,\"target\":" +
                           LocationJson(*resolvedLocation, resolvedGeneration) +
                           ",\"debuggee_state\":\"paused\",\"pause_reason\":" +
                           PauseReasonJson(finalPause) +
                           ",\"instruction_pointer\":" +
                           JsonString(HexValue(finalDump.regcontext.cip)) +
                           ",\"interruption\":" +
                           (interruption == nullptr ? "null" : JsonString(interruption)) +
                           ",\"temporary_breakpoint_cleaned\":true,\"state_generation\":" +
                           std::to_string(finalGeneration) + "}}";
                }
                if (parsed->method == "analysis.function") {
                    if (!resolvedLocation->module || !resolvedLocation->moduleBase ||
                        !resolvedLocation->rva) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "analysis address must resolve inside one loaded module",
                                             false, false);
                    }
                    const auto modules = CaptureModuleRecords();
                    const auto module = modules ? UniqueModule(*modules, *resolvedLocation->module)
                                                : std::optional<ModuleRecord>{};
                    if (!module) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "loaded module changed during analysis validation",
                                             true, false);
                    }
                    if (module->size == 0U || module->size > kMaxAnalysisModuleBytes) {
                        return ErrorResponse(*parsed, "OUTPUT_LIMIT_EXCEEDED",
                                             "analysis module exceeds the 128 MiB bound", false,
                                             false);
                    }
                    if (!PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed before analysis submission", true,
                                             false);
                    }

                    Script::Function::FunctionInfo beforeInfo{};
                    const bool alreadyKnown =
                        Script::Function::GetInfo(resolvedLocation->address, &beforeInfo);
                    std::uint64_t fenceToken = 0U;
                    for (int attempt = 0; attempt < 4 && fenceToken == 0U; ++attempt) {
                        if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&fenceToken),
                                            static_cast<ULONG>(sizeof(fenceToken)),
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
                            fenceToken = 0U;
                        }
                    }
                    if (fenceToken == 0U || !commandFence_.Arm(fenceToken)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "analysis command fence is unavailable", true, false);
                    }
                    const std::string analysisCommand =
                        "analr " + HexValue(resolvedLocation->address);
                    if (!DbgCmdExec(analysisCommand.c_str())) {
                        commandFence_.Cancel(fenceToken);
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger command queue rejected analysis", true,
                                             false);
                    }
                    std::ostringstream fenceText;
                    fenceText << "x64dbg_mcp_fence_internal " << std::hex
                              << std::nouppercase << std::setw(16) << std::setfill('0')
                              << fenceToken;
                    if (!DbgCmdExec(fenceText.str().c_str())) {
                        commandFence_.Cancel(fenceToken);
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "analysis was queued but its completion fence was rejected",
                                             false, true);
                    }
                    if (commandFence_.Wait(fenceToken, requestDeadline) !=
                        CommandFenceWait::completed) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "analysis completion was not command-queue confirmed",
                                             false, true);
                    }
                    if (!PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed while analysis was running", false,
                                             true);
                    }
                    Script::Function::FunctionInfo function{};
                    if (!Script::Function::GetInfo(resolvedLocation->address, &function)) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "analysis did not produce a function marker", false,
                                             false);
                    }
                    const std::string functionModule(
                        function.mod, strnlen_s(function.mod, sizeof(function.mod)));
                    const auto functionOwner = UniqueModule(*modules, functionModule);
                    if (!functionOwner ||
                        !Utf8OrdinalEqualsIgnoreCase(functionOwner->name,
                                                     *resolvedLocation->module) ||
                        function.rvaStart > function.rvaEnd ||
                        function.rvaEnd >= functionOwner->size ||
                        *resolvedLocation->rva < function.rvaStart ||
                        *resolvedLocation->rva > function.rvaEnd) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "analysis returned an invalid function marker", false,
                                             false);
                    }
                    const auto start = LocationFromModules(
                        functionOwner->base + function.rvaStart, *modules);
                    const auto end = LocationFromModules(
                        functionOwner->base + function.rvaEnd, *modules);
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" +
                           std::to_string(resolvedGeneration) +
                           ",\"status\":\"ok\",\"result\":{\"requested_location\":" +
                           LocationJson(*resolvedLocation, resolvedGeneration) +
                           ",\"function\":{\"start\":" +
                           LocationJson(start, resolvedGeneration) + ",\"end\":" +
                           LocationJson(end, resolvedGeneration) +
                           ",\"instruction_count\":" +
                           std::to_string(function.instructioncount) +
                           ",\"manual\":" + (function.manual ? "true" : "false") +
                           "},\"already_known\":" +
                           (alreadyKnown ? "true" : "false") +
                           ",\"state_generation\":" +
                           std::to_string(resolvedGeneration) + "}}";
                }
                if (parsed->method == "debuggee.attach") {
                    if (debuggeeState_.load() != DebuggeeState::absent || DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "attach requires no current debuggee", false, false);
                    }
                    const DWORD sidecarId = sidecarProcess_ == nullptr
                                                ? 0U
                                                : GetProcessId(sidecarProcess_);
                    if (parsed->targetProcessId == GetCurrentProcessId() ||
                        (sidecarId != 0U && parsed->targetProcessId == sidecarId)) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "cannot attach to the debugger host or its owned sidecar",
                                             false, false);
                    }
                    const std::uint64_t before = generation_.load();
                    const std::string command =
                        "attach " + HexValue(parsed->targetProcessId);
                    if (!DbgCmdExec(command.c_str())) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger command queue rejected attach", true,
                                             false);
                    }
                    const auto attachDeadline =
                        requestDeadline > std::chrono::steady_clock::now() +
                                              std::chrono::milliseconds(500)
                            ? requestDeadline - std::chrono::milliseconds(500)
                            : requestDeadline;
                    if (!WaitForAttachPause(parsed->targetProcessId, before,
                                            attachDeadline)) {
                        std::ostringstream diagnostic;
                        diagnostic << "attach confirmation mismatch: requested="
                                   << HexValue(parsed->targetProcessId)
                                   << ", callback=" << HexValue(attachProcessId_.load())
                                   << ", current=" << HexValue(processId_.load())
                                   << ", attach_generation=" << attachGeneration_.load()
                                   << ", pause_generation=" << pausedGeneration_.load();
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             diagnostic.str(),
                                             false, true);
                    }
                    const std::uint64_t confirmed = ObservedGeneration(DebuggeeState::paused);
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(confirmed) +
                           ",\"status\":\"ok\",\"result\":{\"debuggee_state\":\"paused\"" +
                           ",\"session_origin\":\"attached\",\"process_id\":" +
                           JsonString(HexValue(parsed->targetProcessId)) +
                           ",\"state_generation\":" + std::to_string(confirmed) + "}}";
                }
                if (parsed->method == "debuggee.launch" ||
                    parsed->method == "debuggee.launch_dll") {
                    const bool dllLaunch = parsed->method == "debuggee.launch_dll";
                    if (debuggeeState_.load() != DebuggeeState::absent || DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "launch requires no current debuggee", false, false);
                    }
                    const std::optional<std::string> executable =
                        CanonicalUtf8Path(parsed->path, false);
                    if (!executable) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "path must name an existing absolute regular file",
                                             false, false);
                    }
                    const std::u8string executableEncoded(
                        reinterpret_cast<const char8_t*>(executable->data()), executable->size());
                    const std::filesystem::path executablePath(executableEncoded);
                    const auto pe = ReadPeIdentity(executablePath);
                    if (!pe || !PeMatchesBackend(*pe, dllLaunch)) {
                        return ErrorResponse(
                            *parsed, "INVALID_ARGUMENT",
                            dllLaunch
                                ? "path must name an architecture-matched PE DLL"
                                : "path must name an architecture-matched PE executable",
                            false, false);
                    }
                    if (dllLaunch) {
                        const int dllPathLength = MultiByteToWideChar(
                            CP_UTF8, MB_ERR_INVALID_CHARS, executable->data(),
                            static_cast<int>(executable->size()), nullptr, 0);
                        // x64dbg hands the target to loaddll.exe through a
                        // fixed WCHAR[512] mapping, including the trailing NUL.
                        if (dllPathLength <= 0 || dllPathLength >= 512) {
                            return ErrorResponse(
                                *parsed, "INVALID_ARGUMENT",
                                "DLL path exceeds the x64dbg loader mapping bound", false,
                                false);
                        }
                        std::error_code loaderError;
                        const std::filesystem::path loader =
                            ModuleDirectory().parent_path() / L"loaddll.exe";
                        if (!std::filesystem::is_regular_file(loader, loaderError) || loaderError) {
                            return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                                 "x64dbg loaddll.exe is unavailable", false,
                                                 false);
                        }
                    }
                    std::string requestedDirectory = parsed->workingDirectory;
                    if (requestedDirectory.empty()) {
                        const std::u8string parent = executablePath.parent_path().u8string();
                        requestedDirectory.assign(reinterpret_cast<const char*>(parent.data()),
                                                  parent.size());
                    }
                    const std::optional<std::string> workingDirectory =
                        CanonicalUtf8Path(requestedDirectory, true);
                    if (!workingDirectory) {
                        return ErrorResponse(
                            *parsed, "INVALID_ARGUMENT",
                            "working_directory must name an existing absolute directory", false,
                            false);
                    }
                    const std::optional<std::string> renderedArguments = dllLaunch
                        ? std::optional<std::string>(std::string{})
                        : RenderWindowsArguments(parsed->launchArguments);
                    if (!renderedArguments) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "arguments exceed native quoting bounds", false,
                                             false);
                    }
                    std::string processCommandLine = QuoteWindowsArgument(*executable);
                    if (!renderedArguments->empty()) {
                        processCommandLine.push_back(' ');
                        processCommandLine += *renderedArguments;
                    }
                    const int wideLength = processCommandLine.empty()
                                               ? 0
                                               : MultiByteToWideChar(
                                                     CP_UTF8, MB_ERR_INVALID_CHARS,
                                                     processCommandLine.data(),
                                                     static_cast<int>(processCommandLine.size()),
                                                     nullptr, 0);
                    if ((!processCommandLine.empty() && wideLength <= 0) ||
                        wideLength > 32766) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "rendered Windows command line is invalid or too long",
                                             false, false);
                    }
                    const std::optional<std::string> command =
                        BuildInitCommand(*executable, "", *workingDirectory);
                    if (!command) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "launch does not fit the x64dbg command buffer", false,
                                             false);
                    }
                    const std::uint64_t before = generation_.load();
                    if (!DbgCmdExec(command->c_str())) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger command queue rejected the launch", true,
                                             false);
                    }
                    const auto launchDeadline =
                        requestDeadline > std::chrono::steady_clock::now() +
                                              std::chrono::milliseconds(500)
                            ? requestDeadline - std::chrono::milliseconds(500)
                            : requestDeadline;
                    if (!WaitForActionableLaunchPause(before, launchDeadline)) {
#ifndef _WIN64
                        if (!dllLaunch && HasPifExtension(*executable)) {
                            return ErrorResponse(
                                *parsed, "TIMEOUT",
                                "x32dbg handles .PIF with ResolveShortcut before CreateProcessW; "
                                "rename a hash-identical analysis copy to .exe, record its "
                                "provenance, and try again",
                                false, true);
                        }
#endif
                        return ErrorResponse(
                            *parsed, "TIMEOUT",
                            "x64dbg accepted the launch command, but no debug session or "
                            "actionable pause was observed before the deadline; inspect the "
                            "x64dbg log for native loader diagnostics",
                            false, true);
                    }
                    const std::uint64_t confirmed = ObservedGeneration(DebuggeeState::paused);
                    if (dllLaunch) {
                        const auto modules = CaptureModuleRecords();
                        std::optional<std::string> loaderModule;
                        if (modules) {
#ifdef _WIN64
                            constexpr std::string_view loaderPrefix = "dllloader64_";
#else
                            constexpr std::string_view loaderPrefix = "dllloader32_";
#endif
                            for (const auto& module : *modules) {
                                std::string lowered = module.name;
                                std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                                               [](const unsigned char value) {
                                                   return static_cast<char>(std::tolower(value));
                                               });
                                if (lowered.starts_with(loaderPrefix) &&
                                    lowered.ends_with(".exe")) {
                                    if (loaderModule) {
                                        return ErrorResponse(*parsed, "OUTCOME_UNKNOWN",
                                                             "DLL loader identity is ambiguous",
                                                             false, true);
                                    }
                                    loaderModule = module.name;
                                }
                            }
                        }
                        const std::u8string targetNameEncoded = executablePath.filename().u8string();
                        const std::string targetName(
                            reinterpret_cast<const char*>(targetNameEncoded.data()),
                            targetNameEncoded.size());
                        if (!modules || !loaderModule || UniqueModule(*modules, targetName)) {
                            return ErrorResponse(*parsed, "OUTCOME_UNKNOWN",
                                                 "initial DLL loader pause could not be verified",
                                                 false, true);
                        }
                        return "{\"request_id\":" + JsonString(parsed->requestId) +
                               ",\"state_generation\":" + std::to_string(confirmed) +
                               ",\"status\":\"ok\",\"result\":{\"debuggee_state\":\"paused\"" +
                               ",\"target_kind\":\"dll\",\"path\":" + JsonString(*executable) +
                               ",\"working_directory\":" + JsonString(*workingDirectory) +
                               ",\"loader_module\":" + JsonString(*loaderModule) +
                               ",\"target_loaded\":false,\"entry_rva\":" +
                               JsonString(HexValue(pe->entryRva)) +
                               ",\"state_generation\":" + std::to_string(confirmed) + "}}";
                    }
                    const DBGFUNCTIONS* functions = DbgFunctions();
                    if (functions == nullptr || functions->SetCmdline == nullptr ||
                        !functions->SetCmdline(processCommandLine.c_str())) {
                        return ErrorResponse(
                            *parsed, "OUTCOME_UNKNOWN",
                            "debuggee launched but its command line could not be committed",
                            false, true);
                    }
                    std::string argumentsJson = "[";
                    for (std::size_t index = 0U; index < parsed->launchArguments.size(); ++index) {
                        if (index != 0U) argumentsJson.push_back(',');
                        argumentsJson += JsonString(parsed->launchArguments[index]);
                    }
                    argumentsJson += "]";
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(confirmed) +
                           ",\"status\":\"ok\",\"result\":{\"debuggee_state\":\"paused\",\"path\":" +
                           JsonString(*executable) + ",\"working_directory\":" +
                           JsonString(*workingDirectory) + ",\"arguments\":" +
                           argumentsJson + ",\"state_generation\":" +
                           std::to_string(confirmed) + "}}";
                }
                if (parsed->method == "debuggee.detach") {
                    const DebuggeeState state = debuggeeState_.load();
                    const std::uint32_t detachedProcess = processId_.load();
                    if (sessionOrigin_.load() != SessionOrigin::attached ||
                        (state != DebuggeeState::paused && state != DebuggeeState::running) ||
                        detachedProcess == 0U || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "detach requires an active attached session", false,
                                             false);
                    }
                    const std::uint64_t before = generation_.load();
                    if (!DbgCmdExec("detach")) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger command queue rejected detach", true,
                                             false);
                    }
                    if (!WaitForDetach(detachedProcess, before, requestDeadline)) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "detach outcome was not callback-confirmed", false,
                                             true);
                    }
                    const std::uint64_t confirmed = ObservedGeneration(DebuggeeState::absent);
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(confirmed) +
                           ",\"status\":\"ok\",\"result\":{\"debuggee_state\":\"absent\"" +
                           ",\"session_origin\":null,\"detached_process_id\":" +
                           JsonString(HexValue(detachedProcess)) +
                           ",\"state_generation\":" + std::to_string(confirmed) + "}}";
                }
                if (parsed->method == "debugger.step_out") {
                    const std::optional<std::uint64_t> snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "step out requires a paused debuggee", false, false);
                    }
                    REGDUMP_AVX512 beforeDump{};
                    if (!DbgGetRegDumpEx(&beforeDump, sizeof(beforeDump))) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "initial register snapshot is unavailable", true,
                                             false);
                    }
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed before step out submission", true,
                                             false);
                    }
                    const duint initialStackPointer = beforeDump.regcontext.csp;
                    if (!DbgCmdExec("rtr")) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger command queue rejected step out", true,
                                             false);
                    }
                    if (!WaitForState(DebuggeeState::paused, *snapshot, requestDeadline)) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "step out produced no callback-confirmed pause", false,
                                             true);
                    }
                    std::uint64_t confirmed = 0U;
                    PauseObservation pause;
                    {
                        std::lock_guard lock(stateMutex_);
                        confirmed = pausedGeneration_.load();
                        pause = latestPause_;
                    }
                    REGDUMP_AVX512 afterDump{};
                    if (!DbgGetRegDumpEx(&afterDump, sizeof(afterDump))) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "step out paused but its register snapshot is unavailable",
                                             false, true);
                    }
                    DISASM_INSTR instruction{};
                    DbgDisasmAt(afterDump.regcontext.cip, &instruction);
                    const int instructionSize = instruction.instr_size;
                    const std::size_t textLength =
                        strnlen_s(instruction.instruction, sizeof(instruction.instruction));
                    const std::string_view instructionText(instruction.instruction, textLength);
                    if (!PauseObservationCurrent(confirmed, confirmed)) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "debugger changed during step out confirmation", false,
                                             true);
                    }
                    const bool completed = instructionSize > 0 && instructionSize <= 15 &&
                                           IsReturnInstruction(instructionText) &&
                                           afterDump.regcontext.csp >= initialStackPointer;
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(confirmed) +
                           ",\"status\":\"ok\",\"result\":{\"completed\":" +
                           (completed ? "true" : "false") +
                           ",\"debuggee_state\":\"paused\",\"pause_reason\":" +
                           PauseReasonJson(pause) + ",\"instruction_pointer\":" +
                           JsonString(HexValue(afterDump.regcontext.cip)) +
                           ",\"stack_pointer\":" +
                           JsonString(HexValue(afterDump.regcontext.csp)) +
                           ",\"initial_stack_pointer\":" +
                           JsonString(HexValue(initialStackPointer)) +
                           ",\"instruction\":{\"size\":" +
                           std::to_string(instructionSize > 0 ? instructionSize : 0) +
                           ",\"text\":" +
                           JsonString(instructionText) + "},\"state_generation\":" +
                           std::to_string(confirmed) + "}}";
                }
                if (parsed->method == "debugger.pause" || parsed->method == "debugger.resume" ||
                    parsed->method == "debugger.continue_exception" ||
                    parsed->method == "debugger.step_into" ||
                    parsed->method == "debugger.step_over" || parsed->method == "debugger.stop") {
                    const DebuggeeState state = debuggeeState_.load();
                    const char* command = nullptr;
                    std::string ownedCommand;
                    DebuggeeState expected = state;
                    bool valid = false;
                    bool directPause = false;
                    std::optional<std::uint32_t> expectedStepThread;
                    if (parsed->method == "debugger.pause") {
                        expected = DebuggeeState::paused;
                        valid = state == DebuggeeState::running;
                        directPause = true;
                    } else if (parsed->method == "debugger.resume") {
                        command = "run";
                        expected = DebuggeeState::running;
                        valid = state == DebuggeeState::paused;
                    } else if (parsed->method == "debugger.continue_exception") {
                        PauseObservation pause;
                        {
                            std::lock_guard lock(stateMutex_);
                            pause = latestPause_;
                        }
                        for (const RegisterAssignment& assignment :
                             parsed->exceptionRegisterOverrides) {
                            const std::optional<WritableRegister> spec =
                                FindWritableRegister(assignment.name);
                            if (!spec ||
                                (spec->bits < 64U && assignment.value >=
                                    (std::uint64_t{1U} << spec->bits))) {
                                return ErrorResponse(
                                    *parsed, "INVALID_ARGUMENT",
                                    "register override is not writable on this architecture",
                                    false, false);
                            }
                        }
                        if (!parsed->exceptionRegisterOverrides.empty()) {
                            if (!pause.hasThreadId) {
                                return ErrorResponse(
                                    *parsed, "INVALID_DEBUGGER_STATE",
                                    "exception pause has no correlated thread", false, false);
                            }
                            const ThreadContextStatus mutation = MutateThreadContext(
                                pause.threadId, parsed->exceptionRegisterOverrides);
                            if (mutation != ThreadContextStatus::ok) {
                                return ThreadContextErrorResponse(*parsed, mutation);
                            }
                        }
                        ownedCommand = parsed->exceptionDisposition == "handled" ? "serun" : "erun";
                        command = ownedCommand.c_str();
                        expected = DebuggeeState::running;
                        valid = state == DebuggeeState::paused &&
                                pause.kind == PauseReasonKind::exception &&
                                pause.hasExceptionCode &&
                                (parsed->exceptionDisposition == "handled" ||
                                 pause.firstChance);
                    } else if (parsed->method == "debugger.step_into") {
                        command = "sti";
                        expected = DebuggeeState::paused;
                        valid = state == DebuggeeState::paused;
                        expectedStepThread = DbgGetThreadId();
                    } else if (parsed->method == "debugger.step_over") {
                        command = "sto";
                        expected = DebuggeeState::paused;
                        valid = state == DebuggeeState::paused;
                        expectedStepThread = DbgGetThreadId();
                    } else {
                        command = "stop";
                        expected = DebuggeeState::absent;
                        valid = state == DebuggeeState::starting || state == DebuggeeState::running ||
                                state == DebuggeeState::paused;
                        if (sessionOrigin_.load() == SessionOrigin::attached) valid = false;
                    }
                    if (!valid || !DbgIsDebugging()) {
                        const char* message =
                            parsed->method == "debugger.stop" &&
                                    sessionOrigin_.load() == SessionOrigin::attached
                                ? "stop is unsafe for an attached session; use debuggee.detach"
                                : "operation is not valid in the current debugger state";
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE", message, false,
                                             false);
                    }
                    if (expectedStepThread && *expectedStepThread == 0U) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "no debug-event thread is available", false, false);
                    }
                    if (expectedStepThread && parsed->targetThreadId &&
                        parsed->targetThreadId != expectedStepThread) {
                        return ErrorResponse(
                            *parsed, "INVALID_ARGUMENT",
                            "thread_id must match x64dbg's current debug-event thread",
                            false, false);
                    }
                    const std::uint64_t before = generation_.load();
                    const bool isStep = parsed->method == "debugger.step_into" ||
                                        parsed->method == "debugger.step_over";
                    bool submitted = false;
                    if (directPause) {
                        if (pauseInterruptPending_.exchange(true)) {
                            return ErrorResponse(*parsed, "BUSY",
                                                 "a debugger interrupt is already pending", true,
                                                 false);
                        }
                        // Use x64dbg's direct pause implementation. A raw
                        // DebugBreakProcess call enters DbgUiRemoteBreakin,
                        // which exits without raising EXCEPTION_BREAKPOINT when
                        // the debuggee's PEB BeingDebugged byte is hidden. The
                        // debugger command first plants a one-shot breakpoint
                        // at a real debuggee thread's CIP and therefore remains
                        // effective in that anti-debug state.
                        submitted = DbgCmdExecDirect("pause");
                        if (!submitted) pauseInterruptPending_.store(false);
                    } else if (isStep) {
                        // x64dbg's step engine operates on the current debug-event
                        // thread, not the GUI-selected hActiveThread. Submit the
                        // one verified run-state mutation in this executor turn.
                        submitted = DbgCmdExecDirect(command);
                    } else {
                        submitted = DbgCmdExec(command);
                    }
                    if (!submitted) {
                        return ErrorResponse(*parsed, "BUSY",
                                             directPause
                                                 ? "debugger interrupt request failed"
                                                 : "debugger command queue rejected the operation", true,
                                             false);
                    }
                    const bool outcomeConfirmed =
                        isStep ? WaitForPauseReason(PauseReasonKind::step, before, requestDeadline)
                        : directPause
                            ? WaitForPauseReason(PauseReasonKind::userPause, before,
                                                 requestDeadline)
                            : WaitForState(expected, before, requestDeadline);
                    if (!outcomeConfirmed) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "mutation outcome was not callback-confirmed", false,
                                             true);
                    }
                    if (directPause) pauseInterruptPending_.store(false);
                    const std::uint64_t confirmed = ObservedGeneration(expected);
                    if (isStep) {
                        PauseObservation stepPause;
                        {
                            std::lock_guard lock(stateMutex_);
                            stepPause = latestPause_;
                        }
                        if (!expectedStepThread || !stepPause.hasThreadId ||
                            stepPause.threadId != *expectedStepThread) {
                            return ErrorResponse(
                                *parsed, "TIMEOUT",
                                "step paused a different or uncorrelated thread", false, true);
                        }
                        REGDUMP_AVX512 dump{};
                        if (!DbgGetRegDumpEx(&dump, sizeof(dump))) {
                            return ErrorResponse(*parsed, "INTERNAL",
                                                 "step register snapshot is unavailable", true,
                                                 false);
                        }
                        PauseObservation pause;
                        std::uint32_t threadId = 0U;
                        {
                            std::lock_guard lock(stateMutex_);
                            if (generation_.load() != confirmed ||
                                debuggeeState_.load() != DebuggeeState::paused) {
                                return ErrorResponse(*parsed, "BUSY",
                                                     "debugger changed after the confirmed step",
                                                     true, false);
                            }
                            pause = latestPause_;
                            threadId = activeThreadId_.load();
                        }
                        return "{\"request_id\":" + JsonString(parsed->requestId) +
                               ",\"state_generation\":" + std::to_string(confirmed) +
                               ",\"status\":\"ok\",\"result\":{\"debuggee_state\":\"paused\"" +
                               ",\"active_thread_id\":" +
                               (threadId == 0U ? "null" : JsonString(HexValue(threadId))) +
                               ",\"instruction_pointer\":" +
                               JsonString(HexValue(dump.regcontext.cip)) +
                               ",\"pause_reason\":" + PauseReasonJson(pause) +
                               ",\"state_generation\":" + std::to_string(confirmed) + "}}";
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(confirmed) +
                           ",\"status\":\"ok\",\"result\":{\"debuggee_state\":" +
                           JsonString(expected == DebuggeeState::paused
                                          ? "paused"
                                          : expected == DebuggeeState::running ? "running" : "absent") +
                           ",\"state_generation\":" + std::to_string(confirmed) + "}}";
                }
                if (parsed->method == "memory.write") {
                    const duint address = resolvedLocation->address;
                    if (!PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed after address resolution", true,
                                             false);
                    }
                    if (!DbgMemWrite(address, parsed->writeBytes.data(),
                                     static_cast<duint>(parsed->writeBytes.size()))) {
                        return ErrorResponse(*parsed, "ACCESS_DENIED", "memory write failed", false,
                                             false);
                    }
                    std::vector<unsigned char> verified(parsed->writeBytes.size());
                    if (!DbgMemRead(address, verified.data(),
                                    static_cast<duint>(verified.size())) ||
                        verified != parsed->writeBytes) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "memory write could not be verified", false, true);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(generation_.load()) +
                           ",\"status\":\"ok\",\"result\":{\"address\":" +
                           JsonString(HexValue(address)) + ",\"location\":" +
                           LocationJson(*resolvedLocation, resolvedGeneration) +
                           ",\"bytes_written\":" +
                           std::to_string(parsed->writeBytes.size()) + ",\"verified\":true}}";
                }
                if (parsed->method == "breakpoints.enable" ||
                    parsed->method == "breakpoints.disable") {
                    const duint address = resolvedLocation->address;
                    const bool enable = parsed->method == "breakpoints.enable";
                    const DBGFUNCTIONS* functions = DbgFunctions();
                    if (functions == nullptr || functions->GetBridgeBp == nullptr) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "typed breakpoint read-back is unavailable", false,
                                             false);
                    }
                    BPXTYPE nativeType = bp_none;
                    BreakpointTransitionKind transitionKind = BreakpointTransitionKind::software;
                    if (parsed->breakpointKind == "software") {
                        nativeType = bp_normal;
                    } else if (parsed->breakpointKind == "conditional") {
                        nativeType = bp_normal;
                        transitionKind = BreakpointTransitionKind::conditional;
                    } else if (parsed->breakpointKind == "hardware") {
                        nativeType = bp_hardware;
                        transitionKind = BreakpointTransitionKind::hardware;
                    } else if (parsed->breakpointKind == "memory") {
                        nativeType = bp_memory;
                        transitionKind = BreakpointTransitionKind::memory;
                    } else {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "breakpoint selector kind is invalid", false, false);
                    }
                    if (!PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed before breakpoint transition", true,
                                             false);
                    }
                    BRIDGEBP before{};
                    if (!functions->GetBridgeBp(nativeType, address, &before)) {
                        return ErrorResponse(*parsed, "NOT_FOUND",
                                             "selected breakpoint does not exist", false, false);
                    }
                    std::optional<HardwareAccess> hardwareAccess;
                    std::optional<MemoryAccess> memoryAccess;
                    duint memorySize = 0U;
                    bool selectorMatches = false;
                    if (transitionKind == BreakpointTransitionKind::software) {
                        selectorMatches = PlainSoftwareBreakpointSelectable(before, address);
                    } else if (transitionKind == BreakpointTransitionKind::conditional) {
                        selectorMatches = ConditionalBreakpointOwned(
                            before, address, parsed->managedBreakpointId);
                    } else if (transitionKind == BreakpointTransitionKind::hardware) {
                        hardwareAccess = ParseHardwareAccess(parsed->breakpointAccess);
                        selectorMatches = hardwareAccess &&
                            HardwareRequestValid(*hardwareAccess, parsed->breakpointSize, address) &&
                            HardwareBreakpointMatches(before, *hardwareAccess,
                                                      parsed->breakpointSize, false);
                    } else {
                        memoryAccess = ParseMemoryAccess(parsed->breakpointAccess);
                        if (functions->MemBpSize == nullptr) {
                            return ErrorResponse(*parsed, "INTERNAL",
                                                 "typed memory breakpoint size is unavailable",
                                                 false, false);
                        }
                        memorySize = functions->MemBpSize(address);
                        selectorMatches = memoryAccess &&
                            MemoryBreakpointMatches(before, *memoryAccess,
                                                    parsed->breakpointSize, memorySize, false);
                    }
                    if (!selectorMatches) {
                        return ErrorResponse(*parsed, "CONFLICT",
                                             "breakpoint does not exactly match the typed selector",
                                             false, false);
                    }
                    if (transitionKind == BreakpointTransitionKind::hardware && enable &&
                        !before.enabled) {
                        {
                            std::lock_guard lock(stateMutex_);
                            if (generation_.load() == resolvedGeneration &&
                                (latestPause_.kind == PauseReasonKind::processCreated ||
                                 latestPause_.kind == PauseReasonKind::systemBreakpoint)) {
                                return ErrorResponse(
                                    *parsed, "INVALID_DEBUGGER_STATE",
                                    "hardware breakpoints require a pause after process and system-breakpoint initialization",
                                    false, false);
                            }
                        }
                        BPMAP map{};
                        const int reported = DbgGetBpList(bp_hardware, &map);
                        struct TransitionMapGuard {
                            BRIDGEBP* value;
                            ~TransitionMapGuard() {
                                if (value != nullptr) BridgeFree(value);
                            }
                        } guard{map.bp};
                        if (reported < 0 || map.count < 0 ||
                            (map.count > 0 && map.bp == nullptr) || map.count > 65536) {
                            return ErrorResponse(*parsed, "INTERNAL",
                                                 "hardware breakpoint slot snapshot is invalid",
                                                 false, false);
                        }
                        if (HardwareSlotsExhausted(map.bp,
                                                   static_cast<std::size_t>(map.count))) {
                            return ErrorResponse(*parsed, "RESOURCE_EXHAUSTED",
                                                 "all four hardware breakpoint slots are occupied",
                                                 false, false);
                        }
                    }
                    const bool changed = before.enabled != enable;
                    if (changed) {
                        const int status = submitFencedCommand(
                            BreakpointToggleCommand(transitionKind, address, enable));
                        if (status == 1) {
                            return ErrorResponse(*parsed, "BUSY",
                                                 "debugger command queue rejected breakpoint transition",
                                                 true, false);
                        }
                        if (status == 2) {
                            return ErrorResponse(*parsed, "TIMEOUT",
                                                 "breakpoint transition was admitted without confirmation",
                                                 false, true);
                        }
                    }
                    BRIDGEBP after{};
                    if (!functions->GetBridgeBp(nativeType, address, &after) ||
                        after.enabled != enable ||
                        !BreakpointConfigurationUnchanged(
                            before, after,
                            transitionKind == BreakpointTransitionKind::hardware)) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "breakpoint transition could not be exactly confirmed",
                                             false, changed);
                    }
                    bool afterMatches = false;
                    if (transitionKind == BreakpointTransitionKind::software) {
                        afterMatches = PlainSoftwareBreakpointSelectable(after, address);
                    } else if (transitionKind == BreakpointTransitionKind::conditional) {
                        afterMatches = ConditionalBreakpointOwned(
                            after, address, parsed->managedBreakpointId);
                    } else if (transitionKind == BreakpointTransitionKind::hardware) {
                        afterMatches = HardwareBreakpointMatches(
                            after, *hardwareAccess, parsed->breakpointSize, false) &&
                            (!enable || after.slot < 4U);
                    } else {
                        afterMatches = MemoryBreakpointMatches(
                            after, *memoryAccess, parsed->breakpointSize,
                            functions->MemBpSize(address), false);
                    }
                    if (!afterMatches || !PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "breakpoint selector or debugger state changed during transition",
                                             false, changed);
                    }
                    std::string typed;
                    if (transitionKind == BreakpointTransitionKind::hardware) {
                        typed = ",\"access\":" + JsonString(HardwareAccessName(*hardwareAccess)) +
                                ",\"size\":" + std::to_string(parsed->breakpointSize) +
                                ",\"slot\":" +
                                (after.enabled && after.slot < 4U
                                     ? std::to_string(after.slot)
                                     : std::string("null"));
                    } else if (transitionKind == BreakpointTransitionKind::memory) {
                        typed = ",\"access\":" + JsonString(MemoryAccessName(*memoryAccess)) +
                                ",\"size\":" + std::to_string(parsed->breakpointSize);
                    } else if (transitionKind == BreakpointTransitionKind::conditional) {
                        const std::size_t conditionLength = strnlen_s(
                            after.breakCondition, sizeof(after.breakCondition));
                        typed = ",\"managed_id\":" +
                                JsonString(parsed->managedBreakpointId) +
                                ",\"condition_expression\":" +
                                JsonString(std::string_view(after.breakCondition,
                                                            conditionLength)) +
                                ",\"fast_resume\":" +
                                (after.fastResume ? "true" : "false");
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" +
                           std::to_string(resolvedGeneration) +
                           ",\"status\":\"ok\",\"result\":{\"kind\":" +
                           JsonString(parsed->breakpointKind) + ",\"address\":" +
                           JsonString(HexValue(address)) + ",\"location\":" +
                           LocationJson(*resolvedLocation, resolvedGeneration) + typed +
                           ",\"enabled\":" + (enable ? "true" : "false") +
                           ",\"changed\":" + (changed ? "true" : "false") + "}}";
                }
                if (parsed->method == "breakpoints.conditional.set" ||
                    parsed->method == "breakpoints.conditional.remove") {
                    if (parsed->conditionalInvalid) {
                        return ErrorResponse(
                            *parsed, "INVALID_ARGUMENT",
                            "conditional breakpoint value is invalid for this architecture",
                            false, false);
                    }
                    const duint address = resolvedLocation->address;
                    const bool setting = parsed->method == "breakpoints.conditional.set";
                    const DBGFUNCTIONS* functions = DbgFunctions();
                    if (functions == nullptr || functions->GetBridgeBp == nullptr ||
                        functions->BpRefVa == nullptr || functions->BpRefExists == nullptr ||
                        functions->BpSetFieldText == nullptr ||
                        functions->BpSetFieldNumber == nullptr) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "typed conditional breakpoint API is unavailable",
                                             false, false);
                    }
                    if (!PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed before conditional breakpoint mutation",
                                             true, false);
                    }
                    BRIDGEBP before{};
                    const bool beforePresent =
                        functions->GetBridgeBp(bp_normal, address, &before);
                    if (setting && beforePresent) {
                        return ErrorResponse(*parsed, "ALREADY_EXISTS",
                                             "a software breakpoint already exists at this address",
                                             false, false);
                    }
                    if (!setting) {
                        if (!beforePresent) {
                            return ErrorResponse(*parsed, "NOT_FOUND",
                                                 "conditional breakpoint does not exist", false,
                                                 false);
                        }
                        if (!ConditionalBreakpointOwned(before, address,
                                                       parsed->managedBreakpointId)) {
                            return ErrorResponse(*parsed, "CONFLICT",
                                                 "conditional breakpoint is foreign or was renamed",
                                                 false, false);
                        }
                    }
                    const std::string ownedName = ManagedBreakpointName(
                        "conditional", parsed->managedBreakpointId);
                    const auto cleanupOwned = [&]() {
                        BRIDGEBP current{};
                        if (!functions->GetBridgeBp(bp_normal, address, &current)) return 0;
                        if (!ConditionalBreakpointOwned(current, address,
                                                        parsed->managedBreakpointId)) {
                            return 1;
                        }
                        const int cleanupStatus =
                            submitFencedCommand("bc " + HexValue(address));
                        if (cleanupStatus != 0) return 2;
                        BRIDGEBP remaining{};
                        return functions->GetBridgeBp(bp_normal, address, &remaining) ? 2 : 0;
                    };
                    const std::string command =
                        setting ? "bp " + HexValue(address) + ", \"" + ownedName + "\""
                                : "bc " + HexValue(address);
                    const int commandStatus = submitFencedCommand(command);
                    if (commandStatus == 1) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger command queue rejected conditional breakpoint mutation",
                                             true, false);
                    }
                    if (commandStatus == 2) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "conditional breakpoint mutation was admitted without confirmation",
                                             false, true);
                    }
                    if (setting) {
                        BP_REF reference{};
                        if (!functions->BpRefVa(&reference, bp_normal, address) ||
                            !functions->BpRefExists(&reference) ||
                            !functions->BpSetFieldText(
                                &reference, bpf_breakcondition,
                                parsed->conditionalExpression.c_str()) ||
                            !functions->BpSetFieldNumber(&reference, bpf_fastresume, 1U)) {
                            const int cleanup = cleanupOwned();
                            return ErrorResponse(
                                *parsed, cleanup == 1 ? "CONFLICT" : "INTERNAL",
                                "conditional breakpoint fields could not be assigned", false,
                                cleanup == 2);
                        }
                        BRIDGEBP installed{};
                        if (!functions->GetBridgeBp(bp_normal, address, &installed) ||
                            !ConditionalBreakpointMatches(
                                installed, address, parsed->managedBreakpointId,
                                parsed->conditionalExpression)) {
                            const int cleanup = cleanupOwned();
                            return ErrorResponse(
                                *parsed, cleanup == 1 ? "CONFLICT" : "INTERNAL",
                                "conditional breakpoint setup could not be verified", false,
                                cleanup == 2);
                        }
                    } else {
                        BRIDGEBP remaining{};
                        if (functions->GetBridgeBp(bp_normal, address, &remaining)) {
                            return ErrorResponse(*parsed, "TIMEOUT",
                                                 "conditional breakpoint removal could not be confirmed",
                                                 false, true);
                        }
                    }
                    if (!PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during conditional breakpoint mutation",
                                             false, true);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" +
                           std::to_string(resolvedGeneration) +
                           ",\"status\":\"ok\",\"result\":{\"address\":" +
                           JsonString(HexValue(address)) + ",\"location\":" +
                           LocationJson(*resolvedLocation, resolvedGeneration) +
                           ",\"managed_id\":" +
                           JsonString(parsed->managedBreakpointId) + ",\"present\":" +
                           (setting ? "true" : "false") +
                           (setting ? ",\"condition\":" +
                                          ConditionalSpecJson(parsed->conditionalSpec) +
                                          ",\"condition_expression\":" +
                                          JsonString(parsed->conditionalExpression) +
                                          ",\"fast_resume\":true"
                                    : "") +
                           "}}";
                }
                if (parsed->method == "breakpoints.set" ||
                    parsed->method == "breakpoints.remove") {
                    const duint address = resolvedLocation->address;
                    if (!PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed after address resolution", true,
                                             false);
                    }
                    const bool setting = parsed->method == "breakpoints.set";
                    const std::string command = std::string(setting ? "bp " : "bc ") +
                                                HexValue(address);
                    if (!DbgCmdExec(command.c_str())) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger command queue rejected the operation", true,
                                             false);
                    }
                    bool observed = false;
                    while (pluginState_.load() == PluginState::ready &&
                           std::chrono::steady_clock::now() < requestDeadline) {
                        const bool exists = (DbgGetBpxTypeAt(address) & bp_normal) != 0;
                        if (exists == setting) {
                            observed = true;
                            break;
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    }
                    if (!observed) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "breakpoint outcome could not be confirmed", false,
                                             true);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(generation_.load()) +
                           ",\"status\":\"ok\",\"result\":{\"address\":" +
                           JsonString(HexValue(address)) + ",\"location\":" +
                           LocationJson(*resolvedLocation, resolvedGeneration) +
                           ",\"present\":" +
                           (setting ? "true" : "false") + "}}";
                }
                if (parsed->method == "breakpoints.hardware.set" ||
                    parsed->method == "breakpoints.hardware.remove") {
                    const duint address = resolvedLocation->address;
                    const auto access = ParseHardwareAccess(parsed->breakpointAccess);
                    if (!access ||
                        !HardwareRequestValid(*access, parsed->breakpointSize, address)) {
                        return ErrorResponse(
                            *parsed, "INVALID_ARGUMENT",
                            "hardware breakpoint access, size, or alignment is invalid for this architecture",
                            false, false);
                    }
                    {
                        std::lock_guard lock(stateMutex_);
                        if (generation_.load() == resolvedGeneration &&
                            (latestPause_.kind == PauseReasonKind::processCreated ||
                             latestPause_.kind == PauseReasonKind::systemBreakpoint)) {
                            return ErrorResponse(
                                *parsed, "INVALID_DEBUGGER_STATE",
                                "hardware breakpoints require a pause after process and system-breakpoint initialization",
                                false, false);
                        }
                    }
                    const DBGFUNCTIONS* functions = DbgFunctions();
                    if (functions == nullptr || functions->GetBridgeBp == nullptr) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "typed breakpoint read-back is unavailable", false,
                                             false);
                    }
                    if (!PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed after address resolution", true,
                                             false);
                    }
                    BRIDGEBP before{};
                    const bool beforePresent =
                        functions->GetBridgeBp(bp_hardware, address, &before);
                    const bool setting = parsed->method == "breakpoints.hardware.set";
                    unsigned short confirmedSlot = before.slot;
                    if (setting) {
                        if (beforePresent) {
                            return ErrorResponse(*parsed, "ALREADY_EXISTS",
                                                 "a hardware breakpoint already exists at this address",
                                                 false, false);
                        }
                        BPMAP map{};
                        const int reported = DbgGetBpList(bp_hardware, &map);
                        struct HardwareMapGuard {
                            BRIDGEBP* value;
                            ~HardwareMapGuard() {
                                if (value != nullptr) BridgeFree(value);
                            }
                        } guard{map.bp};
                        if (reported < 0 || map.count < 0 ||
                            (map.count > 0 && map.bp == nullptr) || map.count > 65536) {
                            return ErrorResponse(*parsed, "INTERNAL",
                                                 "hardware breakpoint slot snapshot is invalid",
                                                 false, false);
                        }
                        if (HardwareSlotsExhausted(map.bp,
                                                   static_cast<std::size_t>(map.count))) {
                            return ErrorResponse(*parsed, "RESOURCE_EXHAUSTED",
                                                 "all four hardware breakpoint slots are represented",
                                                 false, false);
                        }
                    } else {
                        if (!beforePresent) {
                            return ErrorResponse(*parsed, "NOT_FOUND",
                                                 "no hardware breakpoint exists at this address",
                                                 false, false);
                        }
                        if (!HardwareBreakpointMatches(before, *access,
                                                       parsed->breakpointSize, false)) {
                            return ErrorResponse(*parsed, "CONFLICT",
                                                 "hardware breakpoint does not match access and size",
                                                 false, false);
                        }
                    }
                    std::string command;
                    if (setting) {
                        command = "bphws " + HexValue(address) + ", ";
                        command.push_back(HardwareAccessCommand(*access));
                        command += ", " + std::to_string(parsed->breakpointSize);
                    } else {
                        command = "bphwc " + HexValue(address);
                    }
                    if (!DbgCmdExec(command.c_str())) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger command queue rejected the operation", true,
                                             false);
                    }
                    bool observed = false;
                    while (pluginState_.load() == PluginState::ready &&
                           std::chrono::steady_clock::now() < requestDeadline) {
                        BRIDGEBP current{};
                        const bool present =
                            functions->GetBridgeBp(bp_hardware, address, &current);
                        if (setting && present &&
                            HardwareBreakpointMatches(current, *access,
                                                      parsed->breakpointSize, true)) {
                            confirmedSlot = current.slot;
                            observed = true;
                            break;
                        }
                        if (!setting && !present) {
                            observed = true;
                            break;
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    }
                    if (!observed || !PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(
                            *parsed, "TIMEOUT",
                            "hardware breakpoint outcome could not be exactly confirmed", false,
                            true);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(resolvedGeneration) +
                           ",\"status\":\"ok\",\"result\":{\"address\":" +
                           JsonString(HexValue(address)) + ",\"location\":" +
                           LocationJson(*resolvedLocation, resolvedGeneration) +
                           ",\"type\":\"hardware\",\"access\":" +
                           JsonString(HardwareAccessName(*access)) + ",\"size\":" +
                           std::to_string(parsed->breakpointSize) + ",\"slot\":" +
                           std::to_string(confirmedSlot) + ",\"present\":" +
                           (setting ? "true" : "false") + "}}";
                }
                if (parsed->method == "breakpoints.memory.set" ||
                    parsed->method == "breakpoints.memory.remove") {
                    const duint address = resolvedLocation->address;
                    const auto access = ParseMemoryAccess(parsed->breakpointAccess);
                    if (!access) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "memory breakpoint access is invalid", false, false);
                    }
                    const DBGFUNCTIONS* functions = DbgFunctions();
                    if (functions == nullptr || functions->GetBridgeBp == nullptr ||
                        functions->MemBpSize == nullptr) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "typed memory breakpoint read-back is unavailable",
                                             false, false);
                    }
                    if (!PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed after address resolution", true,
                                             false);
                    }
                    const bool setting = parsed->method == "breakpoints.memory.set";
                    if (setting) {
                        duint regionSize = 0U;
                        const duint regionBase = DbgMemFindBaseAddr(address, &regionSize);
                        if (!MemoryRangeContained(address, parsed->breakpointSize, regionBase,
                                                  regionSize)) {
                            return ErrorResponse(
                                *parsed, "INVALID_ARGUMENT",
                                "memory breakpoint range must fit in one current memory region",
                                false, false);
                        }
                    }
                    BRIDGEBP before{};
                    const bool beforePresent =
                        functions->GetBridgeBp(bp_memory, address, &before);
                    if (setting) {
                        if (beforePresent) {
                            return ErrorResponse(*parsed, "ALREADY_EXISTS",
                                                 "a memory breakpoint already exists at this address",
                                                 false, false);
                        }
                    } else {
                        if (!beforePresent) {
                            return ErrorResponse(*parsed, "NOT_FOUND",
                                                 "no memory breakpoint exists at this address",
                                                 false, false);
                        }
                        const duint observedSize = functions->MemBpSize(address);
                        if (!MemoryBreakpointMatches(before, *access, parsed->breakpointSize,
                                                     observedSize, false)) {
                            return ErrorResponse(*parsed, "CONFLICT",
                                                 "memory breakpoint does not match access and size",
                                                 false, false);
                        }
                    }
                    std::string command;
                    if (setting) {
                        command = "bpmrange " + HexValue(address) + ", " +
                                  HexValue(static_cast<duint>(parsed->breakpointSize)) + ", ";
                        command.push_back(MemoryAccessCommand(*access));
                    } else {
                        command = "bpmc " + HexValue(address);
                    }
                    if (!DbgCmdExec(command.c_str())) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger command queue rejected the operation", true,
                                             false);
                    }
                    bool observed = false;
                    while (pluginState_.load() == PluginState::ready &&
                           std::chrono::steady_clock::now() < requestDeadline) {
                        BRIDGEBP current{};
                        const bool present =
                            functions->GetBridgeBp(bp_memory, address, &current);
                        if (setting && present &&
                            MemoryBreakpointMatches(current, *access, parsed->breakpointSize,
                                                    functions->MemBpSize(address), true)) {
                            observed = true;
                            break;
                        }
                        if (!setting && !present) {
                            observed = true;
                            break;
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    }
                    if (!observed || !PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(
                            *parsed, "TIMEOUT",
                            "memory breakpoint outcome could not be exactly confirmed", false,
                            true);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(resolvedGeneration) +
                           ",\"status\":\"ok\",\"result\":{\"address\":" +
                           JsonString(HexValue(address)) + ",\"location\":" +
                           LocationJson(*resolvedLocation, resolvedGeneration) +
                           ",\"type\":\"memory\",\"access\":" +
                           JsonString(MemoryAccessName(*access)) + ",\"size\":" +
                           std::to_string(parsed->breakpointSize) + ",\"present\":" +
                           (setting ? "true" : "false") + "}}";
                }
                if (parsed->method == "expressions.evaluate_batch") {
                    const std::optional<std::uint64_t> snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false, false);
                    }
                    std::string items = "[";
                    std::size_t successCount = 0U;
                    for (std::size_t index = 0U; index < parsed->expressions.size(); ++index) {
                        duint value = 0;
                        const bool success = DbgFunctions()->ValFromString(
                            parsed->expressions[index].c_str(), &value);
                        if (index != 0U) items.push_back(',');
                        items += "{\"expression\":" + JsonString(parsed->expressions[index]) +
                                 ",\"success\":" + (success ? "true" : "false");
                        if (success) {
                            ++successCount;
                            items += ",\"value\":" + JsonString(HexValue(value)) +
                                     ",\"error\":null}";
                        } else {
                            items += ",\"value\":null,\"error\":{\"code\":"
                                     "\"INVALID_EXPRESSION\",\"message\":"
                                     "\"expression could not be evaluated\"}}";
                        }
                    }
                    items += "]";
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during expression evaluation", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(*snapshot) +
                           ",\"status\":\"ok\",\"result\":{\"items\":" + items +
                           ",\"requested_count\":" +
                           std::to_string(parsed->expressions.size()) +
                           ",\"success_count\":" + std::to_string(successCount) +
                           ",\"state_generation\":" + std::to_string(*snapshot) + "}}";
                }
                if (parsed->method == "process.peb") {
                    const std::optional<std::uint64_t> snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false, false);
                    }
                    const DWORD processId = DbgGetProcessId();
                    const duint peb = DbgGetPebAddress(processId);
                    if (processId == 0U || peb == 0U) {
                        return ErrorResponse(*parsed, "INTERNAL", "PEB address is unavailable",
                                             true, false);
                    }
                    unsigned char beingDebugged = 0U;
                    duint imageBase = 0U;
                    duint loaderData = 0U;
                    duint processParameters = 0U;
                    duint processHeap = 0U;
                    DWORD ntGlobalFlag = 0U;
#ifdef _WIN64
                    constexpr duint imageBaseOffset = 0x10U;
                    constexpr duint loaderDataOffset = 0x18U;
                    constexpr duint processParametersOffset = 0x20U;
                    constexpr duint processHeapOffset = 0x30U;
                    constexpr duint ntGlobalFlagOffset = 0xbcU;
                    constexpr const char* architecture = "x86_64";
#else
                    constexpr duint imageBaseOffset = 0x08U;
                    constexpr duint loaderDataOffset = 0x0cU;
                    constexpr duint processParametersOffset = 0x10U;
                    constexpr duint processHeapOffset = 0x18U;
                    constexpr duint ntGlobalFlagOffset = 0x68U;
                    constexpr const char* architecture = "x86";
#endif
                    if (!DbgMemRead(peb + 2U, &beingDebugged, sizeof(beingDebugged)) ||
                        !DbgMemRead(peb + imageBaseOffset, &imageBase, sizeof(imageBase)) ||
                        !DbgMemRead(peb + loaderDataOffset, &loaderData, sizeof(loaderData)) ||
                        !DbgMemRead(peb + processParametersOffset, &processParameters,
                                    sizeof(processParameters)) ||
                        !DbgMemRead(peb + processHeapOffset, &processHeap,
                                    sizeof(processHeap)) ||
                        !DbgMemRead(peb + ntGlobalFlagOffset, &ntGlobalFlag,
                                    sizeof(ntGlobalFlag))) {
                        return ErrorResponse(*parsed, "ACCESS_DENIED",
                                             "one or more PEB fields are unreadable", false,
                                             false);
                    }
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during PEB snapshot", true, false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(*snapshot) +
                           ",\"status\":\"ok\",\"result\":{\"architecture\":" +
                           JsonString(architecture) + ",\"process_id\":" +
                           std::to_string(processId) + ",\"address\":" +
                           JsonString(HexValue(peb)) + ",\"being_debugged\":" +
                           (beingDebugged == 0U ? "false" : "true") +
                           ",\"being_debugged_raw\":" +
                           JsonString(HexValue(beingDebugged)) + ",\"nt_global_flag\":" +
                           JsonString(HexValue(ntGlobalFlag)) + ",\"image_base\":" +
                           JsonString(HexValue(imageBase)) + ",\"loader_data\":" +
                           JsonString(HexValue(loaderData)) +
                           ",\"process_parameters\":" +
                           JsonString(HexValue(processParameters)) +
                           ",\"process_heap\":" + JsonString(HexValue(processHeap)) +
                           ",\"state_generation\":" + std::to_string(*snapshot) + "}}";
                }
                if (parsed->method == "context.arguments") {
                    const std::optional<std::uint64_t> snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false, false);
                    }
                    const ThreadContextCapture captured =
                        CaptureThreadContext(parsed->targetThreadId);
                    if (captured.status != ThreadContextStatus::ok) {
                        return ThreadContextErrorResponse(*parsed, captured.status);
                    }
                    std::string convention = parsed->callingConvention;
#ifdef _WIN64
                    if (convention == "auto") convention = "windows_x64";
                    if (convention != "windows_x64") {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "x64dbg supports windows_x64 arguments only", false,
                                             false);
                    }
                    constexpr std::size_t registerArgumentCount = 4U;
#else
                    if (convention == "auto") convention = "cdecl";
                    if (convention == "windows_x64") {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "x32dbg does not support windows_x64 arguments",
                                             false, false);
                    }
                    const std::size_t registerArgumentCount = convention == "fastcall" ? 2U :
                                                              convention == "thiscall" ? 1U : 0U;
#endif
                    duint returnAddress = 0U;
                    if (!DbgMemRead(captured.value.registers.csp, &returnAddress,
                                    sizeof(returnAddress))) {
                        return ErrorResponse(*parsed, "ACCESS_DENIED",
                                             "stack return address is unreadable", false, false);
                    }
                    std::string items = "[";
                    for (std::size_t index = 0U; index < parsed->argumentCount; ++index) {
                        duint value = 0U;
                        std::string source;
                        std::string storageAddress = "null";
                        if (index < registerArgumentCount) {
#ifdef _WIN64
                            constexpr const char* names[] = {"rcx", "rdx", "r8", "r9"};
                            const duint values[] = {captured.value.registers.ccx,
                                                    captured.value.registers.cdx,
                                                    captured.value.registers.r8,
                                                    captured.value.registers.r9};
#else
                            constexpr const char* names[] = {"ecx", "edx"};
                            const duint values[] = {captured.value.registers.ccx,
                                                    captured.value.registers.cdx};
#endif
                            source = names[index];
                            value = values[index];
                        } else {
#ifdef _WIN64
                            const duint address = captured.value.registers.csp +
                                                  sizeof(duint) + index * sizeof(duint);
#else
                            const duint address = captured.value.registers.csp + sizeof(duint) +
                                                  (index - registerArgumentCount) * sizeof(duint);
#endif
                            if (!DbgMemRead(address, &value, sizeof(value))) {
                                return ErrorResponse(*parsed, "ACCESS_DENIED",
                                                     "one or more stack arguments are unreadable",
                                                     false, false);
                            }
                            source = "stack";
                            storageAddress = JsonString(HexValue(address));
                        }
                        if (index != 0U) items.push_back(',');
                        items += "{\"index\":" + std::to_string(index) +
                                 ",\"value\":" + JsonString(HexValue(value)) +
                                 ",\"source\":" + JsonString(source) +
                                 ",\"storage_address\":" + storageAddress + "}";
                    }
                    items += "]";
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during argument snapshot", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(*snapshot) +
                           ",\"status\":\"ok\",\"result\":{\"thread_id\":" +
                           JsonString(HexValue(captured.value.threadId)) +
                           ",\"instruction_pointer\":" +
                           JsonString(HexValue(captured.value.registers.cip)) +
                           ",\"stack_pointer\":" +
                           JsonString(HexValue(captured.value.registers.csp)) +
                           ",\"return_address\":" + JsonString(HexValue(returnAddress)) +
                           ",\"calling_convention\":" + JsonString(convention) +
                           ",\"assumption\":\"paused_at_callee_entry\",\"items\":" +
                           items + ",\"state_generation\":" +
                           std::to_string(*snapshot) + "}}";
                }
                if (parsed->method == "expression.evaluate") {
                    const std::optional<std::uint64_t> snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false, false);
                    }
                    duint value = 0;
                    if (!DbgFunctions()->ValFromString(parsed->expression.c_str(), &value)) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "expression could not be evaluated", false, false);
                    }
                    std::ostringstream formatted;
                    formatted << "0x" << std::hex << std::nouppercase << value;
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during expression evaluation", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(*snapshot) +
                           ",\"status\":\"ok\",\"result\":{\"expression\":" +
                           JsonString(parsed->expression) + ",\"value\":" +
                           JsonString(formatted.str()) + ",\"state_generation\":" +
                           std::to_string(*snapshot) + "}}";
                }
                if (parsed->method == "memory.read") {
                    const duint addressValue = resolvedLocation->address;
                    std::vector<unsigned char> bytes(parsed->length);
                    if (!DbgMemRead(addressValue, bytes.data(),
                                    static_cast<duint>(bytes.size()))) {
                        return ErrorResponse(*parsed, "ACCESS_DENIED",
                                             "memory range is not fully readable", false, false);
                    }
                    if (!PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during memory snapshot", true,
                                             false);
                    }
                    std::ostringstream address;
                    address << "0x" << std::hex << std::nouppercase << addressValue;
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(resolvedGeneration) +
                           ",\"status\":\"ok\",\"result\":{\"address\":" +
                           JsonString(address.str()) + ",\"location\":" +
                           LocationJson(*resolvedLocation, resolvedGeneration) +
                           ",\"data_hex\":" +
                           JsonString(Hex(bytes)) + ",\"bytes_read\":" +
                           std::to_string(bytes.size()) + ",\"complete\":true,\"state_generation\":" +
                           std::to_string(resolvedGeneration) + "}}";
                }
                if (parsed->method == "registers.write") {
                    const std::optional<WritableRegister> spec =
                        FindWritableRegister(parsed->registerName);
                    if (!spec) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "register is not writable on this architecture", false,
                                             false);
                    }
                    if (spec->bits < 64U &&
                        parsed->registerWriteValue >= (std::uint64_t{1U} << spec->bits)) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "register value exceeds its width", false, false);
                    }
                    const std::optional<std::uint64_t> snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "register write requires a paused debuggee", false,
                                             false);
                    }
                    const ThreadContextCapture beforeCapture =
                        CaptureThreadContext(parsed->targetThreadId);
                    if (beforeCapture.status != ThreadContextStatus::ok) {
                        return ThreadContextErrorResponse(*parsed, beforeCapture.status);
                    }
                    const std::optional<duint> previous = RegisterValue(
                        beforeCapture.value.registers, parsed->registerName);
                    if (!previous) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "register policy has no snapshot mapping", false,
                                             false);
                    }
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed before register write", true, false);
                    }
                    if (parsed->targetThreadId) {
                        const ThreadContextStatus mutation = MutateThreadContext(
                            *parsed->targetThreadId,
                            {{parsed->registerName, parsed->registerWriteValue}});
                        if (mutation != ThreadContextStatus::ok) {
                            return ThreadContextErrorResponse(*parsed, mutation);
                        }
                    } else if (!Script::Register::Set(
                                   spec->id,
                                   static_cast<duint>(parsed->registerWriteValue))) {
                        return ErrorResponse(*parsed, "ACCESS_DENIED",
                                             "typed register write failed", false, true);
                    }
                    const ThreadContextCapture afterCapture =
                        CaptureThreadContext(parsed->targetThreadId);
                    if (afterCapture.status != ThreadContextStatus::ok) {
                        return ThreadContextErrorResponse(*parsed, afterCapture.status);
                    }
                    const std::optional<duint> observed = RegisterValue(
                        afterCapture.value.registers, parsed->registerName);
                    if (!PausedSnapshotCurrent(*snapshot) || !observed ||
                        *observed != static_cast<duint>(parsed->registerWriteValue)) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "register write read-back did not match", false, true);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(*snapshot) +
                           ",\"status\":\"ok\",\"result\":{\"name\":" +
                           JsonString(parsed->registerName) + ",\"previous_value\":" +
                           JsonString(HexValue(*previous)) + ",\"value\":" +
                           JsonString(HexValue(*observed)) + ",\"changed\":" +
                           (*previous == *observed ? "false" : "true") +
                           ",\"thread_id\":" +
                           JsonString(HexValue(afterCapture.value.threadId)) +
                           ",\"state_generation\":" + std::to_string(*snapshot) + "}}";
                }
                if (parsed->method == "registers.read") {
                    const std::optional<std::uint64_t> snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false, false);
                    }
                    const ThreadContextCapture captured =
                        CaptureThreadContext(parsed->targetThreadId);
                    if (captured.status != ThreadContextStatus::ok) {
                        return ThreadContextErrorResponse(*parsed, captured.status);
                    }
                    std::vector<std::string> names = parsed->registerNames;
                    if (names.empty()) {
#ifdef _WIN64
                        names = {"rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi", "rip", "eflags"};
#else
                        names = {"eax", "ebx", "ecx", "edx", "esp", "ebp", "esi", "edi", "eip", "eflags"};
#endif
                    }
                    std::string registers = "{";
                    for (std::size_t index = 0; index < names.size(); ++index) {
                        const std::optional<duint> value =
                            RegisterValue(captured.value.registers, names[index]);
                        if (!value) {
                            return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                                 "unknown register name", false, false);
                        }
                        std::ostringstream formatted;
                        formatted << "0x" << std::hex << std::nouppercase << *value;
                        if (index != 0U) registers.push_back(',');
                        registers += JsonString(names[index]) + ":" + JsonString(formatted.str());
                    }
                    registers += "}";
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during register snapshot", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(*snapshot) +
                           ",\"status\":\"ok\",\"result\":{\"thread_id\":" +
                           JsonString(HexValue(captured.value.threadId)) +
                           ",\"current\":" +
                           (captured.value.current ? "true" : "false") +
                           ",\"registers\":" + registers +
                           ",\"state_generation\":" + std::to_string(*snapshot) + "}}";
                }
                if (parsed->method == "strings.search") {
                    const std::optional<std::uint64_t> snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false, false);
                    }
                    if (parsed->cursorGeneration && *parsed->cursorGeneration != *snapshot) {
                        return ErrorResponse(*parsed, "STALE_CURSOR", "cursor generation is stale",
                                             false, false);
                    }
                    const auto modules = CaptureModuleRecords();
                    if (!modules) {
                        return ErrorResponse(*parsed, "INTERNAL", "module snapshot is invalid",
                                             true, false);
                    }
                    const auto module = UniqueModule(*modules, parsed->module);
                    if (!module) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "module is missing or ambiguous", false, false);
                    }
                    if (module->size > (std::numeric_limits<std::size_t>::max)() / 2U) {
                        return ErrorResponse(*parsed, "OUTPUT_LIMIT_EXCEEDED",
                                             "module is too large for string pagination", false,
                                             false);
                    }
                    const std::size_t cursorKey = parsed->cursorIndex;
                    const std::size_t scanStart = cursorKey / 2U;
                    if (scanStart > static_cast<std::size_t>(module->size)) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT", "cursor is invalid",
                                             false, false);
                    }
                    constexpr std::size_t kScanBytes = 1024U * 1024U;
                    constexpr std::size_t kChunkBytes = 64U * 1024U;
                    constexpr std::size_t kPageBytes = 4096U;
                    const std::size_t remaining = static_cast<std::size_t>(module->size) - scanStart;
                    const std::size_t scanLength = (std::min)(remaining, kScanBytes);
                    std::vector<unsigned char> bytes(scanLength);
                    std::vector<unsigned char> readable(scanLength, 0U);
                    bool incomplete = false;
                    for (std::size_t offset = 0; offset < scanLength; offset += kChunkBytes) {
                        if (std::chrono::steady_clock::now() >= requestDeadline) {
                            return ErrorResponse(*parsed, "TIMEOUT",
                                                 "string scan exceeded its deadline", true, false);
                        }
                        const std::size_t chunk = (std::min)(kChunkBytes, scanLength - offset);
                        const duint address = module->base + static_cast<duint>(scanStart + offset);
                        if (DbgMemRead(address, bytes.data() + offset, static_cast<duint>(chunk))) {
                            std::fill(readable.begin() + static_cast<std::ptrdiff_t>(offset),
                                      readable.begin() + static_cast<std::ptrdiff_t>(offset + chunk),
                                      1U);
                        } else {
                            incomplete = true;
                            for (std::size_t page = 0; page < chunk; page += kPageBytes) {
                                const std::size_t pageSize = (std::min)(kPageBytes, chunk - page);
                                if (DbgMemRead(address + static_cast<duint>(page),
                                               bytes.data() + offset + page,
                                               static_cast<duint>(pageSize))) {
                                    std::fill(
                                        readable.begin() +
                                            static_cast<std::ptrdiff_t>(offset + page),
                                        readable.begin() +
                                            static_cast<std::ptrdiff_t>(offset + page + pageSize),
                                        1U);
                                }
                            }
                        }
                        if (!PausedSnapshotCurrent(*snapshot)) {
                            return ErrorResponse(*parsed, "BUSY",
                                                 "debugger changed during string scan", true,
                                                 false);
                        }
                    }
                    const auto literalMatch = [parsed](const std::string_view text) {
                        if (!IsValidUtf8(text)) return std::optional<Utf8LiteralMatch>{};
                        if (parsed->query.empty()) return std::optional<Utf8LiteralMatch>(
                            Utf8LiteralMatch{});
                        return Utf8OrdinalMatchIgnoreCase(text, parsed->query);
                    };
                    std::vector<StringCandidate> ascii;
                    std::vector<StringCandidate> wide;
                    const std::size_t retain = parsed->pageLimit + 1U;
                    if (parsed->stringEncoding != "utf16le") {
                        const std::string_view scannedText = bytes.empty()
                                                                 ? std::string_view{}
                                                                 : std::string_view(
                                                                       reinterpret_cast<const char*>(
                                                                           bytes.data()),
                                                                       bytes.size());
                        const auto printableLength = [&readable, scannedText](
                                                         const std::size_t at) {
                            if (readable[at] == 0U) return std::size_t{0};
                            const auto first = static_cast<unsigned char>(scannedText[at]);
                            if (first < 0x20U || first == 0x7fU) return std::size_t{0};
                            const std::size_t length = Utf8SequenceLength(scannedText, at);
                            if (length == 0U || at + length > readable.size()) return std::size_t{0};
                            for (std::size_t index = 0; index < length; ++index) {
                                if (readable[at + index] == 0U) return std::size_t{0};
                            }
                            return length;
                        };
                        for (std::size_t offset = 0; offset < scanLength;) {
                            if ((offset & 0xffffU) == 0U &&
                                std::chrono::steady_clock::now() >= requestDeadline) {
                                return ErrorResponse(*parsed, "TIMEOUT",
                                                     "string extraction exceeded its deadline",
                                                     true, false);
                            }
                            if ((offset & 0xffffU) == 0U &&
                                !PausedSnapshotCurrent(*snapshot)) {
                                return ErrorResponse(*parsed, "BUSY",
                                                     "debugger changed during string extraction",
                                                     true, false);
                            }
                            if (printableLength(offset) == 0U) { ++offset; continue; }
                            const std::size_t begin = offset;
                            std::size_t characterCount = 0U;
                            std::size_t nextCheck = 64U * 1024U;
                            while (offset < scanLength) {
                                const std::size_t sequenceLength = printableLength(offset);
                                if (sequenceLength == 0U) break;
                                offset += sequenceLength;
                                ++characterCount;
                                if (offset - begin >= nextCheck) {
                                    if (std::chrono::steady_clock::now() >= requestDeadline) {
                                        return ErrorResponse(
                                            *parsed, "TIMEOUT",
                                            "string extraction exceeded its deadline", true,
                                            false);
                                    }
                                    if (!PausedSnapshotCurrent(*snapshot)) {
                                        return ErrorResponse(
                                            *parsed, "BUSY",
                                            "debugger changed during string extraction", true,
                                            false);
                                    }
                                    nextCheck += 64U * 1024U;
                                }
                            }
                            const std::size_t length = offset - begin;
                            const std::size_t absoluteOffset = scanStart + begin;
                            const std::size_t key = absoluteOffset * 2U;
                            const std::string_view text(
                                reinterpret_cast<const char*>(bytes.data() + begin), length);
                            const auto match = literalMatch(text);
                            if (characterCount >= parsed->minStringLength && key >= cursorKey &&
                                match && ascii.size() < retain) {
                                StringCandidate candidate;
                                candidate.offset = absoluteOffset;
                                candidate.byteLength = length;
                                candidate.encoding = "ascii_utf8";
                                candidate.key = key;
                                candidate.matchOffset = match->offset;
                                if (parsed->query.empty()) {
                                    const auto context = ContextAroundUtf8Match(text, 0U);
                                    candidate.text = context.text;
                                    candidate.textOffset = context.offset;
                                    candidate.truncated = context.truncated;
                                } else {
                                    const auto context = Utf8ContextAroundMatch(
                                        text, *match, parsed->stringContextBytes);
                                    if (!context) continue;
                                    candidate.text = context->text;
                                    candidate.textOffset = context->textOffset;
                                    candidate.truncated = context->truncated;
                                    candidate.before = context->before;
                                    candidate.match = context->match;
                                    candidate.after = context->after;
                                    candidate.hasMatch = true;
                                }
                                ascii.push_back(std::move(candidate));
                            }
                        }
                    }
                    if (parsed->stringEncoding != "ascii_utf8") {
                        for (std::size_t offset = 0; offset + 1U < scanLength;) {
                            if ((offset & 0xffffU) == 0U &&
                                std::chrono::steady_clock::now() >= requestDeadline) {
                                return ErrorResponse(*parsed, "TIMEOUT",
                                                     "string extraction exceeded its deadline",
                                                     true, false);
                            }
                            if ((offset & 0xffffU) == 0U &&
                                !PausedSnapshotCurrent(*snapshot)) {
                                return ErrorResponse(*parsed, "BUSY",
                                                     "debugger changed during string extraction",
                                                     true, false);
                            }
                            const std::size_t absoluteOffset = scanStart + offset;
                            if ((absoluteOffset & 1U) != 0U || readable[offset] == 0U ||
                                readable[offset + 1U] == 0U) { ++offset; continue; }
                            const auto unitAt = [&bytes](const std::size_t at) -> std::uint16_t {
                                return static_cast<std::uint16_t>(
                                    static_cast<unsigned int>(bytes[at]) |
                                    (static_cast<unsigned int>(bytes[at + 1U]) << 8U));
                            };
                            const auto printableUnits = [&readable, &unitAt, scanLength](
                                                            const std::size_t at) {
                                if (at + 1U >= scanLength || readable[at] == 0U ||
                                    readable[at + 1U] == 0U) return std::size_t{0};
                                const std::uint16_t first = unitAt(at);
                                if (first < 0x20U || first == 0x7fU ||
                                    (first >= 0xdc00U && first <= 0xdfffU)) {
                                    return std::size_t{0};
                                }
                                if (first < 0xd800U || first > 0xdbffU) return std::size_t{1};
                                if (at + 3U >= scanLength || readable[at + 2U] == 0U ||
                                    readable[at + 3U] == 0U) return std::size_t{0};
                                const std::uint16_t second = unitAt(at + 2U);
                                return second >= 0xdc00U && second <= 0xdfffU ? std::size_t{2}
                                                                            : std::size_t{0};
                            };
                            if (printableUnits(offset) == 0U) { offset += 2U; continue; }
                            const std::size_t begin = offset;
                            std::vector<wchar_t> units;
                            std::size_t nextCheck = 64U * 1024U;
                            while (offset + 1U < scanLength) {
                                const std::size_t unitCount = printableUnits(offset);
                                if (unitCount == 0U) break;
                                for (std::size_t index = 0; index < unitCount; ++index) {
                                    units.push_back(
                                        static_cast<wchar_t>(unitAt(offset + index * 2U)));
                                }
                                offset += unitCount * 2U;
                                if (offset - begin >= nextCheck) {
                                    if (std::chrono::steady_clock::now() >= requestDeadline) {
                                        return ErrorResponse(
                                            *parsed, "TIMEOUT",
                                            "string extraction exceeded its deadline", true,
                                            false);
                                    }
                                    if (!PausedSnapshotCurrent(*snapshot)) {
                                        return ErrorResponse(
                                            *parsed, "BUSY",
                                            "debugger changed during string extraction", true,
                                            false);
                                    }
                                    nextCheck += 64U * 1024U;
                                }
                            }
                            const auto text = Utf16ToUtf8(units);
                            const std::size_t key = (scanStart + begin) * 2U + 1U;
                            const auto match = text ? literalMatch(*text)
                                                    : std::optional<Utf8LiteralMatch>{};
                            if (units.size() >= parsed->minStringLength && key >= cursorKey && text &&
                                match && wide.size() < retain) {
                                StringCandidate candidate;
                                candidate.offset = scanStart + begin;
                                candidate.byteLength = units.size() * 2U;
                                candidate.encoding = "utf16le";
                                candidate.key = key;
                                candidate.matchOffset = match->offset;
                                if (parsed->query.empty()) {
                                    const auto context = ContextAroundUtf8Match(*text, 0U);
                                    candidate.text = context.text;
                                    candidate.textOffset = context.offset;
                                    candidate.truncated = context.truncated;
                                } else {
                                    const auto context = Utf8ContextAroundMatch(
                                        *text, *match, parsed->stringContextBytes);
                                    if (!context) continue;
                                    candidate.text = context->text;
                                    candidate.textOffset = context->textOffset;
                                    candidate.truncated = context->truncated;
                                    candidate.before = context->before;
                                    candidate.match = context->match;
                                    candidate.after = context->after;
                                    candidate.hasMatch = true;
                                }
                                wide.push_back(std::move(candidate));
                            }
                            if (offset == begin) offset += 2U;
                        }
                    }
                    std::vector<StringCandidate> candidates;
                    candidates.reserve(ascii.size() + wide.size());
                    std::move(ascii.begin(), ascii.end(), std::back_inserter(candidates));
                    std::move(wide.begin(), wide.end(), std::back_inserter(candidates));
                    std::sort(candidates.begin(), candidates.end(), [](const auto& left, const auto& right) {
                        return left.key < right.key;
                    });
                    const std::size_t returned = (std::min)(candidates.size(), parsed->pageLimit);
                    std::string items = "[";
                    for (std::size_t index = 0; index < returned; ++index) {
                        if (index != 0U) items.push_back(',');
                        const auto& candidate = candidates[index];
                        const duint address = module->base + static_cast<duint>(candidate.offset);
                        items += "{\"text\":" + JsonString(candidate.text) +
                                 ",\"encoding\":" + JsonString(candidate.encoding) +
                                 ",\"byte_length\":" + std::to_string(candidate.byteLength) +
                                 ",\"match_offset\":" + std::to_string(candidate.matchOffset) +
                                 ",\"text_offset\":" + std::to_string(candidate.textOffset) +
                                 ",\"truncated\":" + (candidate.truncated ? "true" : "false") +
                                 ",\"location\":" +
                                 LocationJson(LocationFromModules(address, *modules), *snapshot);
                        if (candidate.hasMatch) {
                            items += ",\"before\":" + JsonString(candidate.before) +
                                     ",\"match\":" + JsonString(candidate.match) +
                                     ",\"after\":" + JsonString(candidate.after);
                        }
                        items += "}";
                    }
                    items += "]";
                    const std::size_t scanEnd = scanStart + scanLength;
                    std::string next = "null";
                    if (candidates.size() > returned) {
                        next = JsonString(DiscoveryCursor(*parsed, *snapshot,
                                                          candidates[returned].key));
                    } else if (scanEnd < static_cast<std::size_t>(module->size)) {
                        next = JsonString(DiscoveryCursor(*parsed, *snapshot, scanEnd * 2U));
                    }
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during string scan", true, false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(*snapshot) +
                           ",\"status\":\"ok\",\"result\":{\"items\":" + items +
                           ",\"next_cursor\":" + next + ",\"bytes_scanned\":" +
                           std::to_string(scanLength) + ",\"incomplete\":" +
                           (incomplete ? "true" : "false") +
                           ",\"completeness\":\"known_only\",\"state_generation\":" +
                           std::to_string(*snapshot) + "}}";
                }
                if (parsed->method == "patches.list") {
                    const std::optional<std::uint64_t> snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false, false);
                    }
                    if (parsed->cursorGeneration && *parsed->cursorGeneration != *snapshot) {
                        return ErrorResponse(*parsed, "STALE_CURSOR", "cursor generation is stale",
                                             false, false);
                    }
                    const auto modules = CaptureModuleRecords();
                    if (!modules) {
                        return ErrorResponse(*parsed, "INTERNAL", "module snapshot is invalid",
                                             true, false);
                    }
                    std::optional<ModuleRecord> selectedModule;
                    if (!parsed->module.empty()) {
                        selectedModule = UniqueModule(*modules, parsed->module);
                        if (!selectedModule) {
                            return ErrorResponse(*parsed, "NOT_FOUND",
                                                 "module is not uniquely loaded", false, false);
                        }
                    }
                    const DBGFUNCTIONS* functions = DbgFunctions();
                    if (functions == nullptr || functions->PatchEnum == nullptr) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "native patch enumeration is unavailable", false,
                                             false);
                    }
                    std::size_t firstBytes = 0U;
                    functions->PatchEnum(nullptr, &firstBytes);
                    if (firstBytes % sizeof(DBGPATCHINFO) != 0U) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "patch size probe is inconsistent", true, false);
                    }
                    const std::size_t recordCount = firstBytes / sizeof(DBGPATCHINFO);
                    if (recordCount > 65536U) {
                        return ErrorResponse(*parsed, "OUTPUT_LIMIT_EXCEEDED",
                                             "patch database exceeds native bounds", false,
                                             false);
                    }
                    std::vector<DBGPATCHINFO> nativeRecords(recordCount);
                    std::size_t enumeratedBytes = firstBytes;
                    if (recordCount != 0U &&
                        (!functions->PatchEnum(nativeRecords.data(), &enumeratedBytes) ||
                         enumeratedBytes != firstBytes)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "patch database changed during enumeration", true,
                                             false);
                    }
                    std::size_t finalBytes = 0U;
                    functions->PatchEnum(nullptr, &finalBytes);
                    if (finalBytes != firstBytes) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "patch database changed after enumeration", true,
                                             false);
                    }
                    std::vector<TrackedPatchByte> records;
                    records.reserve(recordCount);
                    for (const auto& native : nativeRecords) {
                        const std::size_t moduleLength = strnlen_s(native.mod, sizeof(native.mod));
                        if (moduleLength == 0U || moduleLength == sizeof(native.mod) ||
                            native.oldbyte == native.newbyte) {
                            return ErrorResponse(*parsed, "BUSY",
                                                 "patch enumeration contains an invalid record",
                                                 true, false);
                        }
                        const std::string moduleName(native.mod, moduleLength);
                        const auto owner = UniqueModule(*modules, moduleName);
                        const auto location = LocationFromModules(native.addr, *modules);
                        if (!owner || !location.module ||
                            !Utf8OrdinalEqualsIgnoreCase(owner->name, *location.module)) {
                            return ErrorResponse(*parsed, "BUSY",
                                                 "patch record is outside its named module", true,
                                                 false);
                        }
                        records.push_back(TrackedPatchByte{owner->name, native.addr,
                                                           native.oldbyte, native.newbyte});
                    }
                    std::sort(records.begin(), records.end(), [](const auto& left,
                                                                  const auto& right) {
                        if (left.address != right.address) return left.address < right.address;
                        return left.module < right.module;
                    });
                    const std::uint64_t fingerprint = TrackedPatchFingerprint(records);
                    if (parsed->cursorSnapshotFingerprint &&
                        *parsed->cursorSnapshotFingerprint != fingerprint) {
                        return ErrorResponse(*parsed, "STALE_CURSOR",
                                             "patch snapshot changed between pages", false,
                                             false);
                    }
                    if (selectedModule) {
                        std::erase_if(records, [&](const auto& record) {
                            return !Utf8OrdinalEqualsIgnoreCase(record.module,
                                                                 selectedModule->name);
                        });
                    }
                    const auto ranges = NormalizeTrackedPatches(std::move(records));
                    if (!ranges) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "patch records cannot form stable ranges", true,
                                             false);
                    }
                    if (parsed->cursorIndex > ranges->size()) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT", "cursor is invalid",
                                             false, false);
                    }
                    const std::size_t end =
                        (std::min)(ranges->size(), parsed->cursorIndex + parsed->pageLimit);
                    std::string items = "[";
                    for (std::size_t index = parsed->cursorIndex; index < end; ++index) {
                        if (std::chrono::steady_clock::now() >= requestDeadline) {
                            return ErrorResponse(*parsed, "TIMEOUT",
                                                 "patch listing exceeded its deadline", true,
                                                 false);
                        }
                        const auto& range = (*ranges)[index];
                        std::vector<unsigned char> current(range.patched.size());
                        if (!DbgMemRead(range.address, current.data(),
                                        static_cast<duint>(current.size()))) {
                            return ErrorResponse(*parsed, "ACCESS_DENIED",
                                                 "current patch bytes are not readable", false,
                                                 false);
                        }
                        if (index != parsed->cursorIndex) items.push_back(',');
                        items += "{\"start\":" +
                                 LocationJson(LocationFromModules(range.address, *modules),
                                              *snapshot) +
                                 ",\"length\":" + std::to_string(range.patched.size()) +
                                 ",\"original_bytes_hex\":" + JsonString(Hex(range.original)) +
                                 ",\"patched_bytes_hex\":" + JsonString(Hex(range.patched)) +
                                 ",\"current_bytes_hex\":" + JsonString(Hex(current)) +
                                 ",\"current_matches_patch\":" +
                                 (current == range.patched ? "true" : "false") + "}";
                    }
                    items += "]";
                    const std::string next =
                        end < ranges->size()
                            ? JsonString(PatchCursor(*parsed, *snapshot, fingerprint, end))
                            : "null";
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during patch listing", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(*snapshot) +
                           ",\"status\":\"ok\",\"result\":{\"items\":" + items +
                           ",\"next_cursor\":" + next +
                           ",\"completeness\":\"tracked_only\",\"snapshot_fingerprint\":" +
                           JsonString(HexValue(fingerprint)) +
                           ",\"state_generation\":" + std::to_string(*snapshot) + "}}";
                }
                if (parsed->method == "symbols.resolve") {
                    const std::optional<std::uint64_t> snapshot = parsed->addressProvided
                                                                      ? resolvedGeneration
                                                                      : BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false, false);
                    }
                    const auto modules = CaptureModuleRecords();
                    if (!modules) {
                        return ErrorResponse(*parsed, "INTERNAL", "module snapshot is invalid",
                                             true, false);
                    }
                    std::optional<ModuleRecord> selectedModule;
                    if (parsed->addressProvided) {
                        if (resolvedLocation->module) {
                            selectedModule = UniqueModule(*modules, *resolvedLocation->module);
                        }
                    } else {
                        selectedModule = UniqueModule(*modules, parsed->module);
                        if (!selectedModule) {
                            return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                                 "module is missing or ambiguous", false, false);
                        }
                    }
                    ListInfo list{};
                    if (!Script::Symbol::GetList(&list)) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "symbol database is unavailable", true, false);
                    }
                    struct ResolveSymbolGuard {
                        void* p;
                        ~ResolveSymbolGuard() { if (p) BridgeFree(p); }
                    } guard{list.data};
                    if (list.count < 0 || list.count > 65536 ||
                        (list.count > 0 && list.data == nullptr) ||
                        list.size != static_cast<std::size_t>(list.count) *
                                         sizeof(Script::Symbol::SymbolInfo)) {
                        return ErrorResponse(*parsed, "OUTPUT_LIMIT_EXCEEDED",
                                             "symbol database exceeds native bounds", false,
                                             false);
                    }
                    const auto* values =
                        static_cast<const Script::Symbol::SymbolInfo*>(list.data);
                    std::size_t totalMatches = 0U;
                    std::string matches = "[";
                    for (int index = 0; index < list.count; ++index) {
                        if ((index & 0xff) == 0 &&
                            std::chrono::steady_clock::now() >= requestDeadline) {
                            return ErrorResponse(*parsed, "TIMEOUT",
                                                 "symbol resolution exceeded its deadline", true,
                                                 false);
                        }
                        const auto& symbol = values[index];
                        const std::string_view symbolModule(
                            symbol.mod, strnlen_s(symbol.mod, sizeof(symbol.mod)));
                        const std::string_view name(
                            symbol.name, strnlen_s(symbol.name, sizeof(symbol.name)));
                        if (!selectedModule ||
                            !Utf8OrdinalEqualsIgnoreCase(symbolModule,
                                                         selectedModule->name) ||
                            symbol.rva >= selectedModule->size ||
                            selectedModule->base >
                                (std::numeric_limits<duint>::max)() - symbol.rva) {
                            continue;
                        }
                        const duint symbolAddress = selectedModule->base + symbol.rva;
                        const bool match = parsed->addressProvided
                                               ? symbolAddress == resolvedLocation->address
                                               : name == parsed->symbolName;
                        if (!match) continue;
                        ++totalMatches;
                        if (totalMatches > 32U) continue;
                        if (totalMatches != 1U) matches.push_back(',');
                        const char* type = symbol.type == Script::Symbol::Function
                                               ? "function"
                                               : symbol.type == Script::Symbol::Import
                                                     ? "import"
                                                     : "export";
                        matches += "{\"name\":" + JsonString(name) + ",\"type\":" +
                                   JsonString(type) + ",\"manual\":" +
                                   (symbol.manual ? "true" : "false") +
                                   ",\"location\":" +
                                   LocationJson(LocationFromModules(symbolAddress, *modules),
                                                *snapshot) +
                                   "}";
                    }
                    matches += "]";
                    const char* resolution = totalMatches == 0U
                                                 ? "missing"
                                                 : totalMatches == 1U ? "found" : "ambiguous";
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during symbol resolution", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(*snapshot) +
                           ",\"status\":\"ok\",\"result\":{\"resolution\":" +
                           JsonString(resolution) + ",\"matches\":" + matches +
                           ",\"total_matches\":" + std::to_string(totalMatches) +
                           ",\"matches_truncated\":" +
                           (totalMatches > 32U ? "true" : "false") +
                           ",\"completeness\":\"known_only\",\"state_generation\":" +
                           std::to_string(*snapshot) + "}}";
                }
                if (parsed->method == "symbols.search" ||
                    parsed->method == "functions.list" ||
                    parsed->method == "imports.list" || parsed->method == "exports.list" ||
                    parsed->method == "sections.list") {
                    const std::optional<std::uint64_t> snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false, false);
                    }
                    if (parsed->cursorGeneration && *parsed->cursorGeneration != *snapshot) {
                        return ErrorResponse(*parsed, "STALE_CURSOR", "cursor generation is stale",
                                             false, false);
                    }
                    const auto modules = CaptureModuleRecords();
                    if (!modules) {
                        return ErrorResponse(*parsed, "INTERNAL", "module snapshot is invalid",
                                             true, false);
                    }
                    const auto module = UniqueModule(*modules, parsed->module);
                    if (!module) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "module is missing or ambiguous", false, false);
                    }
                    const auto fixedString = [](const char* value,
                                                const std::size_t capacity)
                        -> std::optional<std::string_view> {
                        const std::size_t length = strnlen_s(value, capacity);
                        if (length == capacity) return std::nullopt;
                        const std::string_view text(value, length);
                        return IsValidUtf8(text) ? std::optional<std::string_view>(text)
                                                 : std::nullopt;
                    };
                    if (parsed->method == "sections.list") {
                        Script::Module::ModuleInfo nativeModule{};
                        if (!Script::Module::InfoFromAddr(module->base, &nativeModule) ||
                            nativeModule.base != module->base || nativeModule.size != module->size) {
                            return ErrorResponse(*parsed, "BUSY",
                                                 "module changed during section read", true,
                                                 false);
                        }
                        if (nativeModule.sectionCount < 0 || nativeModule.sectionCount > 4096 ||
                            module->size == 0U ||
                            module->base > (std::numeric_limits<duint>::max)() - module->size) {
                            return ErrorResponse(*parsed, "OUTPUT_LIMIT_EXCEEDED",
                                                 "module section metadata exceeds native bounds",
                                                 false, false);
                        }
                        ListInfo list{};
                        if (!Script::Module::SectionListFromAddr(module->base, &list)) {
                            return ErrorResponse(*parsed, "INTERNAL",
                                                 "module sections are unavailable", true, false);
                        }
                        struct SectionGuard {
                            void* p;
                            ~SectionGuard() { if (p) BridgeFree(p); }
                        } guard{list.data};
                        if (list.count < 0 || list.count > 4096 ||
                            list.count != nativeModule.sectionCount ||
                            (list.count > 0 && list.data == nullptr) ||
                            list.size != static_cast<std::size_t>(list.count) *
                                             sizeof(Script::Module::ModuleSectionInfo)) {
                            return ErrorResponse(*parsed, "OUTPUT_LIMIT_EXCEEDED",
                                                 "module section list exceeds native bounds",
                                                 false, false);
                        }
                        const auto* values =
                            static_cast<const Script::Module::ModuleSectionInfo*>(list.data);
                        const std::size_t count = static_cast<std::size_t>(list.count);
                        if (parsed->cursorIndex > count) {
                            return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                                 "cursor is invalid", false, false);
                        }
                        std::size_t matched = 0U;
                        for (std::size_t index = 0U; index < count; ++index) {
                            if ((index & 0xffU) == 0U &&
                                std::chrono::steady_clock::now() >= requestDeadline) {
                                return ErrorResponse(*parsed, "TIMEOUT",
                                                     "section filtering exceeded its deadline",
                                                     true, false);
                            }
                            const auto& section = values[index];
                            const auto name = fixedString(section.name, sizeof(section.name));
                            if (!name || section.addr < module->base) {
                                return ErrorResponse(*parsed, "INTERNAL",
                                                     "module section record is invalid", false,
                                                     false);
                            }
                            const duint offset = section.addr - module->base;
                            if (offset >= module->size || section.size > module->size - offset) {
                                return ErrorResponse(*parsed, "INTERNAL",
                                                     "module section range is invalid", false,
                                                     false);
                            }
                            if (parsed->query.empty() ||
                                Utf8OrdinalContainsIgnoreCase(*name, parsed->query)) {
                                ++matched;
                            }
                        }
                        std::string items = "[";
                        std::size_t index = parsed->cursorIndex;
                        std::size_t emitted = 0U;
                        for (; index < count && emitted < parsed->pageLimit; ++index) {
                            const auto& section = values[index];
                            const auto name = fixedString(section.name, sizeof(section.name));
                            if (!name) {
                                return ErrorResponse(*parsed, "INTERNAL",
                                                     "module section text is invalid", false,
                                                     false);
                            }
                            if (!parsed->query.empty() &&
                                !Utf8OrdinalContainsIgnoreCase(*name, parsed->query)) {
                                continue;
                            }
                            if (emitted++ != 0U) items.push_back(',');
                            items += "{\"index\":" + std::to_string(index) +
                                     ",\"name\":" +
                                     (name->empty() ? "null" : JsonString(*name)) +
                                     ",\"start\":" +
                                     LocationJson(LocationFromModules(section.addr, *modules),
                                                  *snapshot) +
                                     ",\"size\":" + JsonString(HexValue(section.size)) +
                                     ",\"end_exclusive\":" +
                                     JsonString(HexValue(section.addr + section.size)) + "}";
                        }
                        items += "]";
                        const std::string next =
                            index < count ? JsonString(DiscoveryCursor(*parsed, *snapshot, index))
                                          : "null";
                        if (!PausedSnapshotCurrent(*snapshot)) {
                            return ErrorResponse(*parsed, "BUSY",
                                                 "debugger changed during section read", true,
                                                 false);
                        }
                        return "{\"request_id\":" + JsonString(parsed->requestId) +
                               ",\"state_generation\":" + std::to_string(*snapshot) +
                               ",\"status\":\"ok\",\"result\":{\"module\":" +
                               JsonString(module->name) + ",\"native_count\":" +
                               std::to_string(count) + ",\"matched_count\":" +
                               std::to_string(matched) + ",\"items\":" + items +
                               ",\"next_cursor\":" + next +
                               ",\"completeness\":\"loaded_image_sections\",\"state_generation\":" +
                               std::to_string(*snapshot) + "}}";
                    }
                    if (parsed->method == "imports.list" ||
                        parsed->method == "exports.list") {
                        Script::Module::ModuleInfo nativeModule{};
                        if (!Script::Module::InfoFromAddr(module->base, &nativeModule) ||
                            nativeModule.base != module->base || nativeModule.size != module->size) {
                            return ErrorResponse(*parsed, "BUSY",
                                                 "module changed during linkage read", true,
                                                 false);
                        }
                        if (parsed->method == "imports.list") {
                            ListInfo list{};
                            if (!Script::Module::GetImports(&nativeModule, &list)) {
                                return ErrorResponse(*parsed, "INTERNAL",
                                                     "module imports are unavailable", true,
                                                     false);
                            }
                            struct ImportGuard {
                                void* p;
                                ~ImportGuard() { if (p) BridgeFree(p); }
                            } guard{list.data};
                            if (list.count < 0 || list.count > 65536 ||
                                (list.count > 0 && list.data == nullptr) ||
                                list.size != static_cast<std::size_t>(list.count) *
                                                 sizeof(Script::Module::ModuleImport)) {
                                return ErrorResponse(*parsed, "OUTPUT_LIMIT_EXCEEDED",
                                                     "module import list exceeds native bounds",
                                                     false, false);
                            }
                            const auto* values =
                                static_cast<const Script::Module::ModuleImport*>(list.data);
                            const std::size_t count = static_cast<std::size_t>(list.count);
                            if (parsed->cursorIndex > count) {
                                return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                                     "cursor is invalid", false, false);
                            }
                            std::size_t matched = 0U;
                            for (std::size_t index = 0U; index < count; ++index) {
                                if ((index & 0xffU) == 0U &&
                                    std::chrono::steady_clock::now() >= requestDeadline) {
                                    return ErrorResponse(*parsed, "TIMEOUT",
                                                         "import filtering exceeded its deadline",
                                                         true, false);
                                }
                                const auto name = fixedString(values[index].name,
                                                              sizeof(values[index].name));
                                const auto undecorated = fixedString(
                                    values[index].undecoratedName,
                                    sizeof(values[index].undecoratedName));
                                if (!name || !undecorated) {
                                    return ErrorResponse(*parsed, "INTERNAL",
                                                         "module import text is invalid", false,
                                                         false);
                                }
                                if (parsed->query.empty() ||
                                    Utf8OrdinalContainsIgnoreCase(*name, parsed->query) ||
                                    Utf8OrdinalContainsIgnoreCase(*undecorated, parsed->query)) {
                                    ++matched;
                                }
                            }
                            std::string items = "[";
                            std::size_t index = parsed->cursorIndex;
                            std::size_t emitted = 0U;
                            for (; index < count && emitted < parsed->pageLimit; ++index) {
                                const auto& import = values[index];
                                const auto name = fixedString(import.name, sizeof(import.name));
                                const auto undecorated = fixedString(
                                    import.undecoratedName, sizeof(import.undecoratedName));
                                if (!name || !undecorated || import.iatRva >= module->size ||
                                    module->base > (std::numeric_limits<duint>::max)() -
                                                       import.iatRva ||
                                    import.iatVa != module->base + import.iatRva) {
                                    return ErrorResponse(*parsed, "INTERNAL",
                                                         "module import record is invalid", false,
                                                         false);
                                }
                                if (!parsed->query.empty() &&
                                    !Utf8OrdinalContainsIgnoreCase(*name, parsed->query) &&
                                    !Utf8OrdinalContainsIgnoreCase(*undecorated, parsed->query)) {
                                    continue;
                                }
                                duint target = 0U;
                                const bool readable =
                                    DbgMemRead(import.iatVa, &target, sizeof(target));
                                const char* resolution =
                                    !readable ? "unreadable" : target == 0U ? "unresolved"
                                                                            : "resolved";
                                if (emitted++ != 0U) items.push_back(',');
                                items += "{\"name\":" +
                                         (name->empty() ? "null" : JsonString(*name)) +
                                         ",\"undecorated_name\":" +
                                         (undecorated->empty() ? "null" :
                                                                 JsonString(*undecorated)) +
                                         ",\"ordinal\":" +
                                         (import.ordinal == (std::numeric_limits<duint>::max)()
                                              ? "null"
                                              : std::to_string(import.ordinal)) +
                                         ",\"iat\":" +
                                         LocationJson(LocationFromModules(import.iatVa, *modules),
                                                      *snapshot) +
                                         ",\"resolution\":" + JsonString(resolution) +
                                         ",\"resolved_target\":" +
                                         (readable && target != 0U
                                              ? LocationJson(
                                                    LocationFromModules(target, *modules), *snapshot)
                                              : "null") +
                                         "}";
                            }
                            items += "]";
                            const std::string next =
                                index < count
                                    ? JsonString(DiscoveryCursor(*parsed, *snapshot, index))
                                    : "null";
                            if (!PausedSnapshotCurrent(*snapshot)) {
                                return ErrorResponse(*parsed, "BUSY",
                                                     "debugger changed during import read", true,
                                                     false);
                            }
                            return "{\"request_id\":" + JsonString(parsed->requestId) +
                                   ",\"state_generation\":" + std::to_string(*snapshot) +
                                   ",\"status\":\"ok\",\"result\":{\"module\":" +
                                   JsonString(module->name) + ",\"native_count\":" +
                                   std::to_string(count) + ",\"matched_count\":" +
                                   std::to_string(matched) + ",\"items\":" + items +
                                   ",\"next_cursor\":" + next +
                                   ",\"completeness\":\"known_only\",\"state_generation\":" +
                                   std::to_string(*snapshot) + "}}";
                        }

                        ListInfo list{};
                        if (!Script::Module::GetExports(&nativeModule, &list)) {
                            return ErrorResponse(*parsed, "INTERNAL",
                                                 "module exports are unavailable", true, false);
                        }
                        struct ExportGuard {
                            void* p;
                            ~ExportGuard() { if (p) BridgeFree(p); }
                        } guard{list.data};
                        if (list.count < 0 || list.count > 65536 ||
                            (list.count > 0 && list.data == nullptr) ||
                            list.size != static_cast<std::size_t>(list.count) *
                                             sizeof(Script::Module::ModuleExport)) {
                            return ErrorResponse(*parsed, "OUTPUT_LIMIT_EXCEEDED",
                                                 "module export list exceeds native bounds", false,
                                                 false);
                        }
                        const auto* values =
                            static_cast<const Script::Module::ModuleExport*>(list.data);
                        const std::size_t count = static_cast<std::size_t>(list.count);
                        if (parsed->cursorIndex > count) {
                            return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                                 "cursor is invalid", false, false);
                        }
                        std::size_t matched = 0U;
                        for (std::size_t index = 0U; index < count; ++index) {
                            if ((index & 0xffU) == 0U &&
                                std::chrono::steady_clock::now() >= requestDeadline) {
                                return ErrorResponse(*parsed, "TIMEOUT",
                                                     "export filtering exceeded its deadline",
                                                     true, false);
                            }
                            const auto name = fixedString(values[index].name,
                                                          sizeof(values[index].name));
                            const auto undecorated = fixedString(
                                values[index].undecoratedName,
                                sizeof(values[index].undecoratedName));
                            const auto forward = fixedString(values[index].forwardName,
                                                             sizeof(values[index].forwardName));
                            if (!name || !undecorated || !forward) {
                                return ErrorResponse(*parsed, "INTERNAL",
                                                     "module export text is invalid", false,
                                                     false);
                            }
                            if (parsed->query.empty() ||
                                Utf8OrdinalContainsIgnoreCase(*name, parsed->query) ||
                                Utf8OrdinalContainsIgnoreCase(*undecorated, parsed->query) ||
                                Utf8OrdinalContainsIgnoreCase(*forward, parsed->query)) ++matched;
                        }
                        std::string items = "[";
                        std::size_t index = parsed->cursorIndex;
                        std::size_t emitted = 0U;
                        for (; index < count && emitted < parsed->pageLimit; ++index) {
                            const auto& entry = values[index];
                            const auto name = fixedString(entry.name, sizeof(entry.name));
                            const auto undecorated = fixedString(entry.undecoratedName,
                                                                 sizeof(entry.undecoratedName));
                            const auto forward = fixedString(entry.forwardName,
                                                             sizeof(entry.forwardName));
                            if (!name || !undecorated || !forward || entry.rva >= module->size ||
                                module->base > (std::numeric_limits<duint>::max)() - entry.rva ||
                                entry.va != module->base + entry.rva ||
                                (entry.forwarded && forward->empty())) {
                                return ErrorResponse(*parsed, "INTERNAL",
                                                     "module export record is invalid", false,
                                                     false);
                            }
                            if (!parsed->query.empty() &&
                                !Utf8OrdinalContainsIgnoreCase(*name, parsed->query) &&
                                !Utf8OrdinalContainsIgnoreCase(*undecorated, parsed->query) &&
                                !Utf8OrdinalContainsIgnoreCase(*forward, parsed->query)) continue;
                            if (emitted++ != 0U) items.push_back(',');
                            items += "{\"name\":" +
                                     (name->empty() ? "null" : JsonString(*name)) +
                                     ",\"undecorated_name\":" +
                                     (undecorated->empty() ? "null" : JsonString(*undecorated)) +
                                     ",\"ordinal\":" + std::to_string(entry.ordinal) +
                                     ",\"location\":" +
                                     LocationJson(LocationFromModules(entry.va, *modules),
                                                  *snapshot) +
                                     ",\"forwarded\":" +
                                     (entry.forwarded ? "true" : "false") +
                                     ",\"forward_name\":" +
                                     (entry.forwarded ? JsonString(*forward) : "null") + "}";
                        }
                        items += "]";
                        const std::string next =
                            index < count ? JsonString(DiscoveryCursor(*parsed, *snapshot, index))
                                          : "null";
                        if (!PausedSnapshotCurrent(*snapshot)) {
                            return ErrorResponse(*parsed, "BUSY",
                                                 "debugger changed during export read", true,
                                                 false);
                        }
                        return "{\"request_id\":" + JsonString(parsed->requestId) +
                               ",\"state_generation\":" + std::to_string(*snapshot) +
                               ",\"status\":\"ok\",\"result\":{\"module\":" +
                               JsonString(module->name) + ",\"native_count\":" +
                               std::to_string(count) + ",\"matched_count\":" +
                               std::to_string(matched) + ",\"items\":" + items +
                               ",\"next_cursor\":" + next +
                               ",\"completeness\":\"known_only\",\"state_generation\":" +
                               std::to_string(*snapshot) + "}}";
                    }
                    if (parsed->method == "symbols.search") {
                        ListInfo list{};
                        if (!Script::Symbol::GetList(&list)) {
                            return ErrorResponse(*parsed, "INTERNAL",
                                                 "symbol database is unavailable", true, false);
                        }
                        struct Guard { void* p; ~Guard() { if (p) BridgeFree(p); } } guard{list.data};
                        if (list.count < 0 || list.count > 65536 ||
                            (list.count > 0 && list.data == nullptr) ||
                            list.size != static_cast<std::size_t>(list.count) *
                                             sizeof(Script::Symbol::SymbolInfo)) {
                            return ErrorResponse(*parsed, "OUTPUT_LIMIT_EXCEEDED",
                                                 "symbol database exceeds native bounds", false,
                                                 false);
                        }
                        const auto* values =
                            static_cast<const Script::Symbol::SymbolInfo*>(list.data);
                        const std::size_t count = static_cast<std::size_t>(list.count);
                        if (parsed->cursorIndex > count) {
                            return ErrorResponse(*parsed, "INVALID_ARGUMENT", "cursor is invalid",
                                                 false, false);
                        }
                        std::string items = "[";
                        std::size_t index = parsed->cursorIndex;
                        std::size_t emitted = 0;
                        for (; index < count && emitted < parsed->pageLimit; ++index) {
                            if ((index & 0xffU) == 0U &&
                                std::chrono::steady_clock::now() >= requestDeadline) {
                                return ErrorResponse(*parsed, "TIMEOUT",
                                                     "symbol search exceeded its deadline", true,
                                                     false);
                            }
                            const auto& symbol = values[index];
                            const std::string_view symbolModule(
                                symbol.mod, strnlen_s(symbol.mod, sizeof(symbol.mod)));
                            const std::string_view name(
                                symbol.name, strnlen_s(symbol.name, sizeof(symbol.name)));
                            if (!Utf8OrdinalEqualsIgnoreCase(symbolModule, module->name) ||
                                !Utf8OrdinalContainsIgnoreCase(name, parsed->query)) continue;
                            if (symbol.rva >= module->size ||
                                module->base > (std::numeric_limits<duint>::max)() - symbol.rva) {
                                return ErrorResponse(*parsed, "INTERNAL",
                                                     "symbol record is outside its module", false,
                                                     false);
                            }
                            const char* type = symbol.type == Script::Symbol::Function
                                                   ? "function"
                                                   : symbol.type == Script::Symbol::Import
                                                         ? "import"
                                                         : "export";
                            if (emitted++ != 0U) items.push_back(',');
                            const auto location = LocationFromModules(module->base + symbol.rva,
                                                                      *modules);
                            items += "{\"name\":" + JsonString(name) + ",\"type\":" +
                                     JsonString(type) + ",\"manual\":" +
                                     (symbol.manual ? "true" : "false") + ",\"location\":" +
                                     LocationJson(location, *snapshot) + "}";
                        }
                        items += "]";
                        const std::string next = index < count
                                                     ? JsonString(DiscoveryCursor(*parsed, *snapshot,
                                                                                  index))
                                                     : "null";
                        if (!PausedSnapshotCurrent(*snapshot)) {
                            return ErrorResponse(*parsed, "BUSY",
                                                 "debugger changed during symbol search", true,
                                                 false);
                        }
                        return "{\"request_id\":" + JsonString(parsed->requestId) +
                               ",\"state_generation\":" + std::to_string(*snapshot) +
                               ",\"status\":\"ok\",\"result\":{\"items\":" + items +
                               ",\"next_cursor\":" + next +
                               ",\"completeness\":\"known_only\",\"state_generation\":" +
                               std::to_string(*snapshot) + "}}";
                    }

                    ListInfo functionList{};
                    if (!Script::Function::GetList(&functionList)) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "function database is unavailable", true, false);
                    }
                    struct FunctionGuard { void* p; ~FunctionGuard() { if (p) BridgeFree(p); } }
                        functionGuard{functionList.data};
                    if (functionList.count < 0 || functionList.count > 65536 ||
                        (functionList.count > 0 && functionList.data == nullptr) ||
                        functionList.size != static_cast<std::size_t>(functionList.count) *
                                                 sizeof(Script::Function::FunctionInfo)) {
                        return ErrorResponse(*parsed, "OUTPUT_LIMIT_EXCEEDED",
                                             "function database exceeds native bounds", false,
                                             false);
                    }
                    std::unordered_map<duint, std::string> names;
                    ListInfo symbolList{};
                    if (Script::Symbol::GetList(&symbolList)) {
                        struct SymbolGuard { void* p; ~SymbolGuard() { if (p) BridgeFree(p); } }
                            symbolGuard{symbolList.data};
                        if (symbolList.count < 0 || symbolList.count > 65536 ||
                            (symbolList.count > 0 && symbolList.data == nullptr) ||
                            symbolList.size != static_cast<std::size_t>(symbolList.count) *
                                                   sizeof(Script::Symbol::SymbolInfo)) {
                            return ErrorResponse(*parsed, "OUTPUT_LIMIT_EXCEEDED",
                                                 "symbol database exceeds native bounds", false,
                                                 false);
                        }
                        const auto* symbols =
                            static_cast<const Script::Symbol::SymbolInfo*>(symbolList.data);
                        for (int i = 0; i < symbolList.count; ++i) {
                            if ((i & 0xff) == 0 &&
                                std::chrono::steady_clock::now() >= requestDeadline) {
                                return ErrorResponse(*parsed, "TIMEOUT",
                                                     "function name join exceeded its deadline",
                                                     true, false);
                            }
                            const auto& symbol = symbols[i];
                            const std::string_view symbolModule(
                                symbol.mod, strnlen_s(symbol.mod, sizeof(symbol.mod)));
                            if (symbol.type == Script::Symbol::Function &&
                                Utf8OrdinalEqualsIgnoreCase(symbolModule, module->name)) {
                                names.try_emplace(symbol.rva, symbol.name,
                                                  strnlen_s(symbol.name, sizeof(symbol.name)));
                            }
                        }
                    }
                    const auto* values =
                        static_cast<const Script::Function::FunctionInfo*>(functionList.data);
                    const std::size_t count = static_cast<std::size_t>(functionList.count);
                    if (parsed->cursorIndex > count) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT", "cursor is invalid",
                                             false, false);
                    }
                    std::string items = "[";
                    std::size_t index = parsed->cursorIndex;
                    std::size_t emitted = 0;
                    for (; index < count && emitted < parsed->pageLimit; ++index) {
                        if ((index & 0xffU) == 0U &&
                            std::chrono::steady_clock::now() >= requestDeadline) {
                            return ErrorResponse(*parsed, "TIMEOUT",
                                                 "function search exceeded its deadline", true,
                                                 false);
                        }
                        const auto& function = values[index];
                        const std::string_view functionModule(
                            function.mod, strnlen_s(function.mod, sizeof(function.mod)));
                        if (!Utf8OrdinalEqualsIgnoreCase(functionModule, module->name) ||
                            function.rvaStart > function.rvaEnd ||
                            function.rvaEnd >= module->size) continue;
                        if (module->base > (std::numeric_limits<duint>::max)() -
                                               function.rvaEnd) {
                            return ErrorResponse(*parsed, "INTERNAL",
                                                 "function record is outside its module", false,
                                                 false);
                        }
                        const auto named = names.find(function.rvaStart);
                        if (!parsed->query.empty() &&
                            (named == names.end() ||
                             !Utf8OrdinalContainsIgnoreCase(named->second, parsed->query))) continue;
                        if (emitted++ != 0U) items.push_back(',');
                        const auto start = LocationFromModules(module->base + function.rvaStart,
                                                               *modules);
                        const auto end = LocationFromModules(module->base + function.rvaEnd,
                                                             *modules);
                        items += "{\"name\":" +
                                 (named == names.end() ? "null" : JsonString(named->second)) +
                                 ",\"start\":" + LocationJson(start, *snapshot) +
                                 ",\"end_inclusive\":" + LocationJson(end, *snapshot) +
                                 ",\"instruction_count\":" +
                                 std::to_string(function.instructioncount) + ",\"manual\":" +
                                 (function.manual ? "true" : "false") + "}";
                    }
                    items += "]";
                    const std::string next = index < count
                                                 ? JsonString(DiscoveryCursor(*parsed, *snapshot,
                                                                              index))
                                                 : "null";
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during function search", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(*snapshot) +
                           ",\"status\":\"ok\",\"result\":{\"items\":" + items +
                           ",\"next_cursor\":" + next +
                           ",\"completeness\":\"known_only\",\"state_generation\":" +
                           std::to_string(*snapshot) + "}}";
                }
                if (parsed->method == "references.to") {
                    if (parsed->cursorGeneration &&
                        *parsed->cursorGeneration != resolvedGeneration) {
                        return ErrorResponse(*parsed, "STALE_CURSOR", "cursor generation is stale",
                                             false, false);
                    }
                    const auto modules = CaptureModuleRecords();
                    if (!modules) {
                        return ErrorResponse(*parsed, "INTERNAL", "module snapshot is invalid",
                                             true, false);
                    }
                    const std::size_t reported = DbgGetXrefCountAt(resolvedLocation->address);
                    if (reported > 65536U) {
                        return ErrorResponse(*parsed, "OUTPUT_LIMIT_EXCEEDED",
                                             "reference database exceeds native bounds", false,
                                             false);
                    }
                    XREF_INFO info{};
                    if (reported != 0U && !DbgXrefGet(resolvedLocation->address, &info)) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "reference database is unavailable", true, false);
                    }
                    struct XrefGuard { XREF_RECORD* p; ~XrefGuard() { if (p) BridgeFree(p); } }
                        guard{info.references};
                    if (info.refcount > 65536U || info.refcount != reported ||
                        (info.refcount > 0U && info.references == nullptr)) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "reference snapshot is invalid", false, false);
                    }
                    const std::size_t count = static_cast<std::size_t>(info.refcount);
                    if (parsed->cursorIndex > count) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT", "cursor is invalid",
                                             false, false);
                    }
                    const std::size_t end =
                        (std::min)(count, parsed->cursorIndex + parsed->pageLimit);
                    std::string items = "[";
                    for (std::size_t index = parsed->cursorIndex; index < end; ++index) {
                        if (index != parsed->cursorIndex) items.push_back(',');
                        const auto& reference = info.references[index];
                        const char* type = reference.type == XREF_CALL
                                               ? "call"
                                               : reference.type == XREF_JMP ? "jump" : "data";
                        items += "{\"from\":" +
                                 LocationJson(LocationFromModules(reference.addr, *modules),
                                              resolvedGeneration) +
                                 ",\"type\":" + JsonString(type) + "}";
                    }
                    items += "]";
                    const std::string next = end < count
                                                 ? JsonString(DiscoveryCursor(*parsed,
                                                                              resolvedGeneration,
                                                                              end))
                                                 : "null";
                    if (!PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during reference search", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(resolvedGeneration) +
                           ",\"status\":\"ok\",\"result\":{\"target\":" +
                           LocationJson(*resolvedLocation, resolvedGeneration) +
                           ",\"items\":" + items + ",\"next_cursor\":" + next +
                           ",\"completeness\":\"known_only\",\"state_generation\":" +
                           std::to_string(resolvedGeneration) + "}}";
                }
                if (parsed->method == "callstack.read") {
                    const std::optional<std::uint64_t> snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false, false);
                    }
                    const std::optional<std::uint32_t> requestedThreadValue =
                        parsed->targetThreadId ? parsed->targetThreadId : SelectedThreadId();
                    if (!requestedThreadValue || *requestedThreadValue == 0U) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "no current debugger thread is available", false,
                                             false);
                    }
                    const std::uint32_t requestedThread = *requestedThreadValue;
                    THREADLIST list{};
                    DbgGetThreadList(&list);
                    struct CallstackThreadGuard {
                        THREADALLINFO* value;
                        ~CallstackThreadGuard() { if (value) BridgeFree(value); }
                    } threadGuard{list.list};
                    if (list.count < 0 || list.count > 65536 ||
                        (list.count > 0 && list.list == nullptr)) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "thread snapshot is invalid", false, false);
                    }
                    HANDLE threadHandle = nullptr;
                    for (int index = 0; index < list.count; ++index) {
                        if (list.list[index].BasicInfo.ThreadId == requestedThread) {
                            threadHandle = list.list[index].BasicInfo.Handle;
                            break;
                        }
                    }
                    if (threadHandle == nullptr || threadHandle == INVALID_HANDLE_VALUE) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                             "thread_id is not present in this debuggee", false,
                                             false);
                    }
                    const DBGFUNCTIONS* functions = DbgFunctions();
                    if (functions == nullptr || functions->GetCallStackByThread == nullptr) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "native call-stack API is unavailable", false,
                                             false);
                    }
                    DBGCALLSTACK stack{};
                    functions->GetCallStackByThread(threadHandle, &stack);
                    struct CallstackGuard {
                        DBGCALLSTACKENTRY* value;
                        ~CallstackGuard() { if (value) BridgeFree(value); }
                    } stackGuard{stack.entries};
                    if (stack.total < 0 || stack.total > 50 ||
                        (stack.total > 0 && stack.entries == nullptr)) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "native call-stack snapshot is invalid", false,
                                             false);
                    }
                    const auto modules = CaptureModuleRecords();
                    if (!modules) {
                        return ErrorResponse(*parsed, "INTERNAL", "module snapshot is invalid",
                                             true, false);
                    }
                    const std::size_t nativeCount = static_cast<std::size_t>(stack.total);
                    const std::size_t emitted = (std::min)(nativeCount, parsed->pageLimit);
                    std::string frames = "[";
                    for (std::size_t index = 0; index < emitted; ++index) {
                        if (index != 0U) frames.push_back(',');
                        const auto& frame = stack.entries[index];
                        frames += "{\"index\":" + std::to_string(index) +
                                  ",\"stack_address\":" + JsonString(HexValue(frame.addr)) +
                                  ",\"instruction\":" +
                                  LocationJson(LocationFromModules(frame.from, *modules),
                                               *snapshot) +
                                  ",\"return_to\":" +
                                  LocationJson(LocationFromModules(frame.to, *modules),
                                               *snapshot) +
                                  "}";
                    }
                    frames += "]";
                    if (!PausedSnapshotCurrent(*snapshot)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during call-stack capture", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(*snapshot) +
                           ",\"status\":\"ok\",\"result\":{\"thread_id\":" +
                           JsonString(HexValue(requestedThread)) + ",\"frames\":" + frames +
                           ",\"native_frame_count\":" + std::to_string(nativeCount) +
                           ",\"truncated\":" + (emitted < nativeCount ? "true" : "false") +
                           ",\"completeness\":" +
                           JsonString(nativeCount == 0U ? "inconclusive" : "native_bounded") +
                           ",\"state_generation\":" + std::to_string(*snapshot) + "}}";
                }
                if (parsed->method == "threads.list") {
                    const std::optional<std::uint64_t> snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false, false);
                    }
                    const std::uint64_t generation = *snapshot;
                    if (parsed->cursorGeneration && *parsed->cursorGeneration != generation) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT", "cursor is stale", false,
                                             false);
                    }
                    THREADLIST list{};
                    DbgGetThreadList(&list);
                    struct ThreadListGuard {
                        THREADALLINFO* value;
                        ~ThreadListGuard() { BridgeFree(value); }
                    } guard{list.list};
                    if (list.count < 0 || (list.count > 0 && list.list == nullptr) ||
                        list.count > 65536) {
                        return ErrorResponse(*parsed, "INTERNAL", "thread snapshot is invalid",
                                             false, false);
                    }
                    const std::size_t count = static_cast<std::size_t>(list.count);
                    if (parsed->cursorIndex > count) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT", "cursor is invalid",
                                             false, false);
                    }
                    const std::size_t end =
                        (std::min)(count, parsed->cursorIndex + parsed->pageLimit);
                    std::string items = "[";
                    for (std::size_t index = parsed->cursorIndex; index < end; ++index) {
                        const THREADALLINFO& thread = list.list[index];
                        if (index != parsed->cursorIndex) items.push_back(',');
                        const std::size_t nameLength = strnlen_s(
                            thread.BasicInfo.threadName, sizeof(thread.BasicInfo.threadName));
                        items += "{\"thread_id\":" +
                                 JsonString(HexValue(thread.BasicInfo.ThreadId)) +
                                 ",\"instruction_pointer\":" + JsonString(HexValue(thread.ThreadCip)) +
                                 ",\"start_address\":" +
                                 JsonString(HexValue(thread.BasicInfo.ThreadStartAddress)) +
                                 ",\"suspend_count\":" + std::to_string(thread.SuspendCount) +
                                 ",\"current\":" +
                                 (static_cast<int>(index) == list.CurrentThread ? "true" : "false") +
                                 ",\"name\":" +
                                 JsonString(std::string_view(thread.BasicInfo.threadName, nameLength)) + "}";
                    }
                    items += "]";
                    const std::string next = end < count
                                                 ? JsonString("v1:" + std::to_string(generation) + ":" +
                                                              std::to_string(end))
                                                 : "null";
                    if (!PausedSnapshotCurrent(generation)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during thread snapshot", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(generation) +
                           ",\"status\":\"ok\",\"result\":{\"items\":" + items +
                           ",\"next_cursor\":" + next + ",\"state_generation\":" +
                           std::to_string(generation) + "}}";
                }
                if (parsed->method == "memory.map") {
                    const std::optional<std::uint64_t> snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false, false);
                    }
                    const std::uint64_t generation = *snapshot;
                    if (parsed->cursorGeneration && *parsed->cursorGeneration != generation) {
                        return ErrorResponse(*parsed, "STALE_CURSOR", "cursor generation is stale", false,
                                             false);
                    }
                    std::optional<ModuleRecord> selectedModule;
                    if (!parsed->module.empty()) {
                        const auto modules = CaptureModuleRecords();
                        if (!modules) {
                            return ErrorResponse(*parsed, "INTERNAL",
                                                 "module snapshot is invalid", true, false);
                        }
                        selectedModule = UniqueModule(*modules, parsed->module);
                        if (!selectedModule) {
                            return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                                 "module is missing or ambiguous", false, false);
                        }
                    }
                    MEMMAP map{};
                    if (!DbgMemMap(&map)) {
                        return ErrorResponse(*parsed, "INTERNAL", "memory map is unavailable", true,
                                             false);
                    }
                    struct MapGuard {
                        MEMPAGE* value;
                        ~MapGuard() {
                            if (value != nullptr) BridgeFree(value);
                        }
                    } guard{map.page};
                    if (map.count < 0 || (map.count > 0 && map.page == nullptr) ||
                        map.count > 65536) {
                        return ErrorResponse(*parsed, "OUTPUT_LIMIT_EXCEEDED",
                                             "memory map exceeds native bounds", false, false);
                    }
                    const std::size_t count = static_cast<std::size_t>(map.count);
                    if (parsed->cursorIndex > count) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT", "cursor is invalid",
                                             false, false);
                    }
                    std::string items = "[";
                    std::size_t index = parsed->cursorIndex;
                    std::size_t emitted = 0U;
                    for (; index < count && emitted < parsed->pageLimit; ++index) {
                        if ((index & 0xffU) == 0U) {
                            if (std::chrono::steady_clock::now() >= requestDeadline) {
                                return ErrorResponse(*parsed, "TIMEOUT",
                                                     "memory-map filtering exceeded its deadline",
                                                     true, false);
                            }
                            if (!PausedSnapshotCurrent(generation)) {
                                return ErrorResponse(*parsed, "BUSY",
                                                     "debugger changed during memory-map filtering",
                                                     true, false);
                            }
                        }
                        const MEMPAGE& page = map.page[index];
                        const std::uint64_t base = reinterpret_cast<std::uintptr_t>(
                            page.mbi.BaseAddress);
                        const std::uint64_t size = page.mbi.RegionSize;
                        if (parsed->committedOnly && page.mbi.State != MEM_COMMIT) continue;
                        if (parsed->executableOnly &&
                            !IsExecutableProtection(page.mbi.Protect)) continue;
                        if (selectedModule) {
                            const auto overlap = HalfOpenRangesOverlap(
                                base, size, selectedModule->base, selectedModule->size);
                            if (!overlap) {
                                return ErrorResponse(*parsed, "INTERNAL",
                                                     "memory-map range overflow", false, false);
                            }
                            if (!*overlap) continue;
                        }
                        if (emitted++ != 0U) items.push_back(',');
                        const std::size_t infoLength = strnlen_s(page.info, sizeof(page.info));
                        const std::uint64_t allocationBase =
                            reinterpret_cast<std::uintptr_t>(page.mbi.AllocationBase);
                        items += "{\"base\":" + JsonString(HexValue(base)) +
                                 ",\"size\":" + JsonString(HexValue(size));
                        if (!parsed->compact || allocationBase != base) {
                            items += ",\"allocation_base\":" +
                                     JsonString(HexValue(allocationBase));
                        }
                        items += ",\"protect\":" + JsonString(HexValue(page.mbi.Protect)) +
                                 ",\"state\":" + JsonString(HexValue(page.mbi.State)) +
                                 ",\"type\":" + JsonString(HexValue(page.mbi.Type));
                        if (!parsed->compact || infoLength != 0U) {
                            items += ",\"info\":" +
                                     JsonString(std::string_view(page.info, infoLength));
                        }
                        items += "}";
                    }
                    items += "]";
                    const std::string next = index < count
                                                 ? JsonString(DiscoveryCursor(*parsed, generation,
                                                                              index))
                                                 : "null";
                    if (!PausedSnapshotCurrent(generation)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during memory-map snapshot", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(generation) +
                           ",\"status\":\"ok\",\"result\":{\"items\":" + items +
                           ",\"next_cursor\":" + next + ",\"state_generation\":" +
                           std::to_string(generation) + "}}";
                }
                if (parsed->method == "breakpoints.list") {
                    const std::optional<std::uint64_t> snapshot = BeginActiveSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires an active debuggee", false, false);
                    }
                    const std::uint64_t generation = *snapshot;
                    if (parsed->cursorGeneration && *parsed->cursorGeneration != generation) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT", "cursor is stale", false,
                                             false);
                    }
                    BPMAP map{};
                    const int reported = DbgGetBpList(bp_none, &map);
                    struct BreakpointGuard {
                        BRIDGEBP* value;
                        ~BreakpointGuard() {
                            if (value != nullptr) BridgeFree(value);
                        }
                    } guard{map.bp};
                    if (reported < 0 || map.count < 0 || (map.count > 0 && map.bp == nullptr) ||
                        map.count > 65536) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "breakpoint snapshot is invalid", false, false);
                    }
                    const std::size_t count = static_cast<std::size_t>(map.count);
                    if (parsed->cursorIndex > count) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT", "cursor is invalid",
                                             false, false);
                    }
                    const std::size_t end =
                        (std::min)(count, parsed->cursorIndex + parsed->pageLimit);
                    std::string items = "[";
                    for (std::size_t index = parsed->cursorIndex; index < end; ++index) {
                        const BRIDGEBP& breakpoint = map.bp[index];
                        if (index != parsed->cursorIndex) items.push_back(',');
                        const char* type = "unknown";
                        switch (breakpoint.type) {
                        case bp_normal: type = "software"; break;
                        case bp_hardware: type = "hardware"; break;
                        case bp_memory: type = "memory"; break;
                        case bp_dll: type = "dll"; break;
                        case bp_exception: type = "exception"; break;
                        case bp_none: break;
                        }
                        std::string typedFields;
                        if (breakpoint.type == bp_hardware) {
                            const std::size_t size = HardwareSizeFromNative(breakpoint.hwSize);
                            typedFields = ",\"access\":" +
                                          JsonString(HardwareAccessNameFromNative(
                                              breakpoint.typeEx)) +
                                          ",\"size\":" +
                                          (size == 0U ? std::string("null")
                                                      : std::to_string(size)) +
                                          ",\"slot\":" +
                                          (breakpoint.enabled && breakpoint.slot < 4U
                                               ? std::to_string(breakpoint.slot)
                                               : std::string("null"));
                        } else if (breakpoint.type == bp_memory) {
                            const DBGFUNCTIONS* functions = DbgFunctions();
                            const duint size =
                                functions != nullptr && functions->MemBpSize != nullptr
                                    ? functions->MemBpSize(breakpoint.addr)
                                    : 0U;
                            typedFields = ",\"access\":" +
                                          JsonString(MemoryAccessNameFromNative(
                                              breakpoint.typeEx)) +
                                          ",\"size\":" +
                                          (size == 0U ? std::string("null")
                                                      : std::to_string(size));
                        } else if (breakpoint.type == bp_normal) {
                            const std::size_t conditionLength = strnlen_s(
                                breakpoint.breakCondition,
                                sizeof(breakpoint.breakCondition));
                            if (conditionLength >= sizeof(breakpoint.breakCondition)) {
                                return ErrorResponse(*parsed, "INTERNAL",
                                                     "software breakpoint condition is invalid",
                                                     false, false);
                            }
                            const auto managed =
                                ManagedBreakpointId(breakpoint, "conditional");
                            typedFields = ",\"condition_expression\":" +
                                          (conditionLength == 0U
                                               ? std::string("null")
                                               : JsonString(std::string_view(
                                                     breakpoint.breakCondition,
                                                     conditionLength))) +
                                          ",\"fast_resume\":" +
                                          (breakpoint.fastResume ? "true" : "false") +
                                          ",\"managed_id\":" +
                                          (managed ? JsonString(*managed) : "null");
                        } else if (breakpoint.type == bp_exception) {
                            const char* chance = "unknown";
                            switch (static_cast<BPEXTYPE>(breakpoint.typeEx)) {
                            case ex_firstchance: chance = "first"; break;
                            case ex_secondchance: chance = "second"; break;
                            case ex_all: chance = "both"; break;
                            }
                            const auto managed =
                                ManagedBreakpointId(breakpoint, "exception");
                            typedFields = ",\"code\":" +
                                          JsonString(HexValue(breakpoint.addr)) +
                                          ",\"chance\":" + JsonString(chance) +
                                          ",\"managed_id\":" +
                                          (managed ? JsonString(*managed) : "null");
                        }
                        items += "{\"address\":" + JsonString(HexValue(breakpoint.addr)) +
                                 ",\"type\":" + JsonString(type) + ",\"enabled\":" +
                                 (breakpoint.enabled ? "true" : "false") + ",\"active\":" +
                                 (breakpoint.active ? "true" : "false") +
                                 ",\"hit_count\":" + std::to_string(breakpoint.hitCount) +
                                 typedFields + "}";
                    }
                    items += "]";
                    const std::string next = end < count
                                                 ? JsonString("v1:" + std::to_string(generation) + ":" +
                                                              std::to_string(end))
                                                 : "null";
                    if (!ActiveSnapshotCurrent(generation)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during breakpoint snapshot", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(generation) +
                           ",\"status\":\"ok\",\"result\":{\"items\":" + items +
                           ",\"next_cursor\":" + next + ",\"state_generation\":" +
                           std::to_string(generation) + "}}";
                }
                if (parsed->method == "modules.list") {
                    const std::optional<std::uint64_t> snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false, false);
                    }
                    const std::uint64_t generation = *snapshot;
                    if (parsed->cursorGeneration && *parsed->cursorGeneration != generation) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT", "cursor is stale", false,
                                             false);
                    }
                    ListInfo list{};
                    if (!Script::Module::GetList(&list)) {
                        return ErrorResponse(*parsed, "INTERNAL", "module list is unavailable", true,
                                             false);
                    }
                    struct ModuleGuard {
                        void* value;
                        ~ModuleGuard() {
                            if (value != nullptr) BridgeFree(value);
                        }
                    } guard{list.data};
                    if (list.count < 0 || (list.count > 0 && list.data == nullptr) ||
                        list.count > 65536 ||
                        list.size != static_cast<std::size_t>(list.count) *
                                         sizeof(Script::Module::ModuleInfo)) {
                        return ErrorResponse(*parsed, "INTERNAL", "module list is invalid", false,
                                             false);
                    }
                    const auto* modules =
                        static_cast<const Script::Module::ModuleInfo*>(list.data);
                    const std::size_t count = static_cast<std::size_t>(list.count);
                    if (parsed->cursorIndex > count) {
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT", "cursor is invalid",
                                             false, false);
                    }
                    const std::size_t end =
                        (std::min)(count, parsed->cursorIndex + parsed->pageLimit);
                    std::string items = "[";
                    for (std::size_t index = parsed->cursorIndex; index < end; ++index) {
                        const auto& module = modules[index];
                        if (index != parsed->cursorIndex) items.push_back(',');
                        const std::size_t nameLength = strnlen_s(module.name, sizeof(module.name));
                        const std::size_t pathLength = strnlen_s(module.path, sizeof(module.path));
                        items += "{\"base\":" + JsonString(HexValue(module.base)) +
                                 ",\"size\":" + JsonString(HexValue(module.size)) +
                                 ",\"entry\":" + JsonString(HexValue(module.entry)) +
                                 ",\"name\":" +
                                 JsonString(std::string_view(module.name, nameLength)) +
                                 ",\"path\":" +
                                 JsonString(std::string_view(module.path, pathLength)) + "}";
                    }
                    items += "]";
                    const std::string next = end < count
                                                 ? JsonString("v1:" + std::to_string(generation) + ":" +
                                                              std::to_string(end))
                                                 : "null";
                    if (!PausedSnapshotCurrent(generation)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during module snapshot", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(generation) +
                           ",\"status\":\"ok\",\"result\":{\"items\":" + items +
                           ",\"next_cursor\":" + next + ",\"state_generation\":" +
                           std::to_string(generation) + "}}";
                }
                if (parsed->method == "disassembly.read") {
                    duint address = resolvedLocation->address;
                    std::string items = "[";
                    for (std::size_t index = 0; index < parsed->instructionCount; ++index) {
                        DISASM_INSTR instruction{};
                        DbgDisasmAt(address, &instruction);
                        if (instruction.instr_size <= 0 || instruction.instr_size > 15) {
                            return ErrorResponse(*parsed, "ACCESS_DENIED",
                                                 "instruction bytes are not decodable", false,
                                                 false);
                        }
                        const duint size = static_cast<duint>(instruction.instr_size);
                        if (address > (std::numeric_limits<duint>::max)() - size) {
                            return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                                 "disassembly address overflow", false, false);
                        }
                        if (index != 0U) items.push_back(',');
                        const std::size_t textLength =
                            strnlen_s(instruction.instruction, sizeof(instruction.instruction));
                        items += "{\"address\":" + JsonString(HexValue(address)) +
                                 ",\"size\":" + std::to_string(size) +
                                 ",\"text\":" +
                                 JsonString(std::string_view(instruction.instruction, textLength)) +
                                 "}";
                        address += size;
                    }
                    items += "]";
                    if (!PausedSnapshotCurrent(resolvedGeneration)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger changed during disassembly snapshot", true,
                                             false);
                    }
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(resolvedGeneration) +
                           ",\"status\":\"ok\",\"result\":{\"location\":" +
                           LocationJson(*resolvedLocation, resolvedGeneration) +
                           ",\"items\":" + items + ",\"state_generation\":" +
                           std::to_string(resolvedGeneration) + "}}";
                }
#endif
                return ErrorResponse(*parsed, "UNSUPPORTED", "tool not implemented by plugin",
                                     false, false);
            },
            requestDeadline);
        std::string response;
        switch (execution.status) {
        case ExecutionStatus::completed: response = execution.value; break;
        case ExecutionStatus::busy:
            response = ErrorResponse(*parsed, "BUSY", "debugger queue is full", true, false);
            break;
        case ExecutionStatus::timedOutQueued:
            response = ErrorResponse(*parsed, "TIMEOUT", "operation expired in queue",
                                     !parsed->mutation, false);
            break;
        case ExecutionStatus::timedOutStarted:
            response = ErrorResponse(*parsed, "TIMEOUT", "started operation exceeded deadline",
                                     !parsed->mutation, parsed->mutation);
            break;
        case ExecutionStatus::stopped:
            response = ErrorResponse(*parsed, "CANCELLED", "plugin is draining", true, false);
            break;
        }
        if (!WriteFrame(pipe_, response)) {
            break;
        }
    }
    PluginState ready = PluginState::ready;
    if (pluginState_.compare_exchange_strong(ready, PluginState::starting)) {
        std::lock_guard lock(stateMutex_);
        generation_.fetch_add(1U);
    }
}

std::string Runtime::ScyllaHideProfileResponse(
    const std::string& requestId, const std::string& operationId, const std::string& action,
    const std::string& profile, const std::string& expectedGeneration) {
    const auto errorResponse = [&requestId](const std::string_view code,
                                            const std::string_view message,
                                            const bool retryable,
                                            const std::string_view details = "{}") {
        return "{\"request_id\":" + JsonString(requestId) +
               ",\"state_generation\":0,\"status\":\"error\",\"error\":{\"code\":" +
               JsonString(code) + ",\"message\":" + JsonString(message) +
               ",\"retryable\":" + (retryable ? "true" : "false") +
               ",\"details\":" + std::string(details) + "}}";
    };
    const auto originalText = ReadScyllaHideConfig();
    if (!originalText) {
        return errorResponse("SCYLLAHIDE_NOT_INSTALLED",
                             "plugins/scylla_hide.ini is unavailable", false);
    }
    const auto originalGeneration = ConfigGeneration(*originalText);
    if (!originalGeneration) {
        return errorResponse("INTERNAL", "ScyllaHide config could not be hashed", false);
    }
    std::string policyError;
    auto config = control::ParseScyllaHideConfig(*originalText, policyError);
    if (!config) {
        return errorResponse("SCYLLAHIDE_CONFIG_INVALID", policyError, false);
    }
    bool changed = false;
    std::string currentGeneration = *originalGeneration;
    if (action == "set") {
        if (expectedGeneration != *originalGeneration) {
            const std::string details =
                "{\"expected_config_generation\":" + JsonString(expectedGeneration) +
                ",\"current_config_generation\":" + JsonString(*originalGeneration) + "}";
            return errorResponse("CONFIG_GENERATION_MISMATCH",
                                 "ScyllaHide config changed since it was read", false, details);
        }
        const auto update = control::SetScyllaHideProfile(*originalText, profile, policyError);
        if (!update) {
            return errorResponse("PROFILE_NOT_FOUND", policyError, false);
        }
        changed = update->text != *originalText;
        if (changed && !AtomicReplaceScyllaHideConfig(update->text)) {
            return errorResponse("PROFILE_WRITE_FAILED",
                                 "ScyllaHide config replacement failed", true,
                                 "{\"outcome\":\"unknown\"}");
        }
        const auto verifiedText = ReadScyllaHideConfig();
        if (!verifiedText) {
            return errorResponse("PROFILE_WRITE_FAILED",
                                 "ScyllaHide config could not be verified", true,
                                 "{\"outcome\":\"unknown\"}");
        }
        currentGeneration = ConfigGeneration(*verifiedText).value_or("");
        config = control::ParseScyllaHideConfig(*verifiedText, policyError);
        if (currentGeneration.empty() || !config ||
            config->currentProfile != update->canonicalProfile) {
            return errorResponse("PROFILE_WRITE_FAILED",
                                 "ScyllaHide config verification failed", true,
                                 "{\"outcome\":\"unknown\"}");
        }
    }
    const bool restartRequired = startupScyllaGeneration_ != currentGeneration;
    std::string profiles = "[";
    for (std::size_t index = 0U; index < config->availableProfiles.size(); ++index) {
        if (index != 0U) profiles.push_back(',');
        profiles += JsonString(config->availableProfiles[index]);
    }
    profiles.push_back(']');
    const std::string nextActions =
        restartRequired
            ? "[{\"code\":\"RESTART_DEBUGGER_TO_APPLY\",\"tool\":\"gateway.debugger_restart\",\"reason\":\"The config file differs from the version observed when x64dbg started.\"}]"
            : "[]";
    return "{\"request_id\":" + JsonString(requestId) +
           ",\"state_generation\":0,\"status\":\"ok\",\"result\":{\"backend\":" +
           JsonString(kBackendUtf8) + ",\"action\":" + JsonString(action) +
           (operationId.empty() ? "" : ",\"operation_id\":" + JsonString(operationId)) +
           ",\"configured_profile\":" + JsonString(config->currentProfile) +
           ",\"startup_observed_profile\":" +
           (startupScyllaProfile_.empty() ? "null" : JsonString(startupScyllaProfile_)) +
           ",\"available_profiles\":" + profiles +
           ",\"config_generation\":" + JsonString(currentGeneration) +
           ",\"changed\":" + (changed ? "true" : "false") +
           ",\"restart_required\":" + (restartRequired ? "true" : "false") +
           ",\"next_actions\":" + nextActions + "}}";
}

std::string Runtime::StateResponse(const std::string& requestId) {
    DebuggeeState state;
    std::uint64_t generation = 0;
    std::uint32_t processId = 0;
    std::uint32_t threadId = 0;
    std::string instanceId;
    SessionOrigin origin = SessionOrigin::none;
    PauseObservation pause;
    {
        std::lock_guard lock(stateMutex_);
        state = debuggeeState_.load();
        generation = generation_.load();
        processId = processId_.load();
        threadId = activeThreadId_.load();
        instanceId = instanceId_;
        origin = sessionOrigin_.load();
        pause = latestPause_;
    }
    const char* stateName = "absent";
    switch (state) {
    case DebuggeeState::starting: stateName = "starting"; break;
    case DebuggeeState::paused: stateName = "paused"; break;
    case DebuggeeState::running: stateName = "running"; break;
    case DebuggeeState::stopping: stateName = "stopping"; break;
    case DebuggeeState::exited: stateName = "exited"; break;
    case DebuggeeState::absent: break;
    }
    std::string instructionPointer = "null";
#ifndef MCP_LIFECYCLE_HARNESS
    if (state == DebuggeeState::paused && DbgIsDebugging()) {
        REGDUMP_AVX512 dump{};
        if (!DbgGetRegDumpEx(&dump, sizeof(dump))) {
            return ErrorResponseForId(requestId, "INTERNAL",
                                      "paused register snapshot is unavailable", true, false);
        }
        instructionPointer = JsonString(HexValue(dump.regcontext.cip));
    }
#endif
    {
        std::lock_guard lock(stateMutex_);
        if (pluginState_.load() != PluginState::ready || generation_.load() != generation ||
            debuggeeState_.load() != state) {
            return ErrorResponseForId(requestId, "BUSY",
                                      "debugger state changed during snapshot capture", true,
                                      false);
        }
    }
    return "{\"request_id\":" + JsonString(requestId) + ",\"state_generation\":" +
           std::to_string(generation) +
           ",\"status\":\"ok\",\"result\":{\"instance_id\":" + JsonString(instanceId) +
           ",\"backend\":\"" + kBackendUtf8 +
           "\",\"architecture\":\"" +
#ifdef _WIN64
           "x86_64" +
#else
           "x86" +
#endif
           "\",\"plugin_state\":\"ready\",\"debuggee_state\":\"" + stateName +
           "\",\"session_origin\":" +
           (origin == SessionOrigin::launched
                ? "\"launched\""
                : origin == SessionOrigin::attached ? "\"attached\"" : "null") +
           ",\"process_id\":" +
           (processId == 0U ? "null" : JsonString(HexValue(processId))) +
           ",\"active_thread_id\":" +
           (threadId == 0U ? "null" : JsonString(HexValue(threadId))) +
           ",\"instruction_pointer\":" + instructionPointer +
           ",\"pause_reason\":" +
           (state == DebuggeeState::paused ? PauseReasonJson(pause) : "null") +
           ",\"diagnostic_code\":" +
           (state == DebuggeeState::absent || state == DebuggeeState::exited
                ? "\"NO_DEBUGGEE\""
                : "null") +
           ",\"next_actions\":" +
           (state == DebuggeeState::absent || state == DebuggeeState::exited
                ? "[{\"code\":\"CALL_DEBUGGEE_LAUNCH\",\"tool\":\"debuggee.launch\"},"
                  "{\"code\":\"CALL_DEBUGGEE_ATTACH\",\"tool\":\"debuggee.attach\"}]"
                : "[]") +
           ",\"state_generation\":" + std::to_string(generation) + "}}";
}

std::optional<std::uint64_t> Runtime::BeginPausedSnapshot() noexcept {
    std::lock_guard lock(stateMutex_);
    if (pluginState_.load() != PluginState::ready ||
        debuggeeState_.load() != DebuggeeState::paused) {
        return std::nullopt;
    }
    return generation_.load();
}

std::optional<std::uint64_t> Runtime::BeginActiveSnapshot() noexcept {
    std::lock_guard lock(stateMutex_);
    const DebuggeeState state = debuggeeState_.load();
    if (pluginState_.load() != PluginState::ready ||
        (state != DebuggeeState::paused && state != DebuggeeState::running)) {
        return std::nullopt;
    }
    return generation_.load();
}

bool Runtime::PausedSnapshotCurrent(const std::uint64_t generation) noexcept {
    std::lock_guard lock(stateMutex_);
    return pluginState_.load() == PluginState::ready &&
           debuggeeState_.load() == DebuggeeState::paused && generation_.load() == generation;
}

bool Runtime::ActiveSnapshotCurrent(const std::uint64_t generation) noexcept {
    std::lock_guard lock(stateMutex_);
    const DebuggeeState state = debuggeeState_.load();
    return pluginState_.load() == PluginState::ready &&
           (state == DebuggeeState::paused || state == DebuggeeState::running) &&
           generation_.load() == generation;
}

bool Runtime::PauseObservationCurrent(const std::uint64_t generation,
                                      const std::uint64_t pauseGeneration) noexcept {
    std::lock_guard lock(stateMutex_);
    return pluginState_.load() == PluginState::ready &&
           debuggeeState_.load() == DebuggeeState::paused && generation_.load() == generation &&
           pausedGeneration_.load() == pauseGeneration;
}

bool Runtime::WaitForState(const DebuggeeState expected, const std::uint64_t afterGeneration,
                           const std::chrono::steady_clock::time_point deadline) noexcept {
    std::unique_lock lock(stateMutex_);
    return stateChanged_.wait_until(lock, deadline, [this, expected, afterGeneration] {
        return pluginState_.load() != PluginState::ready ||
               ObservedGeneration(expected) > afterGeneration;
    }) &&
           pluginState_.load() == PluginState::ready &&
           ObservedGeneration(expected) > afterGeneration;
}

bool Runtime::WaitForPauseReason(const PauseReasonKind reason,
                                 const std::uint64_t afterGeneration,
                                 const std::chrono::steady_clock::time_point deadline) noexcept {
    std::unique_lock lock(stateMutex_);
    return stateChanged_.wait_until(lock, deadline, [this, reason, afterGeneration] {
        return pluginState_.load() != PluginState::ready ||
               (pausedGeneration_.load() > afterGeneration && latestPause_.kind == reason);
    }) &&
           pluginState_.load() == PluginState::ready &&
           pausedGeneration_.load() > afterGeneration && latestPause_.kind == reason;
}

bool Runtime::WaitForActionableLaunchPause(
    const std::uint64_t afterGeneration,
    const std::chrono::steady_clock::time_point deadline) noexcept {
    std::unique_lock lock(stateMutex_);
    return stateChanged_.wait_until(lock, deadline, [this, afterGeneration] {
        return pluginState_.load() != PluginState::ready ||
               (pausedGeneration_.load() > afterGeneration &&
                latestPause_.kind != PauseReasonKind::processCreated);
    }) &&
           pluginState_.load() == PluginState::ready &&
           pausedGeneration_.load() > afterGeneration &&
           latestPause_.kind != PauseReasonKind::processCreated;
}

bool Runtime::WaitForAttachPause(
    const std::uint32_t processId, const std::uint64_t afterGeneration,
    const std::chrono::steady_clock::time_point deadline) noexcept {
    std::unique_lock lock(stateMutex_);
    return stateChanged_.wait_until(lock, deadline, [this, processId, afterGeneration] {
        return pluginState_.load() != PluginState::ready ||
               (attachGeneration_.load() > afterGeneration &&
                attachProcessId_.load() == processId &&
                pausedGeneration_.load() > attachGeneration_.load() &&
                debuggeeState_.load() == DebuggeeState::paused &&
                processId_.load() == processId);
    }) &&
           pluginState_.load() == PluginState::ready &&
           attachGeneration_.load() > afterGeneration &&
           attachProcessId_.load() == processId &&
           pausedGeneration_.load() > attachGeneration_.load() &&
           debuggeeState_.load() == DebuggeeState::paused && processId_.load() == processId;
}

bool Runtime::WaitForDetach(
    const std::uint32_t processId, const std::uint64_t afterGeneration,
    const std::chrono::steady_clock::time_point deadline) noexcept {
    std::unique_lock lock(stateMutex_);
    return stateChanged_.wait_until(lock, deadline, [this, processId, afterGeneration] {
        return pluginState_.load() != PluginState::ready ||
               (detachGeneration_.load() > afterGeneration &&
                detachProcessId_.load() == processId &&
                absentGeneration_.load() > detachGeneration_.load() &&
                debuggeeState_.load() == DebuggeeState::absent);
    }) &&
           pluginState_.load() == PluginState::ready &&
           detachGeneration_.load() > afterGeneration &&
           detachProcessId_.load() == processId &&
           absentGeneration_.load() > detachGeneration_.load() &&
           debuggeeState_.load() == DebuggeeState::absent;
}

std::uint64_t Runtime::ObservedGeneration(const DebuggeeState state) const noexcept {
    switch (state) {
    case DebuggeeState::paused: return pausedGeneration_.load();
    case DebuggeeState::running: return runningGeneration_.load();
    case DebuggeeState::absent: return absentGeneration_.load();
    case DebuggeeState::starting:
    case DebuggeeState::stopping:
    case DebuggeeState::exited: return 0U;
    }
    return 0U;
}

void Runtime::RecordEventLocked(EventRecord event) noexcept {
    constexpr std::uint64_t kMaxJsonSafeInteger = 9007199254740991ULL;
    if (nextEventSequence_ > kMaxJsonSafeInteger) return;
    event.sequence = nextEventSequence_++;
    if (eventCount_ < kEventCapacity) {
        eventRing_[(eventStart_ + eventCount_) % kEventCapacity] = event;
        ++eventCount_;
    } else {
        eventRing_[eventStart_] = event;
        eventStart_ = (eventStart_ + 1U) % kEventCapacity;
    }
}

void Runtime::OnDebuggerEvent(const int callbackType, void* const callbackInfo) noexcept {
    if (callbackType == CB_TRACEEXECUTE) {
        auto* info = static_cast<PLUG_CB_TRACEEXECUTE*>(callbackInfo);
        if (info == nullptr) return;
        {
            std::lock_guard lock(traceMutex_);
            if (trace_.Active()) {
                info->stop = trace_.OnStep(static_cast<std::uint64_t>(info->cip), info->stop,
                                           std::chrono::steady_clock::now()) ||
                             info->stop;
            }
        }
        traceChanged_.notify_all();
        return;
    }
    DebuggeeState next = debuggeeState_.load();
    PauseObservation pause;
    std::optional<std::uint32_t> callbackProcessId;
    std::optional<std::uint32_t> callbackThreadId;
    bool clearProcess = false;
    bool hasPauseReason = false;
    bool refineCurrentPause = false;
    bool resetOrigin = false;
    bool markLaunched = false;
    bool markAttached = false;
    bool markDetaching = false;
    bool exceptionBreakpointCallback = false;
    bool clearPendingException = false;
    EventRecord event;
    switch (callbackType) {
    case CB_INITDEBUG:
        event.kind = EventKind::debugInitialized;
        resetOrigin = true;
        next = DebuggeeState::starting;
        break;
    case CB_CREATEPROCESS: {
        event.kind = EventKind::processCreated;
        const auto* info = static_cast<const PLUG_CB_CREATEPROCESS*>(callbackInfo);
        if (info != nullptr && info->fdProcessInfo != nullptr) {
            callbackProcessId = info->fdProcessInfo->dwProcessId;
            callbackThreadId = info->fdProcessInfo->dwThreadId;
            event.processId = *callbackProcessId;
            event.threadId = *callbackThreadId;
            event.hasProcessId = true;
            event.hasThreadId = true;
        }
        next = DebuggeeState::paused;
        markLaunched = true;
        pause.kind = PauseReasonKind::processCreated;
        hasPauseReason = true;
        break;
    }
    case CB_SYSTEMBREAKPOINT:
        event.kind = EventKind::systemBreakpoint;
        next = DebuggeeState::paused;
        pause.kind = PauseReasonKind::systemBreakpoint;
        hasPauseReason = true;
        refineCurrentPause = true;
        break;
    case CB_BREAKPOINT: {
        event.kind = EventKind::breakpoint;
        next = DebuggeeState::paused;
        pause.kind = PauseReasonKind::breakpoint;
        hasPauseReason = true;
        refineCurrentPause = true;
        const auto* info = static_cast<const PLUG_CB_BREAKPOINT*>(callbackInfo);
        if (info != nullptr && info->breakpoint != nullptr) {
            pause.address = info->breakpoint->addr;
            pause.hasAddress = true;
            pause.breakpointType = static_cast<std::uint8_t>(info->breakpoint->type);
            pause.hitCount = info->breakpoint->hitCount;
            event.address = pause.address;
            event.hasAddress = true;
            event.breakpointType = pause.breakpointType;
            event.auxiliary = pause.hitCount;
            exceptionBreakpointCallback = info->breakpoint->type == bp_exception;
        }
        break;
    }
    case CB_EXCEPTION: {
        event.kind = EventKind::exception;
        next = DebuggeeState::paused;
        pause.kind = PauseReasonKind::exception;
        hasPauseReason = true;
        refineCurrentPause = true;
        const auto* info = static_cast<const PLUG_CB_EXCEPTION*>(callbackInfo);
        if (info != nullptr && info->Exception != nullptr) {
            pause.exceptionCode = info->Exception->ExceptionRecord.ExceptionCode;
            pause.hasExceptionCode = true;
            pause.address = reinterpret_cast<std::uintptr_t>(
                info->Exception->ExceptionRecord.ExceptionAddress);
            pause.hasAddress = true;
            pause.firstChance = info->Exception->dwFirstChance != 0U;
            event.code = pause.exceptionCode;
            event.address = pause.address;
            event.hasCode = true;
            event.hasAddress = true;
            event.firstChance = pause.firstChance;
        }
        // DebugBreakProcess reports its owned interrupt as a first-chance
        // EXCEPTION_BREAKPOINT rather than CB_PAUSEDEBUG. Correlate it only while
        // this runtime has one outstanding direct pause request; all other
        // breakpoint exceptions retain their native exception semantics.
        if (pauseInterruptPending_.load() && pause.hasExceptionCode &&
            pause.exceptionCode == EXCEPTION_BREAKPOINT) {
            pause.kind = PauseReasonKind::userPause;
            pause.hasAddress = false;
            pause.hasExceptionCode = false;
            pause.firstChance = false;
            event.kind = EventKind::paused;
            event.hasAddress = false;
            event.hasCode = false;
            event.firstChance = false;
        }
        clearPendingException = true;
        break;
    }
    case CB_PAUSEDEBUG:
        event.kind = EventKind::paused;
        next = DebuggeeState::paused;
        pause.kind = PauseReasonKind::userPause;
        hasPauseReason = true;
        break;
    case CB_STEPPED:
        event.kind = EventKind::stepped;
        next = DebuggeeState::paused;
        pause.kind = PauseReasonKind::step;
        hasPauseReason = true;
        break;
    case CB_RESUMEDEBUG:
        event.kind = EventKind::resumed;
        next = DebuggeeState::running;
        clearPendingException = true;
        break;
    case CB_ATTACH: {
        event.kind = EventKind::attached;
        const auto* info = static_cast<const PLUG_CB_ATTACH*>(callbackInfo);
        if (info != nullptr && info->dwProcessId != 0U) {
            callbackProcessId = info->dwProcessId;
        }
        markAttached = true;
        next = DebuggeeState::starting;
        break;
    }
    case CB_DETACH: {
        event.kind = EventKind::detached;
        const auto* info = static_cast<const PLUG_CB_DETACH*>(callbackInfo);
        if (info != nullptr && info->fdProcessInfo != nullptr) {
            callbackProcessId = info->fdProcessInfo->dwProcessId;
        }
        markDetaching = true;
        next = DebuggeeState::stopping;
        break;
    }
    case CB_STOPPINGDEBUG:
        event.kind = EventKind::stopping;
        next = DebuggeeState::stopping;
        break;
    case CB_EXITPROCESS: {
        event.kind = EventKind::processExited;
        const auto* info = static_cast<const PLUG_CB_EXITPROCESS*>(callbackInfo);
        if (info != nullptr && info->ExitProcess != nullptr) {
            event.auxiliary = info->ExitProcess->dwExitCode;
        }
        next = DebuggeeState::exited;
        break;
    }
    case CB_STOPDEBUG:
        event.kind = EventKind::debugStopped;
        clearProcess = true;
        resetOrigin = true;
        next = DebuggeeState::absent;
        break;
    case CB_DEBUGEVENT: {
        const auto* info = static_cast<const PLUG_CB_DEBUGEVENT*>(callbackInfo);
        if (info != nullptr && info->DebugEvent != nullptr) {
            std::lock_guard lock(stateMutex_);
            const DEBUG_EVENT& debugEvent = *info->DebugEvent;
            processId_.store(debugEvent.dwProcessId);
            activeThreadId_.store(debugEvent.dwThreadId);
            const std::uint64_t observed = generation_.fetch_add(1U) + 1U;
            EventRecord generic;
            generic.generation = observed;
            generic.processId = debugEvent.dwProcessId;
            generic.threadId = debugEvent.dwThreadId;
            generic.hasProcessId = true;
            generic.hasThreadId = true;
            bool recordGeneric = true;
            switch (debugEvent.dwDebugEventCode) {
            case EXCEPTION_DEBUG_EVENT:
                pendingException_.processId = debugEvent.dwProcessId;
                pendingException_.threadId = debugEvent.dwThreadId;
                pendingException_.code = debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
                pendingException_.address = reinterpret_cast<std::uintptr_t>(
                    debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
                pendingException_.firstChance =
                    debugEvent.u.Exception.dwFirstChance != 0U;
                pendingException_.valid = true;
                recordGeneric = false;
                break;
            case CREATE_THREAD_DEBUG_EVENT:
                generic.kind = EventKind::threadCreated;
                generic.address = reinterpret_cast<std::uintptr_t>(
                    debugEvent.u.CreateThread.lpStartAddress);
                generic.hasAddress = generic.address != 0U;
                break;
            case EXIT_THREAD_DEBUG_EVENT:
                generic.kind = EventKind::threadExited;
                generic.auxiliary = debugEvent.u.ExitThread.dwExitCode;
                break;
            case LOAD_DLL_DEBUG_EVENT:
                generic.kind = EventKind::dllLoaded;
                generic.address = reinterpret_cast<std::uintptr_t>(debugEvent.u.LoadDll.lpBaseOfDll);
                generic.hasAddress = generic.address != 0U;
                break;
            case UNLOAD_DLL_DEBUG_EVENT:
                generic.kind = EventKind::dllUnloaded;
                generic.address =
                    reinterpret_cast<std::uintptr_t>(debugEvent.u.UnloadDll.lpBaseOfDll);
                generic.hasAddress = generic.address != 0U;
                break;
            case OUTPUT_DEBUG_STRING_EVENT:
                generic.kind = EventKind::debugString;
                generic.address = reinterpret_cast<std::uintptr_t>(
                    debugEvent.u.DebugString.lpDebugStringData);
                generic.hasAddress = generic.address != 0U;
                generic.auxiliary = debugEvent.u.DebugString.nDebugStringLength;
                generic.firstChance = debugEvent.u.DebugString.fUnicode != 0U;
                break;
            case RIP_EVENT:
                generic.kind = EventKind::rip;
                generic.auxiliary = debugEvent.u.RipInfo.dwError;
                generic.code = debugEvent.u.RipInfo.dwType;
                generic.hasCode = true;
                break;
            default: recordGeneric = false; break;
            }
            if (recordGeneric) RecordEventLocked(generic);
            stateChanged_.notify_all();
        }
        return;
    }
    default: return;
    }
    TraceReason traceFallback = TraceReason::none;
    switch (callbackType) {
    case CB_BREAKPOINT: traceFallback = TraceReason::breakpoint; break;
    case CB_EXCEPTION:
        traceFallback = pause.kind == PauseReasonKind::userPause
                            ? TraceReason::userPause
                            : TraceReason::exception;
        break;
    case CB_PAUSEDEBUG: traceFallback = TraceReason::userPause; break;
    case CB_EXITPROCESS:
    case CB_STOPDEBUG:
    case CB_STOPPINGDEBUG: traceFallback = TraceReason::processExit; break;
    case CB_STEPPED:
    case CB_SYSTEMBREAKPOINT: traceFallback = TraceReason::interrupted; break;
    default: break;
    }
    if (traceFallback != TraceReason::none) {
        {
            std::lock_guard traceLock(traceMutex_);
            if (trace_.Finalize(traceFallback)) tracePauseSubmitted_ = false;
        }
        traceChanged_.notify_all();
    }
    std::lock_guard lock(stateMutex_);
    if (exceptionBreakpointCallback && pendingException_.valid && pause.hasAddress &&
        pendingException_.code == pause.address &&
        (pendingException_.processId == 0U ||
         pendingException_.processId == processId_.load()) &&
        (pendingException_.threadId == 0U ||
         pendingException_.threadId == activeThreadId_.load())) {
        pause.kind = PauseReasonKind::exception;
        pause.exceptionCode = pendingException_.code;
        pause.hasExceptionCode = true;
        pause.address = pendingException_.address;
        pause.hasAddress = pause.address != 0U;
        pause.firstChance = pendingException_.firstChance;
        event.kind = EventKind::exception;
        event.code = pendingException_.code;
        event.hasCode = true;
        event.address = pendingException_.address;
        event.hasAddress = pendingException_.address != 0U;
        event.firstChance = pendingException_.firstChance;
        pendingException_.valid = false;
    } else if (clearPendingException) {
        pendingException_.valid = false;
    }
    if (resetOrigin) sessionOrigin_.store(SessionOrigin::none);
    if (markAttached) sessionOrigin_.store(SessionOrigin::attached);
    if (markLaunched && sessionOrigin_.load() != SessionOrigin::attached) {
        sessionOrigin_.store(SessionOrigin::launched);
    }
    if (clearProcess) {
        processId_.store(0U);
        activeThreadId_.store(0U);
    } else {
        if (callbackProcessId) processId_.store(*callbackProcessId);
        if (callbackThreadId) activeThreadId_.store(*callbackThreadId);
    }
    if (next == DebuggeeState::paused && activeThreadId_.load() != 0U) {
        pause.threadId = activeThreadId_.load();
        pause.hasThreadId = true;
    }
    if (clearProcess) {
        pauseInterruptPending_.store(false);
    }
    const DebuggeeState previous = debuggeeState_.load();
    if (next == DebuggeeState::paused && previous == DebuggeeState::paused) {
        if (callbackType == CB_PAUSEDEBUG) {
            return;
        }
        if (refineCurrentPause ||
            (callbackType == CB_STEPPED && latestPause_.kind == PauseReasonKind::userPause)) {
            const std::uint64_t observed = generation_.fetch_add(1U) + 1U;
            pausedGeneration_.store(observed);
            pause.generation = observed;
            latestPause_ = pause;
            event.generation = observed;
            RecordEventLocked(event);
            stateChanged_.notify_all();
            return;
        }
    }
    debuggeeState_.store(next);
    const std::uint64_t observed = generation_.fetch_add(1U) + 1U;
    if (markAttached) {
        attachProcessId_.store(callbackProcessId.value_or(0U));
        attachGeneration_.store(observed);
    }
    if (markDetaching) {
        detachProcessId_.store(callbackProcessId.value_or(processId_.load()));
        detachGeneration_.store(observed);
    }
    switch (next) {
    case DebuggeeState::paused:
        pausedGeneration_.store(observed);
        pause.generation = observed;
        if (!hasPauseReason) {
            pause.kind = PauseReasonKind::unknown;
        }
        latestPause_ = pause;
        break;
    case DebuggeeState::running: runningGeneration_.store(observed); break;
    case DebuggeeState::absent: absentGeneration_.store(observed); break;
    case DebuggeeState::starting:
    case DebuggeeState::stopping:
    case DebuggeeState::exited: break;
    }
    event.generation = observed;
    event.processId = processId_.load();
    event.threadId = activeThreadId_.load();
    event.hasProcessId = event.hasProcessId || event.processId != 0U;
    event.hasThreadId = event.hasThreadId || event.threadId != 0U;
    RecordEventLocked(event);
    stateChanged_.notify_all();
}

bool Runtime::OnCommandFence(const std::uint64_t token) noexcept {
    return commandFence_.Signal(token);
}

void Runtime::TraceSupervisor() noexcept {
    std::unique_lock lock(traceMutex_);
    while (!traceSupervisorStopping_) {
        traceChanged_.wait(lock, [this] {
            return traceSupervisorStopping_ || (trace_.Active() && !tracePauseSubmitted_);
        });
        if (traceSupervisorStopping_) break;
        const std::string id = trace_.Id();
        const auto deadline = trace_.Deadline();
        if (traceChanged_.wait_until(lock, deadline, [this, &id] {
                return traceSupervisorStopping_ || !trace_.Active() ||
                       !trace_.Matches(id) || tracePauseSubmitted_;
            })) {
            continue;
        }
        if (!trace_.Active() || !trace_.Matches(id) || tracePauseSubmitted_) continue;
        (void)trace_.RequestStop(TraceReason::timeout);
        tracePauseSubmitted_ = true;
        traceChanged_.notify_all();
        lock.unlock();
#ifndef MCP_LIFECYCLE_HARNESS
        const auto pauseDeadline = std::chrono::steady_clock::now() +
                                   std::chrono::milliseconds(2000);
        (void)executor_.Execute([this, id] {
            std::lock_guard traceLock(traceMutex_);
            if (!trace_.Active() || !trace_.Matches(id)) return std::string{};
            (void)DbgCmdExec("pause");
            return std::string{};
        }, pauseDeadline);
#endif
        lock.lock();
    }
}

void Runtime::Stop() noexcept {
    const PluginState previous = pluginState_.exchange(PluginState::draining);
    if (previous == PluginState::stopped) {
        pluginState_.store(PluginState::stopped);
        return;
    }
    bool pauseTrace = false;
    {
        std::lock_guard lock(traceMutex_);
        if (trace_.Active()) {
            (void)trace_.RequestStop(TraceReason::backendShutdown);
            pauseTrace = !tracePauseSubmitted_;
            tracePauseSubmitted_ = true;
        }
        traceSupervisorStopping_ = true;
    }
    traceChanged_.notify_all();
#ifndef MCP_LIFECYCLE_HARNESS
    if (pauseTrace) {
        const auto pauseDeadline = std::chrono::steady_clock::now() +
                                   std::chrono::milliseconds(1000);
        (void)executor_.Execute([] {
            (void)DbgCmdExec("pause");
            return std::string{};
        }, pauseDeadline);
    }
#else
    (void)pauseTrace;
#endif
    if (traceSupervisor_.joinable()) traceSupervisor_.join();
    {
        std::lock_guard lock(traceMutex_);
        if (trace_.Active()) (void)trace_.Finalize(TraceReason::backendShutdown);
    }
    traceChanged_.notify_all();
    commandFence_.Stop();
    stateChanged_.notify_all();
    CloseHandleValue(nonceWriter_); // stdin EOF asks the child to shut down gracefully.
    if (worker_.joinable()) {
        CancelSynchronousIo(worker_.native_handle());
    }
    if (pipe_ != INVALID_HANDLE_VALUE) {
        CancelIoEx(pipe_, nullptr);
        DisconnectNamedPipe(pipe_);
    }
    if (worker_.joinable()) {
        worker_.join();
    }
    executor_.Stop();
    if (sidecarProcess_ != nullptr && WaitForSingleObject(sidecarProcess_, kShutdownMs) == WAIT_TIMEOUT) {
        TerminateProcess(sidecarProcess_, ERROR_PROCESS_ABORTED); // bounded last resort only.
        WaitForSingleObject(sidecarProcess_, 1000U);
    }
    CloseHandleValue(sidecarProcess_);
    CloseHandleValue(sidecarJob_);
    if (pipe_ != INVALID_HANDLE_VALUE) {
        CloseHandle(pipe_);
        pipe_ = INVALID_HANDLE_VALUE;
    }
    CloseHandleValue(instanceMutex_);
    SecureZeroMemory(nonce_.data(), nonce_.size());
    nonce_.clear();
    instanceId_.clear();
    pluginState_.store(PluginState::stopped);
}

void Runtime::CloseHandleValue(HANDLE& handle) noexcept {
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
    }
    handle = nullptr;
}
} // namespace mcp
