#include "runtime.h"
#include "utf8.h"

#include <bcrypt.h>
#include <sddl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <charconv>
#include <cstddef>
#include <cstring>
#include <filesystem>
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
#include "jansson/jansson.h"

namespace mcp {
namespace {
constexpr DWORD kMaxFrameBytes = 1024U * 1024U;
constexpr DWORD kShutdownMs = 5000U;
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
    std::optional<std::uint64_t> cursorFingerprint;
    bool discoveryCursorInvalid{false};
};

bool IsMutation(const std::string_view method) {
    return method == "debugger.pause" || method == "debugger.resume" ||
           method == "debugger.step_into" || method == "debugger.step_over" ||
           method == "debugger.stop" || method == "memory.write" ||
           method == "breakpoints.set" || method == "breakpoints.remove" ||
           method == "debuggee.launch";
}

bool IsPageMethod(const std::string_view method) {
    return method == "memory.map" || method == "modules.list" || method == "threads.list" ||
           method == "breakpoints.list";
}

bool IsDiscoveryMethod(const std::string_view method) {
    return method == "symbols.search" || method == "functions.list" ||
           method == "strings.search" || method == "references.to";
}

std::uint64_t DiscoveryFingerprint(const std::string_view method,
                                   const std::string_view module,
                                   const std::string_view query,
                                   const std::string_view encoding,
                                   const std::size_t minLength) {
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
    const bool mutation = IsMutation(methodValue);
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
    std::optional<std::uint64_t> cursorFingerprint;
    bool discoveryCursorInvalid = false;
    if (methodValue == "debugger.state") {
        if (json_object_size(payload) != 0U) {
            return std::nullopt;
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
        const std::size_t expectedFields = directoryValue == nullptr ? 2U : 3U;
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
    } else if (methodValue == "address.resolve") {
        if (json_object_size(payload) != 1U ||
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
        if (json_object_size(payload) > 1U) {
            return std::nullopt;
        }
        json_t* names = json_object_get(payload, "names");
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
    } else if (IsDiscoveryMethod(methodValue)) {
        json_t* module = json_object_get(payload, "module");
        json_t* queryValue = json_object_get(payload, "query");
        json_t* encoding = json_object_get(payload, "encoding");
        json_t* minimum = json_object_get(payload, "min_length");
        json_t* limit = json_object_get(payload, "limit");
        json_t* cursor = json_object_get(payload, "cursor");
        json_t* address = json_object_get(payload, "address");
        const bool references = methodValue == "references.to";
        const std::size_t expectedFields = 1U + (queryValue ? 1U : 0U) +
                                           (encoding ? 1U : 0U) + (minimum ? 1U : 0U) +
                                           (limit ? 1U : 0U) + (cursor ? 1U : 0U);
        if (json_object_size(payload) != expectedFields ||
            (references ? !ParseAddressReference(address, addressValue)
                        : !IsBoundedModuleName(module)) ||
            (references && module != nullptr) || (!references && address != nullptr) ||
            (references && queryValue != nullptr) ||
            (methodValue != "strings.search" && (encoding != nullptr || minimum != nullptr))) {
            return std::nullopt;
        }
        if (!references) {
            moduleFilter.assign(json_string_value(module), json_string_length(module));
        }
        if (queryValue != nullptr) {
            if (!json_is_string(queryValue) || json_string_length(queryValue) == 0U ||
                json_string_length(queryValue) > 256U) return std::nullopt;
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
        if (limit != nullptr) {
            if (!json_is_integer(limit) || json_integer_value(limit) < 1 ||
                json_integer_value(limit) > 256) return std::nullopt;
            pageLimit = static_cast<std::size_t>(json_integer_value(limit));
        }
        const std::uint64_t expectedFingerprint = DiscoveryFingerprint(
            methodValue, moduleFilter, query, stringEncoding, minStringLength);
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
    } else if (methodValue == "debugger.pause" || methodValue == "debugger.resume" ||
               methodValue == "debugger.step_into" || methodValue == "debugger.step_over" ||
               methodValue == "debugger.stop") {
        if (json_object_size(payload) != 1U ||
            !json_is_string(json_object_get(payload, "operation_id"))) {
            return std::nullopt;
        }
    } else if (methodValue == "breakpoints.set" || methodValue == "breakpoints.remove") {
        if (json_object_size(payload) != 2U ||
            !json_is_string(json_object_get(payload, "operation_id")) ||
            !ParseAddressReference(json_object_get(payload, "address"), addressValue)) {
            return std::nullopt;
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
                   addressValue, lengthValue, std::move(registerNames), pageLimit,
                   cursorGeneration, cursorIndex, instructionCount,
                   std::move(writeBytes), afterGeneration, waitTimeoutMs,
                   std::move(moduleFilter), std::move(query), std::move(stringEncoding),
                   minStringLength, cursorFingerprint, discoveryCursorInvalid};
}

bool IsAcceptedHandshakeAck(const std::string_view bytes) {
    json_error_t error{};
    JsonOwner root(json_loadb(bytes.data(), bytes.size(), JSON_REJECT_DUPLICATES, &error));
    if (!root || !json_is_object(root.get()) || json_object_size(root.get()) != 4U) {
        return false;
    }
    json_t* major = json_object_get(root.get(), "protocol_major");
    json_t* minor = json_object_get(root.get(), "protocol_minor");
    json_t* accepted = json_object_get(root.get(), "accepted");
    json_t* errorCode = json_object_get(root.get(), "error_code");
    return json_is_integer(major) && json_integer_value(major) == 1 && json_is_integer(minor) &&
           json_integer_value(minor) == 0 && json_is_true(accepted) && json_is_null(errorCode);
}

std::string HexValue(const std::uint64_t value) {
    std::ostringstream formatted;
    formatted << "0x" << std::hex << std::nouppercase << value;
    return formatted.str();
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

struct StringCandidate {
    std::size_t offset{0};
    std::size_t byteLength{0};
    std::string text;
    const char* encoding{"ascii_utf8"};
    bool truncated{false};
    std::size_t key{0};
    std::size_t matchOffset{0};
    std::size_t textOffset{0};
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
#endif

bool Runtime::Start() {
    PluginState expected = PluginState::stopped;
    if (!pluginState_.compare_exchange_strong(expected, PluginState::starting)) {
        return false;
    }
    std::wstring mutexName = std::wstring(L"Local\\x64dbg-mcp-backend-") + kBackend;
#ifdef MCP_LIFECYCLE_HARNESS
    // A lifecycle harness is an isolated backend instance. Keep its ownership
    // check independent from a debugger the developer may already be running.
    mutexName += L"-test-" + std::to_wstring(GetCurrentProcessId());
#endif
    instanceMutex_ = CreateMutexW(nullptr, FALSE, mutexName.c_str());
    if (instanceMutex_ == nullptr || GetLastError() == ERROR_ALREADY_EXISTS || !executor_.Start() ||
        !CreateEndpoint() || !LaunchSidecar()) {
        Stop();
        return false;
    }
    try {
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
        executable = ModuleDirectory() / L".." / L".." / L"server" / L"x64dbg-mcp-server.exe";
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
    handshake << "{\"protocol_major\":1,\"protocol_minor\":0,\"backend\":\""
              << kBackendUtf8 << "\",\"plugin_pid\":" << GetCurrentProcessId()
              << ",\"nonce\":" << JsonString(nonce_) << "}";
    std::string ack;
    if (!WriteFrame(pipe_, handshake.str()) || !ReadFrame(pipe_, ack) ||
        !IsAcceptedHandshakeAck(ack)) {
        PluginLog("[x64dbg-mcp-backend] sidecar IPC handshake failed");
        return;
    }
    {
        std::lock_guard lock(stateMutex_);
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
        const ExecutionResult execution = executor_.Execute(
            [this, parsed, requestDeadline] {
                if (parsed->method == "debugger.state") {
                    return StateResponse(parsed->requestId);
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
                const bool addressMethod = parsed->method == "address.resolve" ||
                                           parsed->method == "memory.read" ||
                                           parsed->method == "memory.write" ||
                                           parsed->method == "breakpoints.set" ||
                                           parsed->method == "breakpoints.remove" ||
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
                if (IsDiscoveryMethod(parsed->method) && parsed->discoveryCursorInvalid) {
                    return ErrorResponse(*parsed, "INVALID_ARGUMENT",
                                         "cursor does not match the discovery filters", false,
                                         false);
                }
                if (parsed->method == "address.resolve") {
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(resolvedGeneration) +
                           ",\"status\":\"ok\",\"result\":" +
                           LocationJson(*resolvedLocation, resolvedGeneration) + "}";
                }
                if (parsed->method == "debuggee.launch") {
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
                    std::string requestedDirectory = parsed->workingDirectory;
                    if (requestedDirectory.empty()) {
                        const std::u8string encoded(
                            reinterpret_cast<const char8_t*>(executable->data()),
                            executable->size());
                        const std::filesystem::path executablePath(encoded);
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
                    const std::uint64_t before = generation_.load();
                    const std::string command = "init \"" + *executable + "\", \"\", \"" +
                                                *workingDirectory + "\"";
                    if (!DbgCmdExec(command.c_str())) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger command queue rejected the launch", true,
                                             false);
                    }
                    if (!WaitForActionableLaunchPause(before, requestDeadline)) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "launch did not reach an actionable debugger pause",
                                             false, true);
                    }
                    const std::uint64_t confirmed = ObservedGeneration(DebuggeeState::paused);
                    return "{\"request_id\":" + JsonString(parsed->requestId) +
                           ",\"state_generation\":" + std::to_string(confirmed) +
                           ",\"status\":\"ok\",\"result\":{\"debuggee_state\":\"paused\",\"path\":" +
                           JsonString(*executable) + ",\"working_directory\":" +
                           JsonString(*workingDirectory) + ",\"state_generation\":" +
                           std::to_string(confirmed) + "}}";
                }
                if (parsed->method == "debugger.pause" || parsed->method == "debugger.resume" ||
                    parsed->method == "debugger.step_into" ||
                    parsed->method == "debugger.step_over" || parsed->method == "debugger.stop") {
                    const DebuggeeState state = debuggeeState_.load();
                    const char* command = nullptr;
                    DebuggeeState expected = state;
                    bool valid = false;
                    if (parsed->method == "debugger.pause") {
                        command = "pause";
                        expected = DebuggeeState::paused;
                        valid = state == DebuggeeState::running;
                    } else if (parsed->method == "debugger.resume") {
                        command = "run";
                        expected = DebuggeeState::running;
                        valid = state == DebuggeeState::paused;
                    } else if (parsed->method == "debugger.step_into") {
                        command = "sti";
                        expected = DebuggeeState::paused;
                        valid = state == DebuggeeState::paused;
                    } else if (parsed->method == "debugger.step_over") {
                        command = "sto";
                        expected = DebuggeeState::paused;
                        valid = state == DebuggeeState::paused;
                    } else {
                        command = "stop";
                        expected = DebuggeeState::absent;
                        valid = state == DebuggeeState::starting || state == DebuggeeState::running ||
                                state == DebuggeeState::paused;
                    }
                    if (!valid || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation is not valid in the current debugger state",
                                             false, false);
                    }
                    const std::uint64_t before = generation_.load();
                    if (!DbgCmdExec(command)) {
                        return ErrorResponse(*parsed, "BUSY",
                                             "debugger command queue rejected the operation", true,
                                             false);
                    }
                    const bool isStep = parsed->method == "debugger.step_into" ||
                                        parsed->method == "debugger.step_over";
                    const bool outcomeConfirmed =
                        isStep ? WaitForPauseReason(PauseReasonKind::step, before, requestDeadline)
                               : WaitForState(expected, before, requestDeadline);
                    if (!outcomeConfirmed) {
                        return ErrorResponse(*parsed, "TIMEOUT",
                                             "mutation outcome was not callback-confirmed", false,
                                             true);
                    }
                    const std::uint64_t confirmed = ObservedGeneration(expected);
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
                if (parsed->method == "registers.read") {
                    const std::optional<std::uint64_t> snapshot = BeginPausedSnapshot();
                    if (!snapshot || !DbgIsDebugging()) {
                        return ErrorResponse(*parsed, "INVALID_DEBUGGER_STATE",
                                             "operation requires a paused debuggee", false, false);
                    }
                    REGDUMP_AVX512 dump{};
                    if (!DbgGetRegDumpEx(&dump, sizeof(dump))) {
                        return ErrorResponse(*parsed, "INTERNAL",
                                             "register snapshot is unavailable", true, false);
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
                        const std::optional<duint> value = RegisterValue(dump.regcontext, names[index]);
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
                           ",\"status\":\"ok\",\"result\":{\"registers\":" + registers +
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
                    const auto matchOffset = [parsed](const std::string_view text) {
                        if (!IsValidUtf8(text)) return std::optional<std::size_t>{};
                        return Utf8OrdinalFindIgnoreCase(text, parsed->query);
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
                            const auto match = matchOffset(text);
                            if (characterCount >= parsed->minStringLength && key >= cursorKey &&
                                match && ascii.size() < retain) {
                                const auto context = ContextAroundUtf8Match(text, *match);
                                ascii.push_back(StringCandidate{
                                    absoluteOffset, length, context.text, "ascii_utf8",
                                    context.truncated, key, *match, context.offset});
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
                            const auto match = text ? matchOffset(*text)
                                                    : std::optional<std::size_t>{};
                            if (units.size() >= parsed->minStringLength && key >= cursorKey && text &&
                                match && wide.size() < retain) {
                                const auto context = ContextAroundUtf8Match(*text, *match);
                                wide.push_back(StringCandidate{
                                    scanStart + begin, units.size() * 2U, context.text, "utf16le",
                                    context.truncated, key, *match, context.offset});
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
                                 LocationJson(LocationFromModules(address, *modules), *snapshot) +
                                 "}";
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
                if (parsed->method == "symbols.search" ||
                    parsed->method == "functions.list") {
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
                        return ErrorResponse(*parsed, "INVALID_ARGUMENT", "cursor is stale", false,
                                             false);
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
                        map.count > 1'000'000) {
                        return ErrorResponse(*parsed, "INTERNAL", "memory map is invalid", false,
                                             false);
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
                        const MEMPAGE& page = map.page[index];
                        if (index != parsed->cursorIndex) items.push_back(',');
                        const std::size_t infoLength = strnlen_s(page.info, sizeof(page.info));
                        items += "{\"base\":" +
                                 JsonString(HexValue(reinterpret_cast<std::uintptr_t>(
                                     page.mbi.BaseAddress))) +
                                 ",\"size\":" + JsonString(HexValue(page.mbi.RegionSize)) +
                                 ",\"allocation_base\":" +
                                 JsonString(HexValue(reinterpret_cast<std::uintptr_t>(
                                     page.mbi.AllocationBase))) +
                                 ",\"protect\":" + JsonString(HexValue(page.mbi.Protect)) +
                                 ",\"state\":" + JsonString(HexValue(page.mbi.State)) +
                                 ",\"type\":" + JsonString(HexValue(page.mbi.Type)) +
                                 ",\"info\":" + JsonString(std::string_view(page.info, infoLength)) +
                                 "}";
                    }
                    items += "]";
                    const std::string next = end < count
                                                 ? JsonString("v1:" + std::to_string(generation) + ":" +
                                                              std::to_string(end))
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
                        items += "{\"address\":" + JsonString(HexValue(breakpoint.addr)) +
                                 ",\"type\":" + JsonString(type) + ",\"enabled\":" +
                                 (breakpoint.enabled ? "true" : "false") + ",\"active\":" +
                                 (breakpoint.active ? "true" : "false") +
                                 ",\"hit_count\":" + std::to_string(breakpoint.hitCount) + "}";
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

std::string Runtime::StateResponse(const std::string& requestId) {
    DebuggeeState state;
    std::uint64_t generation = 0;
    std::uint32_t processId = 0;
    std::uint32_t threadId = 0;
    PauseObservation pause;
    {
        std::lock_guard lock(stateMutex_);
        state = debuggeeState_.load();
        generation = generation_.load();
        processId = processId_.load();
        threadId = activeThreadId_.load();
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
           ",\"status\":\"ok\",\"result\":{\"backend\":\"" + kBackendUtf8 +
           "\",\"architecture\":\"" +
#ifdef _WIN64
           "x86_64" +
#else
           "x86" +
#endif
           "\",\"plugin_state\":\"ready\",\"debuggee_state\":\"" + stateName +
           "\",\"process_id\":" +
           (processId == 0U ? "null" : JsonString(HexValue(processId))) +
           ",\"active_thread_id\":" +
           (threadId == 0U ? "null" : JsonString(HexValue(threadId))) +
           ",\"instruction_pointer\":" + instructionPointer +
           ",\"pause_reason\":" +
           (state == DebuggeeState::paused ? PauseReasonJson(pause) : "null") +
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

void Runtime::OnDebuggerEvent(const int callbackType, void* const callbackInfo) noexcept {
    DebuggeeState next = debuggeeState_.load();
    PauseObservation pause;
    std::optional<std::uint32_t> callbackProcessId;
    std::optional<std::uint32_t> callbackThreadId;
    bool clearProcess = false;
    bool hasPauseReason = false;
    bool refineCurrentPause = false;
    switch (callbackType) {
    case CB_INITDEBUG: next = DebuggeeState::starting; break;
    case CB_CREATEPROCESS: {
        const auto* info = static_cast<const PLUG_CB_CREATEPROCESS*>(callbackInfo);
        if (info != nullptr && info->fdProcessInfo != nullptr) {
            callbackProcessId = info->fdProcessInfo->dwProcessId;
            callbackThreadId = info->fdProcessInfo->dwThreadId;
        }
        next = DebuggeeState::paused;
        pause.kind = PauseReasonKind::processCreated;
        hasPauseReason = true;
        break;
    }
    case CB_SYSTEMBREAKPOINT:
        next = DebuggeeState::paused;
        pause.kind = PauseReasonKind::systemBreakpoint;
        hasPauseReason = true;
        refineCurrentPause = true;
        break;
    case CB_BREAKPOINT: {
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
        }
        break;
    }
    case CB_EXCEPTION: {
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
        }
        break;
    }
    case CB_PAUSEDEBUG:
        next = DebuggeeState::paused;
        pause.kind = PauseReasonKind::userPause;
        hasPauseReason = true;
        break;
    case CB_STEPPED:
        next = DebuggeeState::paused;
        pause.kind = PauseReasonKind::step;
        hasPauseReason = true;
        break;
    case CB_RESUMEDEBUG: next = DebuggeeState::running; break;
    case CB_STOPPINGDEBUG: next = DebuggeeState::stopping; break;
    case CB_EXITPROCESS: next = DebuggeeState::exited; break;
    case CB_STOPDEBUG:
        clearProcess = true;
        next = DebuggeeState::absent;
        break;
    case CB_DEBUGEVENT: {
        const auto* info = static_cast<const PLUG_CB_DEBUGEVENT*>(callbackInfo);
        if (info != nullptr && info->DebugEvent != nullptr) {
            std::lock_guard lock(stateMutex_);
            processId_.store(info->DebugEvent->dwProcessId);
            activeThreadId_.store(info->DebugEvent->dwThreadId);
            generation_.fetch_add(1U);
            stateChanged_.notify_all();
        }
        return;
    }
    default: return;
    }
    std::lock_guard lock(stateMutex_);
    if (clearProcess) {
        processId_.store(0U);
        activeThreadId_.store(0U);
    } else {
        if (callbackProcessId) processId_.store(*callbackProcessId);
        if (callbackThreadId) activeThreadId_.store(*callbackThreadId);
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
            stateChanged_.notify_all();
            return;
        }
    }
    debuggeeState_.store(next);
    const std::uint64_t observed = generation_.fetch_add(1U) + 1U;
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
    stateChanged_.notify_all();
}

void Runtime::Stop() noexcept {
    const PluginState previous = pluginState_.exchange(PluginState::draining);
    if (previous == PluginState::stopped) {
        pluginState_.store(PluginState::stopped);
        return;
    }
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
    pluginState_.store(PluginState::stopped);
}

void Runtime::CloseHandleValue(HANDLE& handle) noexcept {
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
    }
    handle = nullptr;
}
} // namespace mcp
