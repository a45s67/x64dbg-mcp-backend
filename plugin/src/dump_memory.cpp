#include "dump_memory.h"

#include <Windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <limits>
#include <vector>

namespace mcp {
bool ValidDumpPath(const std::wstring_view path) noexcept {
    if (path.size() < 4U || path.size() >= 32700U ||
        !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) ||
        path[1] != L':' || path[2] != L'\\') return false;
    std::size_t start = 3U;
    for (std::size_t end = start; end <= path.size(); ++end) {
        if (end < path.size() && path[end] != L'\\') {
            const wchar_t c = path[end];
            if (c < 32 || c == 127 || c == L':' || c == L'/' || c == L'"' ||
                c == L'<' || c == L'>' || c == L'|' || c == L'?' || c == L'*') return false;
            continue;
        }
        const auto part = path.substr(start, end - start);
        if (part.empty() || part.back() == L'.' || part.back() == L' ') return false;
        const auto stem = part.substr(0U, part.find(L'.'));
        const auto equal = [stem](std::wstring_view reserved) {
            if (stem.size() != reserved.size()) return false;
            for (std::size_t i = 0; i < stem.size(); ++i) {
                wchar_t c = stem[i];
                if (c >= L'a' && c <= L'z') c -= L'a' - L'A';
                if (c != reserved[i]) return false;
            }
            return true;
        };
        if (equal(L"CON") || equal(L"PRN") || equal(L"AUX") || equal(L"NUL") ||
            equal(L"CONIN$") || equal(L"CONOUT$")) return false;
        if (stem.size() == 4U && (equal(L"COM1") || equal(L"COM2") || equal(L"COM3") ||
            equal(L"COM4") || equal(L"COM5") || equal(L"COM6") || equal(L"COM7") ||
            equal(L"COM8") || equal(L"COM9") || equal(L"LPT1") || equal(L"LPT2") ||
            equal(L"LPT3") || equal(L"LPT4") || equal(L"LPT5") || equal(L"LPT6") ||
            equal(L"LPT7") || equal(L"LPT8") || equal(L"LPT9") ||
            stem.back() == L'\u00b9' || stem.back() == L'\u00b2' || stem.back() == L'\u00b3')) return false;
        start = end + 1U;
    }
    return true;
}

DumpResult DumpMemory(const std::wstring& path, const std::uint64_t address,
    const std::size_t length, const bool overwrite,
    const std::chrono::steady_clock::time_point deadline,
    const std::function<bool(std::uint64_t, unsigned char*, std::size_t)>& reader,
    const std::function<bool()>& current) {
    DumpResult result;
    if (!ValidDumpPath(path) || length == 0U || length > 67108864U ||
        address > (std::numeric_limits<std::uint64_t>::max)() - (length - 1U)) {
        result.code = "INVALID_ARGUMENT";
        result.message = "dump requires a drive-absolute regular-file path and 1..67108864 bytes";
        return result;
    }
    struct Resources {
        std::vector<HANDLE> ancestors;
        HANDLE file{INVALID_HANDLE_VALUE};
        BCRYPT_ALG_HANDLE algorithm{nullptr};
        BCRYPT_HASH_HANDLE hash{nullptr};
        std::wstring temporary;
        bool ownsTemporary{false};
        ~Resources() {
            if (hash) BCryptDestroyHash(hash);
            if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0U);
            if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
            if (ownsTemporary) DeleteFileW(temporary.c_str());
            for (const HANDLE handle : ancestors) CloseHandle(handle);
        }
    } resources;
    const auto valid = [&] {
        if (std::chrono::steady_clock::now() >= deadline) {
            result.code = "TIMEOUT";
            result.message = "dump deadline expired before publication";
            return false;
        }
        if (!current()) {
            result.code = "BUSY";
            result.message = "debugger changed before dump publication";
            return false;
        }
        return true;
    };
    if (!valid()) return result;
    const auto separator = path.rfind(L'\\');
    // Deny delete sharing for every ancestor, preventing rename/reparse swaps
    // between validation, sibling creation, and publication.
    resources.ancestors.reserve(static_cast<std::size_t>(std::count(path.begin(), path.end(), L'\\')));
    for (std::size_t end = 2U; end <= separator; ++end) {
        if (path[end] != L'\\') continue;
        const std::wstring directory = end == 2U ? path.substr(0U, 3U) : path.substr(0U, end);
        const HANDLE handle = CreateFileW(directory.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (handle == INVALID_HANDLE_VALUE) return result;
        resources.ancestors.push_back(handle);
        BY_HANDLE_FILE_INFORMATION info{};
        if (GetFileType(handle) != FILE_TYPE_DISK || !GetFileInformationByHandle(handle, &info) ||
            (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U ||
            (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U || !valid()) return result;
    }
    const auto destinationValid = [&] {
        const DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) return GetLastError() == ERROR_FILE_NOT_FOUND;
        return overwrite && (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT |
                                          FILE_ATTRIBUTE_DEVICE)) == 0U;
    };
    if (!destinationValid()) return result;
    std::array<unsigned char, 16> random{};
    if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return result;
    random[6] = static_cast<unsigned char>((random[6] & 0x0fU) | 0x40U);
    random[8] = static_cast<unsigned char>((random[8] & 0x3fU) | 0x80U);
    constexpr wchar_t digits[] = L"0123456789abcdef";
    resources.temporary = path.substr(0U, separator + 1U) + L".mcp-dump-";
    for (std::size_t i = 0; i < random.size(); ++i) {
        if (i == 4U || i == 6U || i == 8U || i == 10U) resources.temporary += L'-';
        resources.temporary += digits[random[i] >> 4U];
        resources.temporary += digits[random[i] & 15U];
    }
    resources.temporary += L".tmp";
    resources.file = CreateFileW(resources.temporary.c_str(), GENERIC_WRITE | DELETE, 0U, nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (resources.file == INVALID_HANDLE_VALUE) return result;
    resources.ownsTemporary = true;
    if (BCryptOpenAlgorithmProvider(&resources.algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0U) < 0 ||
        BCryptCreateHash(resources.algorithm, &resources.hash, nullptr, 0U, nullptr, 0U, 0U) < 0) return result;
    std::array<unsigned char, 65536> buffer{};
    for (std::size_t offset = 0U; offset < length;) {
        const auto count = (std::min)(buffer.size(), length - offset);
        if (!valid()) return result;
        if (!reader(address + offset, buffer.data(), count)) {
            result.message = "memory range is not fully readable; dump was not published";
            return result;
        }
        if (!valid()) return result;
        DWORD written = 0U;
        if (!WriteFile(resources.file, buffer.data(), static_cast<DWORD>(count), &written, nullptr) ||
            written != count || BCryptHashData(resources.hash, buffer.data(), written, 0U) < 0) return result;
        offset += count;
        if (!valid()) return result;
    }
    std::array<unsigned char, 32> digest{};
    if (BCryptFinishHash(resources.hash, digest.data(), static_cast<ULONG>(digest.size()), 0U) < 0 ||
        !FlushFileBuffers(resources.file)) return result;
    result.sha256.reserve(64U);
    for (const unsigned char byte : digest) {
        result.sha256 += static_cast<char>(digits[byte >> 4U]);
        result.sha256 += static_cast<char>(digits[byte & 15U]);
    }
    if (!destinationValid() || !valid()) return result;
    const auto pathBytes = path.size() * sizeof(wchar_t);
    const auto renameBytes = offsetof(FILE_RENAME_INFO, FileName) + pathBytes;
    std::vector<std::max_align_t> renameStorage(
        (renameBytes + sizeof(wchar_t) + sizeof(std::max_align_t) - 1U) /
        sizeof(std::max_align_t));
    std::memset(renameStorage.data(), 0,
                renameStorage.size() * sizeof(std::max_align_t));
    auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(renameStorage.data());
    rename->ReplaceIfExists = overwrite ? TRUE : FALSE;
    rename->RootDirectory = nullptr;
    rename->FileNameLength = static_cast<DWORD>(pathBytes);
    std::memcpy(rename->FileName, path.data(), pathBytes);
    rename->FileName[path.size()] = L'\0';
    if (!SetFileInformationByHandle(resources.file, FileRenameInfo, rename,
                                    static_cast<DWORD>(renameBytes + sizeof(wchar_t)))) return result;
    resources.ownsTemporary = false;
    result.bytesWritten = length;
    result.complete = true;
    result.code = nullptr;
    result.message = nullptr;
    return result;
}
}
