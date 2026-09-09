#include "dump_memory.h"

#include <Windows.h>

#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {
constexpr std::uint64_t kBase = 0x1000U;

std::size_t TemporaryCount(const std::filesystem::path& directory) {
    std::size_t count = 0U;
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.path().filename().wstring().starts_with(L".mcp-dump-") &&
            entry.path().extension() == L".tmp") ++count;
    }
    return count;
}
}

int main() {
    const auto directory = std::filesystem::temp_directory_path() /
        (L"x64dbg-mcp-dump-test-" + std::to_wstring(GetCurrentProcessId()));
    std::error_code error;
    std::filesystem::remove_all(directory, error);
    assert(std::filesystem::create_directory(directory));
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::error_code ignored; std::filesystem::remove_all(path, ignored); }
    } cleanup{directory};
    (void)cleanup;

    assert(mcp::ValidDumpPath((directory / L"dump.bin").wstring()));
    assert(!mcp::ValidDumpPath(L"relative.bin"));
    assert(!mcp::ValidDumpPath(L"C:\\bad?name.bin"));
    assert(!mcp::ValidDumpPath(L"C:\\CON.txt"));
    assert(!mcp::ValidDumpPath(L"C:\\trailing.\\file.bin"));

    const auto reader = [](const std::uint64_t address, unsigned char* bytes,
                           const std::size_t size) {
        for (std::size_t index = 0U; index < size; ++index) {
            bytes[index] = static_cast<unsigned char>((address - kBase + index) & 0xffU);
        }
        return true;
    };
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    const auto destination = directory / L"dump.bin";
    const auto first = mcp::DumpMemory(destination.wstring(), kBase, 256U, false, deadline,
                                       reader, [] { return true; });
    assert(first.complete && first.bytesWritten == 256U);
    assert(first.sha256 == "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880");
    std::ifstream input(destination, std::ios::binary);
    const std::vector<unsigned char> bytes{std::istreambuf_iterator<char>(input), {}};
    assert(bytes.size() == 256U && bytes.front() == 0U && bytes.back() == 255U);
    assert(std::distance(std::filesystem::directory_iterator(directory),
                         std::filesystem::directory_iterator{}) == 1);
    input.close();

    const auto denied = mcp::DumpMemory(destination.wstring(), kBase, 16U, false, deadline,
                                        reader, [] { return true; });
    assert(!denied.complete);
    assert(std::filesystem::file_size(destination) == 256U);

    const auto replaced = mcp::DumpMemory(destination.wstring(), kBase, 16U, true, deadline,
                                          reader, [] { return true; });
    assert(replaced.complete && replaced.bytesWritten == 16U);
    assert(std::filesystem::file_size(destination) == 16U);

    const auto failed = mcp::DumpMemory((directory / L"failed.bin").wstring(), kBase, 128U,
        false, deadline, [](std::uint64_t, unsigned char*, std::size_t) { return false; },
        [] { return true; });
    assert(!failed.complete && !std::filesystem::exists(directory / L"failed.bin"));
    assert(TemporaryCount(directory) == 0U);
    return 0;
}
