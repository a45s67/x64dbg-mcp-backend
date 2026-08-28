#include "utf8.h"

#include <iostream>
#include <cstdint>
#include <string>
#include <string_view>

namespace {
bool Expect(const std::string_view name, const std::string& actual,
            const std::string_view expected) {
    if (actual == expected) {
        return true;
    }
    std::cerr << name << " mismatch\nactual:   " << actual << "\nexpected: " << expected << '\n';
    return false;
}

std::uint64_t Next(std::uint64_t& state) {
    state = state * 6364136223846793005ULL + 1442695040888963407ULL;
    return state;
}

bool ExerciseDeterministicCorpus() {
    constexpr std::uint64_t seed = 0x555446385f4a534eULL;
    constexpr std::size_t cases = 4096U;
    std::uint64_t state = seed;
    for (std::size_t index = 0; index < cases; ++index) {
        const std::size_t length = static_cast<std::size_t>(Next(state) % 257U);
        std::string input(length, '\0');
        for (char& value : input) value = static_cast<char>(Next(state) & 0xffU);
        const std::string escaped = mcp::JsonString(input);
        if (escaped.size() < 2U || escaped.front() != '"' || escaped.back() != '"' ||
            escaped.size() > input.size() * 6U + 2U || !mcp::IsValidUtf8(escaped)) {
            std::cerr << "deterministic UTF-8 corpus failed; seed=" << seed
                      << " case=" << index << '\n';
            return false;
        }
        (void)mcp::Utf8OrdinalEqualsIgnoreCase(input, escaped);
        (void)mcp::Utf8OrdinalContainsIgnoreCase(input, escaped);
        (void)mcp::Utf8OrdinalFindIgnoreCase(input, escaped);
    }
    return true;
}
}  // namespace

int main() {
    bool ok = true;
    ok &= Expect("ascii escaping", mcp::JsonString("a\"b\\c\n\t\x01z"),
                 "\"a\\\"b\\\\c\\n\\t\\u0001z\"");
    ok &= Expect("valid unicode", mcp::JsonString("München-分析-😀"),
                 "\"München-分析-😀\"");
    ok &= Expect("overlong", mcp::JsonString(std::string("x\xc0\xafy", 4)),
                 std::string("\"x\xef\xbf\xbd\xef\xbf\xbdy\"", 10));
    ok &= Expect("isolated continuation", mcp::JsonString(std::string("\x80", 1)),
                 std::string("\"\xef\xbf\xbd\"", 5));
    ok &= Expect("surrogate", mcp::JsonString(std::string("\xed\xa0\x80", 3)),
                 std::string("\"\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\"", 11));
    ok &= Expect("truncated", mcp::JsonString(std::string("\xf0\x9f", 2)),
                 std::string("\"\xef\xbf\xbd\xef\xbf\xbd\"", 8));
    ok &= mcp::IsValidUtf8("München-分析-😀");
    ok &= !mcp::IsValidUtf8(std::string("\xed\xa0\x80", 3));
    ok &= mcp::Utf8SequenceLength("A分析", 0U) == 1U;
    ok &= mcp::Utf8SequenceLength("A分析", 1U) == 3U;
    ok &= mcp::Utf8SequenceLength(std::string("\xff", 1), 0U) == 0U;
    ok &= mcp::Utf8SequenceLength("A", 1U) == 0U;

    ok &= mcp::Utf8OrdinalEqualsIgnoreCase("München-分析.EXE", "MÜNCHEN-分析.exe");
    ok &= mcp::Utf8OrdinalContainsIgnoreCase("prefix-München-分析-suffix", "MÜNCHEN-分析");
    ok &= mcp::Utf8OrdinalFindIgnoreCase("前綴-München-分析", "MÜNCHEN").value_or(0U) == 7U;
    ok &= !mcp::Utf8OrdinalContainsIgnoreCase("München", "分析");
    ok &= !mcp::Utf8OrdinalEqualsIgnoreCase(std::string("bad\xff", 4), "BAD");
    ok &= ExerciseDeterministicCorpus();
    if (!ok) {
        std::cerr << "UTF-8 boundary tests failed\n";
        return 1;
    }
    std::cout << "UTF-8 boundary tests passed\n";
    return 0;
}
