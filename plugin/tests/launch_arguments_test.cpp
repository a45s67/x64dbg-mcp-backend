#include "launch_arguments.h"

#include <cassert>

int main() {
    using namespace mcp;
    assert(QuoteWindowsArgument("") == "\"\"");
    assert(QuoteWindowsArgument("plain") == "\"plain\"");
    assert(QuoteWindowsArgument("with space") == "\"with space\"");
    assert(QuoteWindowsArgument("comma,value") == "\"comma,value\"");
    assert(QuoteWindowsArgument("quote\"inside") == "\"quote\\\"inside\"");
    assert(QuoteWindowsArgument("trail\\") == "\"trail\\\\\"");
    assert(QuoteWindowsArgument("two\\\\\"quotes") ==
           "\"two\\\\\\\\\\\"quotes\"");
    const std::vector<std::string> values{
        "", "plain", "with space", "quote\"inside", "trail\\", "comma,value",
        "\xe5\x85\xa9\xe5\x80\x8b\xe5\xad\x97"};
    const auto rendered = RenderWindowsArguments(values);
    assert(rendered && rendered->starts_with("\"\" \"plain\""));
    assert(ValidLaunchArgument("\xe5\x85\xa9\xe5\x80\x8b\xe5\xad\x97"));
    assert(!ValidLaunchArgument("line\nbreak"));
    assert(!ValidLaunchArgument(std::string(257U, 'a')));
    assert(!RenderWindowsArguments(std::vector<std::string>(33U, "x")));
    const std::vector<std::string> oversized{
        std::string(256U, 'a'), std::string(256U, 'b'), "c"};
    assert(!RenderWindowsArguments(oversized));
    assert(EscapeX64dbgCommandArgument("a\\b\"c") == "a\\\\b\\\"c");
    const auto command = BuildInitCommand("C:/a.exe", *rendered, "C:/work");
    assert(command && command->starts_with("scriptcmd init \"C:/a.exe\", \""));
    assert(command->size() < kX64dbgCommandBufferBytes);
    assert(!BuildInitCommand(std::string(kX64dbgCommandBufferBytes, 'x'), "",
                             "C:/work"));
}
