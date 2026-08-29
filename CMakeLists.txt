cmake_minimum_required(VERSION 3.25)
project(x64dbg_mcp_backend VERSION 0.6.0 LANGUAGES CXX)
include(CTest)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(NOT WIN32)
  message(FATAL_ERROR "The x64dbg plugin is Windows-only")
endif()

set(X64DBG_ROOT "$ENV{X64DBG_ROOT}" CACHE PATH "Root of the pinned x64dbg SDK/release")
if(NOT EXISTS "${X64DBG_ROOT}/pluginsdk/_plugins.h")
  message(FATAL_ERROR "Set X64DBG_ROOT to an x64dbg distribution containing pluginsdk")
endif()

if(BUILD_TESTING)
  add_executable(x64dbg_mcp_lifecycle_test
    plugin/tests/lifecycle_harness.cpp
    plugin/src/command_fence.cpp
    plugin/src/debugger_executor.cpp
    plugin/src/memory_filters.cpp
    plugin/src/runtime.cpp
    plugin/src/utf8.cpp
  )
  target_compile_features(x64dbg_mcp_lifecycle_test PRIVATE cxx_std_20)
  target_include_directories(x64dbg_mcp_lifecycle_test PRIVATE plugin/src)
  target_include_directories(x64dbg_mcp_lifecycle_test SYSTEM PRIVATE "${X64DBG_ROOT}/pluginsdk")
  target_compile_definitions(x64dbg_mcp_lifecycle_test PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX MCP_LIFECYCLE_HARNESS)
  target_compile_options(x64dbg_mcp_lifecycle_test PRIVATE /W4 /WX /permissive- /EHsc /utf-8)
  target_link_libraries(x64dbg_mcp_lifecycle_test PRIVATE bcrypt advapi32 ws2_32)

  add_executable(x64dbg_mcp_executor_test
    plugin/tests/executor_test.cpp
    plugin/src/debugger_executor.cpp
  )
  target_compile_features(x64dbg_mcp_executor_test PRIVATE cxx_std_20)
  target_include_directories(x64dbg_mcp_executor_test PRIVATE plugin/src)
  target_compile_definitions(x64dbg_mcp_executor_test PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(x64dbg_mcp_executor_test PRIVATE /W4 /WX /permissive- /EHsc /utf-8)

  add_executable(x64dbg_mcp_command_fence_test
    plugin/tests/command_fence_test.cpp
    plugin/src/command_fence.cpp
  )
  target_compile_features(x64dbg_mcp_command_fence_test PRIVATE cxx_std_20)
  target_include_directories(x64dbg_mcp_command_fence_test PRIVATE plugin/src)
  target_compile_definitions(x64dbg_mcp_command_fence_test PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(x64dbg_mcp_command_fence_test PRIVATE
    /W4 /WX /permissive- /EHsc /utf-8)

  add_executable(x64dbg_mcp_debuggee_fixture WIN32
    plugin/tests/debuggee_fixture.cpp
  )
  target_compile_features(x64dbg_mcp_debuggee_fixture PRIVATE cxx_std_20)
  target_compile_definitions(x64dbg_mcp_debuggee_fixture PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(x64dbg_mcp_debuggee_fixture PRIVATE /W4 /WX /permissive- /EHsc /utf-8)

  add_executable(x64dbg_mcp_utf8_test
    plugin/tests/utf8_test.cpp
    plugin/src/utf8.cpp
  )
  target_compile_features(x64dbg_mcp_utf8_test PRIVATE cxx_std_20)
  target_include_directories(x64dbg_mcp_utf8_test PRIVATE plugin/src)
  target_compile_definitions(x64dbg_mcp_utf8_test PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(x64dbg_mcp_utf8_test PRIVATE /W4 /WX /permissive- /EHsc /utf-8)

  add_executable(x64dbg_mcp_memory_filters_test
    plugin/tests/memory_filters_test.cpp
    plugin/src/memory_filters.cpp
  )
  target_compile_features(x64dbg_mcp_memory_filters_test PRIVATE cxx_std_20)
  target_include_directories(x64dbg_mcp_memory_filters_test PRIVATE plugin/src)
  target_compile_definitions(x64dbg_mcp_memory_filters_test PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(x64dbg_mcp_memory_filters_test PRIVATE /W4 /WX /permissive- /EHsc /utf-8)

  add_executable(x64dbg_mcp_register_policy_test
    plugin/tests/register_policy_test.cpp
    plugin/src/register_policy.cpp
  )
  target_compile_features(x64dbg_mcp_register_policy_test PRIVATE cxx_std_20)
  target_include_directories(x64dbg_mcp_register_policy_test PRIVATE plugin/src)
  target_include_directories(x64dbg_mcp_register_policy_test SYSTEM PRIVATE "${X64DBG_ROOT}/pluginsdk")
  target_compile_definitions(x64dbg_mcp_register_policy_test PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(x64dbg_mcp_register_policy_test PRIVATE /W4 /WX /permissive- /EHsc /utf-8)

  add_executable(x64dbg_mcp_breakpoint_policy_test
    plugin/tests/breakpoint_policy_test.cpp
    plugin/src/breakpoint_policy.cpp
  )
  target_compile_features(x64dbg_mcp_breakpoint_policy_test PRIVATE cxx_std_20)
  target_include_directories(x64dbg_mcp_breakpoint_policy_test PRIVATE plugin/src)
  target_include_directories(x64dbg_mcp_breakpoint_policy_test SYSTEM PRIVATE "${X64DBG_ROOT}/pluginsdk")
  target_compile_definitions(x64dbg_mcp_breakpoint_policy_test PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(x64dbg_mcp_breakpoint_policy_test PRIVATE /W4 /WX /permissive- /EHsc /utf-8)
endif()

add_library(x64dbg_mcp_plugin SHARED
  plugin/src/breakpoint_policy.cpp
  plugin/src/command_fence.cpp
  plugin/src/debugger_executor.cpp
  plugin/src/memory_filters.cpp
  plugin/src/plugin.cpp
  plugin/src/register_policy.cpp
  plugin/src/runtime.cpp
  plugin/src/utf8.cpp
)
target_compile_features(x64dbg_mcp_plugin PRIVATE cxx_std_20)
target_include_directories(x64dbg_mcp_plugin SYSTEM PRIVATE "${X64DBG_ROOT}/pluginsdk")
target_compile_definitions(x64dbg_mcp_plugin PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX
)
target_compile_options(x64dbg_mcp_plugin PRIVATE /W4 /WX /permissive- /EHsc /utf-8)
target_link_options(x64dbg_mcp_plugin PRIVATE /Brepro)
target_link_libraries(x64dbg_mcp_plugin PRIVATE bcrypt advapi32)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(X64DBG_ARCH_DIR "x64")
  set(JANSSON_IMPORT_LIB "${X64DBG_ROOT}/pluginsdk/jansson/jansson_x64.lib")
  target_link_libraries(x64dbg_mcp_plugin PRIVATE
    "${X64DBG_ROOT}/pluginsdk/x64dbg.lib"
    "${X64DBG_ROOT}/pluginsdk/x64bridge.lib"
  )
  set_target_properties(x64dbg_mcp_plugin PROPERTIES OUTPUT_NAME "x64dbg-mcp-backend" SUFFIX ".dp64")
else()
  set(X64DBG_ARCH_DIR "x32")
  set(JANSSON_IMPORT_LIB "${X64DBG_ROOT}/pluginsdk/jansson/jansson_x86.lib")
  target_link_libraries(x64dbg_mcp_plugin PRIVATE
    "${X64DBG_ROOT}/pluginsdk/x32dbg.lib"
    "${X64DBG_ROOT}/pluginsdk/x32bridge.lib"
  )
  set_target_properties(x64dbg_mcp_plugin PROPERTIES OUTPUT_NAME "x64dbg-mcp-backend" SUFFIX ".dp32")
endif()

target_link_libraries(x64dbg_mcp_plugin PRIVATE "${JANSSON_IMPORT_LIB}")
if(BUILD_TESTING)
  target_link_libraries(x64dbg_mcp_lifecycle_test PRIVATE "${JANSSON_IMPORT_LIB}")
  add_custom_command(TARGET x64dbg_mcp_lifecycle_test POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      "${X64DBG_ROOT}/release/${X64DBG_ARCH_DIR}/jansson.dll"
      "$<TARGET_FILE_DIR:x64dbg_mcp_lifecycle_test>/jansson.dll")
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(MCP_TEST_ARCH x64)
    set(MCP_TEST_PORT 43864)
  else()
    set(MCP_TEST_ARCH x32)
    set(MCP_TEST_PORT 43832)
  endif()
  add_test(NAME executor-${MCP_TEST_ARCH} COMMAND x64dbg_mcp_executor_test)
  add_test(NAME command-fence-${MCP_TEST_ARCH} COMMAND x64dbg_mcp_command_fence_test)
  add_test(NAME utf8-${MCP_TEST_ARCH} COMMAND x64dbg_mcp_utf8_test)
  add_test(NAME memory-filters-${MCP_TEST_ARCH} COMMAND x64dbg_mcp_memory_filters_test)
  add_test(NAME register-policy-${MCP_TEST_ARCH} COMMAND x64dbg_mcp_register_policy_test)
  add_test(NAME breakpoint-policy-${MCP_TEST_ARCH} COMMAND x64dbg_mcp_breakpoint_policy_test)
  add_test(NAME lifecycle-${MCP_TEST_ARCH}
    COMMAND x64dbg_mcp_lifecycle_test
      "${CMAKE_SOURCE_DIR}/target/release/x64dbg-mcp-server.exe" "${MCP_TEST_PORT}")
  math(EXPR MCP_CRASH_TEST_PORT "${MCP_TEST_PORT} + 1")
  add_test(NAME sidecar-crash-${MCP_TEST_ARCH}
    COMMAND x64dbg_mcp_lifecycle_test
      "${CMAKE_SOURCE_DIR}/target/release/x64dbg-mcp-server.exe" "${MCP_CRASH_TEST_PORT}"
      sidecar-crash)
  math(EXPR MCP_INSTALLED_CONFIG_TEST_PORT "${MCP_TEST_PORT} + 2")
  add_test(NAME installed-config-${MCP_TEST_ARCH}
    COMMAND x64dbg_mcp_lifecycle_test
      "${CMAKE_SOURCE_DIR}/target/release/x64dbg-mcp-server.exe"
      "${MCP_INSTALLED_CONFIG_TEST_PORT}" installed-config)
  math(EXPR MCP_ACTIVE_WAIT_TEST_PORT "${MCP_TEST_PORT} + 3")
  add_test(NAME active-wait-shutdown-${MCP_TEST_ARCH}
    COMMAND x64dbg_mcp_lifecycle_test
      "${CMAKE_SOURCE_DIR}/target/release/x64dbg-mcp-server.exe"
      "${MCP_ACTIVE_WAIT_TEST_PORT}" active-wait-shutdown)
  set_tests_properties(executor-${MCP_TEST_ARCH} command-fence-${MCP_TEST_ARCH}
    utf8-${MCP_TEST_ARCH}
    memory-filters-${MCP_TEST_ARCH} register-policy-${MCP_TEST_ARCH}
    breakpoint-policy-${MCP_TEST_ARCH}
    lifecycle-${MCP_TEST_ARCH}
    sidecar-crash-${MCP_TEST_ARCH} installed-config-${MCP_TEST_ARCH}
    active-wait-shutdown-${MCP_TEST_ARCH}
    PROPERTIES TIMEOUT 15)
endif()
