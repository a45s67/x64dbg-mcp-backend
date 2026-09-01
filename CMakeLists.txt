cmake_minimum_required(VERSION 3.25)
project(x64dbg_mcp_backend VERSION 0.1.1 LANGUAGES CXX)
include(CTest)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(NOT WIN32)
  message(FATAL_ERROR "The x64dbg plugin is Windows-only")
endif()

# One architecture-neutral host controller is shipped with the x64 build and
# manages either x32dbg or x64dbg by exact installed path.
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  add_executable(x96dbg_mcp_control
    controller/src/main.cpp
    controller/src/control_policy.cpp
  )
  target_compile_features(x96dbg_mcp_control PRIVATE cxx_std_20)
  target_include_directories(x96dbg_mcp_control PRIVATE controller/src)
  target_compile_definitions(x96dbg_mcp_control PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(x96dbg_mcp_control PRIVATE /W4 /WX /permissive- /EHsc /utf-8)
  target_link_options(x96dbg_mcp_control PRIVATE /Brepro)
  target_link_libraries(x96dbg_mcp_control PRIVATE winhttp user32)
  set_target_properties(x96dbg_mcp_control PROPERTIES OUTPUT_NAME "x96dbg-mcp-control")
endif()

set(X64DBG_ROOT "$ENV{X64DBG_ROOT}" CACHE PATH "Root of the pinned x64dbg SDK/release")
if(NOT EXISTS "${X64DBG_ROOT}/pluginsdk/_plugins.h")
  message(FATAL_ERROR "Set X64DBG_ROOT to an x64dbg distribution containing pluginsdk")
endif()

if(BUILD_TESTING)
  add_executable(x64dbg_mcp_control_policy_test
    controller/tests/control_policy_test.cpp
    controller/src/control_policy.cpp
  )
  target_compile_features(x64dbg_mcp_control_policy_test PRIVATE cxx_std_20)
  target_include_directories(x64dbg_mcp_control_policy_test PRIVATE controller/src)
  target_compile_options(x64dbg_mcp_control_policy_test PRIVATE
    /W4 /WX /permissive- /EHsc /utf-8 /UNDEBUG)

  add_executable(x64dbg_mcp_lifecycle_test
    controller/src/control_policy.cpp
    plugin/tests/lifecycle_harness.cpp
    plugin/src/breakpoint_policy.cpp
    plugin/src/command_fence.cpp
    plugin/src/debugger_executor.cpp
    plugin/src/memory_filters.cpp
    plugin/src/launch_arguments.cpp
    plugin/src/patch_policy.cpp
    plugin/src/memory_search.cpp
    plugin/src/pe_policy.cpp
    plugin/src/trace_policy.cpp
    plugin/src/runtime.cpp
    plugin/src/utf8.cpp
  )
  target_compile_features(x64dbg_mcp_lifecycle_test PRIVATE cxx_std_20)
  target_include_directories(x64dbg_mcp_lifecycle_test PRIVATE plugin/src controller/src)
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
  target_link_libraries(x64dbg_mcp_debuggee_fixture PRIVATE shell32)

  add_library(x64dbg_mcp_debuggee_dll_fixture SHARED
    plugin/tests/debuggee_dll_fixture.cpp
  )
  target_compile_features(x64dbg_mcp_debuggee_dll_fixture PRIVATE cxx_std_20)
  target_compile_definitions(x64dbg_mcp_debuggee_dll_fixture PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(x64dbg_mcp_debuggee_dll_fixture PRIVATE
    /W4 /WX /permissive- /EHsc /utf-8)
  set_target_properties(x64dbg_mcp_debuggee_dll_fixture PROPERTIES
    OUTPUT_NAME "mcp-debuggee-dll-fixture")

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

  add_executable(x64dbg_mcp_memory_search_test
    plugin/tests/memory_search_test.cpp
    plugin/src/memory_search.cpp
  )
  target_compile_features(x64dbg_mcp_memory_search_test PRIVATE cxx_std_20)
  target_include_directories(x64dbg_mcp_memory_search_test PRIVATE plugin/src)
  target_compile_definitions(x64dbg_mcp_memory_search_test PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(x64dbg_mcp_memory_search_test PRIVATE /W4 /WX /permissive- /EHsc /utf-8)

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

  add_executable(x64dbg_mcp_pe_policy_test
    plugin/tests/pe_policy_test.cpp
    plugin/src/pe_policy.cpp
  )
  target_compile_features(x64dbg_mcp_pe_policy_test PRIVATE cxx_std_20)
  target_include_directories(x64dbg_mcp_pe_policy_test PRIVATE plugin/src)
  target_compile_definitions(x64dbg_mcp_pe_policy_test PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(x64dbg_mcp_pe_policy_test PRIVATE
    /W4 /WX /permissive- /EHsc /utf-8)

  add_executable(x64dbg_mcp_trace_policy_test
    plugin/tests/trace_policy_test.cpp
    plugin/src/trace_policy.cpp
  )
  target_compile_features(x64dbg_mcp_trace_policy_test PRIVATE cxx_std_20)
  target_include_directories(x64dbg_mcp_trace_policy_test PRIVATE plugin/src)
  target_compile_definitions(x64dbg_mcp_trace_policy_test PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(x64dbg_mcp_trace_policy_test PRIVATE
    /W4 /WX /permissive- /EHsc /utf-8)

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

  add_executable(x64dbg_mcp_patch_policy_test
    plugin/tests/patch_policy_test.cpp
    plugin/src/patch_policy.cpp
  )
  target_compile_features(x64dbg_mcp_patch_policy_test PRIVATE cxx_std_20)
  target_include_directories(x64dbg_mcp_patch_policy_test PRIVATE plugin/src)
  target_include_directories(x64dbg_mcp_patch_policy_test SYSTEM PRIVATE "${X64DBG_ROOT}/pluginsdk")
  target_compile_definitions(x64dbg_mcp_patch_policy_test PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(x64dbg_mcp_patch_policy_test PRIVATE /W4 /WX /permissive- /EHsc /utf-8)

  add_executable(x64dbg_mcp_launch_arguments_test
    plugin/tests/launch_arguments_test.cpp
    plugin/src/launch_arguments.cpp
  )
  target_compile_features(x64dbg_mcp_launch_arguments_test PRIVATE cxx_std_20)
  target_include_directories(x64dbg_mcp_launch_arguments_test PRIVATE plugin/src)
  target_compile_definitions(x64dbg_mcp_launch_arguments_test PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(x64dbg_mcp_launch_arguments_test PRIVATE
    /W4 /WX /permissive- /EHsc /utf-8)

  # CMake's Release flags define NDEBUG. These native tests intentionally use
  # assert for compact policy checks, so keep assertions active in every test
  # configuration rather than producing successful no-op executables.
  foreach(MCP_ASSERT_TEST
      x64dbg_mcp_executor_test
      x64dbg_mcp_command_fence_test
      x64dbg_mcp_utf8_test
      x64dbg_mcp_memory_filters_test
      x64dbg_mcp_memory_search_test
      x64dbg_mcp_register_policy_test
      x64dbg_mcp_pe_policy_test
      x64dbg_mcp_trace_policy_test
      x64dbg_mcp_breakpoint_policy_test
      x64dbg_mcp_patch_policy_test)
    target_compile_options(${MCP_ASSERT_TEST} PRIVATE /UNDEBUG)
  endforeach()
  target_compile_options(x64dbg_mcp_launch_arguments_test PRIVATE /UNDEBUG)
endif()

add_library(x64dbg_mcp_plugin SHARED
  controller/src/control_policy.cpp
  plugin/src/breakpoint_policy.cpp
  plugin/src/command_fence.cpp
  plugin/src/debugger_executor.cpp
  plugin/src/memory_filters.cpp
  plugin/src/memory_search.cpp
  plugin/src/launch_arguments.cpp
  plugin/src/patch_policy.cpp
  plugin/src/pe_policy.cpp
  plugin/src/trace_policy.cpp
  plugin/src/plugin.cpp
  plugin/src/register_policy.cpp
  plugin/src/runtime.cpp
  plugin/src/utf8.cpp
)
target_compile_features(x64dbg_mcp_plugin PRIVATE cxx_std_20)
target_include_directories(x64dbg_mcp_plugin PRIVATE controller/src)
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
  add_test(NAME memory-search-${MCP_TEST_ARCH} COMMAND x64dbg_mcp_memory_search_test)
  add_test(NAME register-policy-${MCP_TEST_ARCH} COMMAND x64dbg_mcp_register_policy_test)
  add_test(NAME pe-policy-${MCP_TEST_ARCH} COMMAND x64dbg_mcp_pe_policy_test)
  add_test(NAME trace-policy-${MCP_TEST_ARCH} COMMAND x64dbg_mcp_trace_policy_test)
  add_test(NAME breakpoint-policy-${MCP_TEST_ARCH} COMMAND x64dbg_mcp_breakpoint_policy_test)
  add_test(NAME patch-policy-${MCP_TEST_ARCH} COMMAND x64dbg_mcp_patch_policy_test)
  add_test(NAME launch-arguments-${MCP_TEST_ARCH} COMMAND x64dbg_mcp_launch_arguments_test)
  add_test(NAME control-policy-${MCP_TEST_ARCH} COMMAND x64dbg_mcp_control_policy_test)
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
  math(EXPR MCP_ACTIVE_TRACE_TEST_PORT "${MCP_TEST_PORT} + 4")
  add_test(NAME active-trace-shutdown-${MCP_TEST_ARCH}
    COMMAND x64dbg_mcp_lifecycle_test
      "${CMAKE_SOURCE_DIR}/target/release/x64dbg-mcp-server.exe"
      "${MCP_ACTIVE_TRACE_TEST_PORT}" active-trace-shutdown)
  set_tests_properties(executor-${MCP_TEST_ARCH} command-fence-${MCP_TEST_ARCH}
    utf8-${MCP_TEST_ARCH}
    memory-filters-${MCP_TEST_ARCH} memory-search-${MCP_TEST_ARCH}
    register-policy-${MCP_TEST_ARCH}
    pe-policy-${MCP_TEST_ARCH}
    breakpoint-policy-${MCP_TEST_ARCH}
    patch-policy-${MCP_TEST_ARCH}
    launch-arguments-${MCP_TEST_ARCH}
    control-policy-${MCP_TEST_ARCH}
    lifecycle-${MCP_TEST_ARCH}
    sidecar-crash-${MCP_TEST_ARCH} installed-config-${MCP_TEST_ARCH}
    active-wait-shutdown-${MCP_TEST_ARCH} active-trace-shutdown-${MCP_TEST_ARCH}
    PROPERTIES TIMEOUT 15)
endif()
