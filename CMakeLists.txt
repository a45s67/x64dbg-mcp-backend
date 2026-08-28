cmake_minimum_required(VERSION 3.25)
project(x64dbg_mcp_backend VERSION 0.1.0 LANGUAGES CXX)
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
    plugin/src/debugger_executor.cpp
    plugin/src/runtime.cpp
  )
  target_compile_features(x64dbg_mcp_lifecycle_test PRIVATE cxx_std_20)
  target_include_directories(x64dbg_mcp_lifecycle_test PRIVATE plugin/src)
  target_include_directories(x64dbg_mcp_lifecycle_test SYSTEM PRIVATE "${X64DBG_ROOT}/pluginsdk")
  target_compile_definitions(x64dbg_mcp_lifecycle_test PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX MCP_LIFECYCLE_HARNESS)
  target_compile_options(x64dbg_mcp_lifecycle_test PRIVATE /W4 /WX /permissive- /EHsc)
  target_link_libraries(x64dbg_mcp_lifecycle_test PRIVATE bcrypt advapi32 ws2_32)

  add_executable(x64dbg_mcp_executor_test
    plugin/tests/executor_test.cpp
    plugin/src/debugger_executor.cpp
  )
  target_compile_features(x64dbg_mcp_executor_test PRIVATE cxx_std_20)
  target_include_directories(x64dbg_mcp_executor_test PRIVATE plugin/src)
  target_compile_definitions(x64dbg_mcp_executor_test PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(x64dbg_mcp_executor_test PRIVATE /W4 /WX /permissive- /EHsc)

  add_executable(x64dbg_mcp_debuggee_fixture WIN32
    plugin/tests/debuggee_fixture.cpp
  )
  target_compile_features(x64dbg_mcp_debuggee_fixture PRIVATE cxx_std_20)
  target_compile_definitions(x64dbg_mcp_debuggee_fixture PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(x64dbg_mcp_debuggee_fixture PRIVATE /W4 /WX /permissive- /EHsc)
endif()

add_library(x64dbg_mcp_plugin SHARED
  plugin/src/debugger_executor.cpp
  plugin/src/plugin.cpp
  plugin/src/runtime.cpp
)
target_compile_features(x64dbg_mcp_plugin PRIVATE cxx_std_20)
target_include_directories(x64dbg_mcp_plugin SYSTEM PRIVATE "${X64DBG_ROOT}/pluginsdk")
target_compile_definitions(x64dbg_mcp_plugin PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX
)
target_compile_options(x64dbg_mcp_plugin PRIVATE /W4 /WX /permissive- /EHsc)
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
  set_tests_properties(executor-${MCP_TEST_ARCH} lifecycle-${MCP_TEST_ARCH}
    sidecar-crash-${MCP_TEST_ARCH} installed-config-${MCP_TEST_ARCH}
    PROPERTIES TIMEOUT 15)
endif()
