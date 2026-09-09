@echo off
setlocal EnableExtensions

rem Keep localized MSVC /showIncludes machine-readable for CMake/Ninja. CMake
rem decodes the probe using the console code page; UTF-8 prevents a mojibake prefix.
chcp 65001 >nul

if /I "%~1"=="x64" (
  set "MCP_ARCH=x64"
) else if /I "%~1"=="x86" (
  set "MCP_ARCH=x86"
) else (
  echo Usage: scripts\build-plugin.cmd ^<x86^|x64^> [test]
  exit /b 2
)
set "MCP_BUILD_TESTING=OFF"
if /I "%~2"=="test" set "MCP_BUILD_TESTING=ON"

if not defined X64DBG_ROOT set "X64DBG_ROOT=C:\tools\x64dbg"
if not exist "%X64DBG_ROOT%\pluginsdk\_plugins.h" (
  echo X64DBG_ROOT does not contain pluginsdk: %X64DBG_ROOT%
  exit /b 2
)

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo vswhere.exe was not found. Install Visual Studio Build Tools.
  exit /b 2
)

for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%I"
if not defined VSINSTALL (
  echo Visual Studio with the x86/x64 C++ toolchain was not found.
  exit /b 2
)

rem Build the host server before selecting the native plugin's compiler architecture.
rem The helper emits only the current Cargo executable path on stdout, never a fallback.
set "MCP_TEST_SERVER="
if /I "%MCP_BUILD_TESTING%"=="ON" (
  for /f "usebackq delims=" %%I in (`powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-test-server.ps1"`) do set "MCP_TEST_SERVER=%%I"
)
if /I "%MCP_BUILD_TESTING%"=="ON" if not defined MCP_TEST_SERVER (
  echo Rust test server build or artifact discovery failed.
  exit /b 1
)

call "%VSINSTALL%\Common7\Tools\VsDevCmd.bat" -arch=%MCP_ARCH% -host_arch=x64 >nul
if errorlevel 1 exit /b 1

if /I "%MCP_BUILD_TESTING%"=="ON" (
  cmake --preset windows-%MCP_ARCH% --fresh -DBUILD_TESTING=ON "-DMCP_TEST_SERVER:FILEPATH=%MCP_TEST_SERVER%"
) else (
  cmake --preset windows-%MCP_ARCH% --fresh -DBUILD_TESTING=OFF
)
if errorlevel 1 exit /b 1

cmake --build --preset windows-%MCP_ARCH%-release
if errorlevel 1 exit /b 1
if /I not "%~2"=="test" exit /b 0
ctest --test-dir "build\windows-%MCP_ARCH%" --output-on-failure
if errorlevel 1 exit /b 1
exit /b 0
