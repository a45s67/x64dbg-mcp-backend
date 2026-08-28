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
  echo Usage: scripts\build-plugin.cmd ^<x86^|x64^>
  exit /b 2
)

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

for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products Microsoft.VisualStudio.Product.BuildTools -property installationPath`) do set "VSINSTALL=%%I"
if not defined VSINSTALL (
  echo Visual Studio Build Tools was not found.
  exit /b 2
)

call "%VSINSTALL%\Common7\Tools\VsDevCmd.bat" -arch=%MCP_ARCH% -host_arch=x64 >nul
if errorlevel 1 exit /b %errorlevel%

cmake --preset windows-%MCP_ARCH% --fresh
if errorlevel 1 exit /b %errorlevel%

cmake --build --preset windows-%MCP_ARCH%-release
if errorlevel 1 exit /b %errorlevel%
if /I "%~2"=="test" (
  ctest --test-dir "build\windows-%MCP_ARCH%" --output-on-failure
  exit /b %errorlevel%
)
exit /b 0
