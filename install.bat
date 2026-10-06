@echo off
setlocal EnableExtensions

rem ------------------------------------------------------------------
rem  install.bat - Windows installer for Volley
rem
rem  Builds and installs Volley from cmd.exe:
rem    1. locates a POSIX build environment (MSYS2 first, then WSL)
rem    2. checks that the required packages are present and installs
rem       them when they are missing (MSYS2 pacman / WSL apt)
rem    3. runs ./configure, make, and make install via install.sh
rem
rem  usage:
rem    install.bat [/prefix=DIR] [/jobs=N] [/check] [/y] [/no-deps]
rem                [/deps-only] [/build-only] [/clean] [/uninstall]
rem                [/addpath] [/msys2=DIR] [/wsl] [/?]
rem
rem  examples:
rem    install.bat                         build + install to /usr/local
rem    install.bat /y /check               also run the test suite
rem    install.bat /prefix=C:\volley       install under C:\volley
rem    install.bat /uninstall              remove what was installed
rem ------------------------------------------------------------------

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "PREFIX="
set "JOBS="
set "OPTS="
set "MSYS2DIR="
set "FORCE_WSL="
set "ADDPATH="

:parse
if "%~1"=="" goto parsed

if /i "%~1"=="/?"         goto help
if /i "%~1"=="/help"      goto help
if /i "%~1"=="-h"         goto help
if /i "%~1"=="--help"     goto help

if /i "%~1"=="/check"     (set "OPTS=%OPTS% --check"     & shift & goto parse)
if /i "%~1"=="/y"         (set "VL_YES=1"                & shift & goto parse)
if /i "%~1"=="/yes"       (set "VL_YES=1"                & shift & goto parse)
if /i "%~1"=="/no-deps"   (set "VL_NO_DEPS=1"            & shift & goto parse)
if /i "%~1"=="/deps-only" (set "OPTS=%OPTS% --deps-only" & shift & goto parse)
if /i "%~1"=="/build-only" (set "OPTS=%OPTS% --build-only" & shift & goto parse)
if /i "%~1"=="/clean"     (set "OPTS=%OPTS% --clean"     & shift & goto parse)
if /i "%~1"=="/uninstall" (set "OPTS=%OPTS% --uninstall" & shift & goto parse)
if /i "%~1"=="/addpath"   (set "ADDPATH=1"               & shift & goto parse)
if /i "%~1"=="/wsl"       (set "FORCE_WSL=1"             & shift & goto parse)

set "KEY="
set "VAL="
for /f "tokens=1,* delims==" %%a in ("%~1") do (
  set "KEY=%%a"
  set "VAL=%%b"
)
if /i "%KEY%"=="/prefix" (set "PREFIX=%VAL%" & shift & goto parse)
if /i "%KEY%"=="/jobs"   (set "JOBS=%VAL%"   & shift & goto parse)
if /i "%KEY%"=="/msys2"  (set "MSYS2DIR=%VAL%" & shift & goto parse)

echo install.bat: unknown option: %~1
echo               run "install.bat /?" for help
exit /b 2

:parsed

if defined PREFIX set "VL_PREFIX=%PREFIX%"
if defined JOBS   set "VL_JOBS=%JOBS%"

rem ------------------------------------------------------------------
rem  locate the source tree
rem ------------------------------------------------------------------
if not exist "%ROOT%\configure" (
  echo install.bat: "%ROOT%" is not a Volley source tree ^(no configure^)
  exit /b 1
)
if not exist "%ROOT%\Makefile" (
  echo install.bat: "%ROOT%" is not a Volley source tree ^(no Makefile^)
  exit /b 1
)
pushd "%ROOT%" >nul || (
  echo install.bat: cannot enter "%ROOT%"
  exit /b 1
)

echo _   _       _ _
echo ^| ^| ^| ^|     ^| ^| ^|
echo ^| ^| ^| ^| ___ ^| ^| ^| ___ _   _
echo ^| ^| ^| ^|/ _ \^| ^| ^|/ _ \ ^| ^| ^|
echo \ \_/ / (_) ^| ^| ^|  __/ ^|_^|_ ^|
echo  \___/ \___/^|_^|_^|\___|\__, ^|
echo                       __/ ^|
echo                      ^|___/
echo.
echo volley installer for Windows
echo   source   %ROOT%

rem ------------------------------------------------------------------
rem  1. find a build environment
rem ------------------------------------------------------------------
set "BASH="
set "KIND="

rem --- MSYS2 root given explicitly
if defined MSYS2DIR if exist "%MSYS2DIR%\usr\bin\bash.exe" (
  set "BASH=%MSYS2DIR%\usr\bin\bash.exe"
  set "KIND=msys2"
)

rem --- already running inside MSYS2
if not defined KIND if defined MSYSTEM (
  where pacman.exe >nul 2>&1
  if not errorlevel 1 for /f "delims=" %%i in ('where bash.exe 2^>nul') do (
    if not defined BASH (set "BASH=%%i" & set "KIND=msys2")
  )
)

rem --- well-known MSYS2 install locations
if not defined KIND (
  for %%D in (
    "%SystemDrive%\msys64"
    "%SystemDrive%\msys32"
    "%ProgramFiles%\msys64"
    "%ProgramFiles(x86)%\msys64"
    "%LOCALAPPDATA%\Programs\msys64"
    "C:\msys64"
    "D:\msys64"
  ) do (
    if exist "%%~D\usr\bin\bash.exe" if not defined BASH (
      set "BASH=%%~D\usr\bin\bash.exe"
      set "KIND=msys2"
    )
  )
)

rem --- whatever bash.exe is on PATH (classifies MSYS2 vs Git Bash)
if not defined KIND (
  for /f "delims=" %%i in ('where bash.exe 2^>nul') do call :trybash "%%i"
)

rem --- WSL as a fallback
if not defined KIND if not defined FORCE_WSL (
  wsl.exe --status >nul 2>&1
  if not errorlevel 1 set "KIND=wsl"
)
if defined FORCE_WSL set "KIND=wsl"

if not defined KIND goto needenv

if /i "%KIND%"=="gitbash" goto needenv

rem ------------------------------------------------------------------
rem  2. report the environment
rem ------------------------------------------------------------------
if /i "%KIND%"=="msys2" (
  echo   msys2    %BASH%
) else (
  echo   wsl      Windows Subsystem for Linux
)
echo.

rem ------------------------------------------------------------------
rem  3. run the shared installer (deps -> configure -> make -> install)
rem ------------------------------------------------------------------
if /i "%KIND%"=="msys2" goto run_msys2
if /i "%KIND%"=="wsl"   goto run_wsl
goto needenv

:run_msys2
rem work out C:\msys64 from C:\msys64\usr\bin\bash.exe for the PATH hint
set "BASHDIR="
for %%i in ("%BASH%") do set "BASHDIR=%%~dpi"
set "MSYSROOT=%BASHDIR:\usr\bin\=%"
set "MSYSTEM=MINGW64"
echo == configure, make and install via install.sh ==
"%BASH%" -lc "sh ./install.sh%OPTS%"
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" goto failed

rem Windows folder that now holds volley.exe
set "PFXARG=%PREFIX%"
if not defined PFXARG set "PFXARG=/usr/local"
set "WINBIN=%PFXARG%\bin"
if not "%PFXARG:~0,1%"=="/" goto winbin_ok
set "SUB=%PFXARG:~1%"
set "SUB=%SUB:/=\%"
set "WINBIN=%MSYSROOT%%SUB%\bin"
:winbin_ok
echo.
echo   installed to  %WINBIN%
if defined ADDPATH call :addpath "%WINBIN%"
if not defined ADDPATH if not defined PREFIX (
  echo   to use it from cmd.exe, add that folder to PATH:
  echo     setx PATH "%%PATH%%;%WINBIN%"
)
goto done

:run_wsl
echo == configure, make and install via WSL ==
wsl.exe bash -lc "sh ./install.sh%OPTS%"
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" goto failed
echo.
echo   installed inside WSL to /usr/local/bin
goto done

rem ------------------------------------------------------------------
rem  no usable environment
rem ------------------------------------------------------------------
:needenv
echo.
if /i "%KIND%"=="gitbash" (
  echo   Git Bash was found, but it ships no compiler and no OpenSSL
  echo   headers, so it cannot build Volley.
) else (
  echo   no usable build environment was found.
)
echo.
echo   Volley on Windows needs either MSYS2 ^(recommended^) or WSL:
echo.
echo     winget install --id MSYS2.MSYS2 -e
echo     wsl --install
echo.
echo   Then re-run this script, or from an MSYS2 shell:
echo     pacman -S --needed base-devel mingw-w64-x86_64-toolchain
echo     pacman -S mingw-w64-x86_64-openssl mingw-w64-x86_64-zlib
echo     sh ./install.sh

where winget.exe >nul 2>&1
if errorlevel 1 goto failed
if not defined VL_YES (
  echo.
  set "GO="
  set /p "GO=install MSYS2 now with winget? [y/N] "
)
if defined GO if /i not "%GO%"=="y" goto failed
if not defined VL_YES if not defined GO goto failed
echo.
echo == installing MSYS2 with winget ==
winget install --id MSYS2.MSYS2 -e --accept-package-agreements --accept-source-agreements
if errorlevel 1 (
  echo install.bat: winget could not install MSYS2
  goto failed
)
echo MSYS2 installed; re-run install.bat
goto done

rem ------------------------------------------------------------------
:trybash
if defined BASH exit /b 0
set "TB=%~1"
for %%i in ("%TB%") do set "TBDIR=%%~dpi"
if exist "%TBDIR%pacman.exe" (
  set "BASH=%TB%"
  set "KIND=msys2"
  exit /b 0
)
set "BASH=%TB%"
set "KIND=gitbash"
exit /b 0

:addpath
set "NEWPATH=%~1"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$b=[Environment]::GetEnvironmentVariable('Path','User');" ^
  "if(-not $b){$b=''};" ^
  "$n=$env:NEWPATH;" ^
  "if(($b -split ';') -notcontains $n){" ^
  "[Environment]::SetEnvironmentVariable('Path',($b.TrimEnd(';')+';'+$n),'User');Write-Host '  added to user PATH'}" ^
  "else{Write-Host '  already on user PATH'}"
exit /b 0

:failed
popd
echo.
echo install.bat: installation did not complete
exit /b 1

:done
popd
echo.
echo done
exit /b 0

:help
echo.volley installer for Windows
echo.
echo usage: install.bat [/prefix=DIR] [/jobs=N] [/check] [/y] [/no-deps]
echo                    [/deps-only] [/build-only] [/clean] [/uninstall]
echo                    [/addpath] [/msys2=DIR] [/wsl] [/?]
echo.
echo   /prefix=DIR    install root, Windows or MSYS2 style
echo                  (default C:\msys64\usr\local)
echo   /jobs=N        parallel build jobs (default: all cores)
echo   /check         run the test suite before installing
echo   /y             answer yes to package installs without prompting
echo   /no-deps       report missing packages, never install them
echo   /deps-only     check/install dependencies and exit
echo   /build-only    compile but do not install
echo   /clean         remove previous build products first
echo   /uninstall     remove the installed files and exit
echo   /addpath       add the install folder to the user PATH
echo   /msys2=DIR     use this MSYS2 root (contains usr\bin\bash.exe)
echo   /wsl           build inside WSL instead of MSYS2
echo   /?             this help
exit /b 0
