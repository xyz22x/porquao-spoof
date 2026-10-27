@echo off
setlocal enabledelayedexpansion

rem === Porquao Spoof build ===
rem 1) vcvars (MSVC env)
rem 2) user-mode: cmake + ninja (pqspoof.exe, vulnscan.exe, PorquaoSpoof.exe)
rem 3) kernel driver: cl + link against WDK km libs (spfs.sys)

set QTDIR=C:\Qt\6.8.2\msvc2022_64
set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

call %VCVARS% >nul
if errorlevel 1 (
    echo [err] vcvars64.bat not found - install VS2022 with C++ tools
    exit /b 1
)

rem ---------- user-mode ----------
cmake -B build -G Ninja -DCMAKE_PREFIX_PATH=%QTDIR% -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 exit /b 1
cmake --build build
if errorlevel 1 exit /b 1

rem deploy Qt DLLs next to the exe so it runs standalone
C:\Qt\6.8.2\msvc2022_64\bin\windeployqt.exe --release --no-translations --no-opengl-sw --no-compiler-runtime build\PorquaoSpoof.exe >nul 2>&1

rem ---------- kernel driver (Route A) ----------
rem locate WDK: newest kit wins
set "KITINC="
for /d %%I in ("C:\Program Files (x86)\Windows Kits\10\Include\10.*") do set "KITINC=%%I"
if "%KITINC%"=="" (
    echo [warn] WDK not found - spfs.sys not built. Install the Windows Driver Kit, then re-run.
    echo [ok]   user-mode targets built: build\pqspoof.exe, build\vulnscan.exe, build\PorquaoSpoof.exe
    exit /b 0
)
set "KM="
set "KMLIBROOT="
for /d %%D in ("C:\Program Files (x86)\Windows Kits\10\lib\10.*") do set "KMLIBROOT=%%D"
call set "KM=%KMLIBROOT%\km\x64"
if not exist "%KM%\ntoskrnl.lib" (
    echo [warn] WDK km libs missing - install the WDK Driver Libraries
    exit /b 0
)

cl /nologo /kernel /W4 /GS- /O2 /Zp8 /c ^
   /I"%KITINC%\km\crt" /I"%KITINC%\shared" /I"%KITINC%\km" ^
   /D_AMD64_ /DAMD64 /D_WIN64 /DNTDDI_VERSION=0x0A00000C /D_WIN32_WINNT=0x0A00 ^
   spfs.c /Fospfs.obj
if errorlevel 1 exit /b 1

link /nologo /SUBSYSTEM:NATIVE /DRIVER /ENTRY:DriverEntry /OUT:spfs.sys ^
     spfs.obj "%KM%\ntoskrnl.lib" "%KM%\hal.lib" "%KM%\BufferOverflowK.lib"
if errorlevel 1 exit /b 1

echo.
echo [ok] build complete:
echo   build\pqspoof.exe      - CLI engine
echo   build\vulnscan.exe     - vulnerable-driver scanner
echo   build\PorquaoSpoof.exe - Qt UI (deployed, runs standalone)
echo   spfs.sys               - boot-start kernel driver
