# Builds the dftty protocol unit test with the NDK and runs it on Android.
#
# The daemon under test (dftty.c) is plain fork/exec/pipe code and needs no
# root and no vulnerable kernel, so any device or a stock emulator works.
# Running it on Android uses bionic - the same libc as the real device - so
# the fork/pipe/waitpid semantics match production exactly.
#
# Examples:
#   # use whatever adb target is connected (builds x86_64 by default)
#   powershell -ExecutionPolicy Bypass -File app\src\main\jni\tests\run_dftty_test.ps1
#
#   # boot the AVD headless first, then run
#   ... -File app\src\main\jni\tests\run_dftty_test.ps1 -BootAvd
#
#   # run on an arm64 phone
#   ... -File app\src\main\jni\tests\run_dftty_test.ps1 -Abi arm64-v8a
param(
    [string]$Abi = "x86_64",
    [string]$Api = "32",
    [string]$Ndk = "D:\AndroidStudio\Sdk\ndk\27.2.12479018",
    [string]$Sdk = "D:\AndroidStudio\Sdk",
    [string]$Serial = "",
    [switch]$BootAvd,
    [string]$Avd = "Medium_Phone_API_36.1"
)

$ErrorActionPreference = "Stop"

$triple = switch ($Abi) {
    "x86_64"    { "x86_64-linux-android$Api" }
    "arm64-v8a" { "aarch64-linux-android$Api" }
    default      { throw "unsupported ABI: $Abi (use x86_64 or arm64-v8a)" }
}
$clang = Join-Path $Ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\$triple-clang.cmd"
if (-not (Test-Path $clang)) { throw "clang not found: $clang" }

$bin = Join-Path $PSScriptRoot "dftty_test"
Write-Host "== building ($Abi, API $Api) ==" -ForegroundColor Cyan
# max-page-size=16384: Android 16 images can use 16 KB pages, and a 4 KB
# aligned ELF is refused at load (SIGSEGV). Matches the app's own native
# targets in CMakeLists.txt.
& $clang -O2 -Wall -Wno-unused-function '-Wl,-z,max-page-size=16384' `
    -o $bin (Join-Path $PSScriptRoot "dftty_test.c")
if ($LASTEXITCODE -ne 0) { throw "compile failed" }

$adbArgs = @()
if ($Serial) { $adbArgs = @("-s", $Serial) }

$online = (& adb @adbArgs devices) -split "`n" | Where-Object { $_ -match "\sdevice$" }
if (-not $online) {
    if ($BootAvd) {
        $emu = Join-Path $Sdk "emulator\emulator.exe"
        Write-Host "== booting $Avd (headless) ==" -ForegroundColor Cyan
        Start-Process $emu -ArgumentList @(
            "-avd", $Avd, "-no-window", "-no-audio", "-no-boot-anim",
            "-no-snapshot", "-gpu", "swiftshader_indirect")
        & adb @adbArgs wait-for-device
        Write-Host "== waiting for boot ==" -ForegroundColor Cyan
        while (((& adb @adbArgs shell getprop sys.boot_completed) -replace "`r", "").Trim() -ne "1") {
            Start-Sleep -Seconds 3
        }
    } else {
        throw "no adb device. Connect one, or pass -BootAvd to start the emulator."
    }
}

Write-Host "== running on /data/local/tmp/dftty_test ==" -ForegroundColor Cyan
& adb @adbArgs push $bin /data/local/tmp/dftty_test | Out-Null
& adb @adbArgs shell chmod 755 /data/local/tmp/dftty_test
& adb @adbArgs shell /data/local/tmp/dftty_test
exit $LASTEXITCODE
