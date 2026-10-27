# Porquao Spoof

Hardware identity spoofer for Windows with three target profiles, a vulnerable-driver scanner, and a native Qt6 UI. Open source — the community owns it from here.

![platform](https://img.shields.io/badge/Windows-10%2F11-blue) ![build](https://img.shields.io/badge/C%2B%2B-20-orange)

## What it does

| Profile | Target | Anti-cheat | Method |
|---|---|---|---|
| **Vava Spoof** | Valorant | Vanguard | Boot-start kernel driver (Route A) or BYOVD runtime (Route B) |
| **Roblox Spoof** | Roblox | Hyperion | Session spoof — resets on reboot |
| **Mine Spoof** | Minecraft | — | Session spoof — resets on reboot |

Identity surfaces covered: motherboard/BIOS strings, MAC addresses, disk volume IDs and serials, EDID monitor identity, TPM presence, SMBIOS type-1 strings (kernel), disk DeviceExtension serials (kernel).

## Spoof semantics

**Roblox / Mine (session):** applied while toggled, lives until reboot. Registry identity writes are backed up on first run; a restore agent (`PQSpoofAgent`) can roll everything back on next logon.

**Valorant (boot):** Vanguard checks hardware identity from boot. Route A installs a boot-start driver (`spfs.sys`, group *Extended Base*) that patches identity before Vanguard loads. Route B loads a vulnerable vendor driver at runtime for arbitrary kernel r/w and patches identity live.

## Routes

### Route A — kernel driver (recommended for Valorant)
1. `build.bat` compiles `spfs.sys` (WDK required).
2. `pqspoof --install-boot` copies the driver and registers it boot-start in the *Extended Base* group — that group loads before Vanguard.
3. `bcdedit /set testsigning on` + reboot — test mode accepts the driver signature.
4. On every boot the driver spoofs before game launch.

### Route B — BYOVD (runtime, no reboot)
The engine scans for known-vulnerable signed drivers already on disk (`gdrv.sys`, `iqvw64e.sys`, `RTCore64.sys`, `Msio64.sys`, `AsrDrv103.sys`, `ene.sys`, `cpuz141.sys`, `WinIo64.sys`, `lha.sys` — table in `vuln_drivers.h`), loads the first match, and gets arbitrary kernel read/write through its ioctl. Kernel patches then run live: disk DeviceExtension serials and SMBIOS type-1 strings via `\Device\SmbiosData`.

Route B caveat: it cannot rewrite the full disk serial path on every setup without the handle-table trick — Route A is the complete path. When Vanguard is running, Route B first demotes it to demand-start (logged as a warning) — full bypass still requires boot mode + reboot.

## Build

Requirements: Visual Studio 2022 (C++), CMake+Ninja, Qt 6.8.2 (msvc2022_64 at `C:\Qt\6.8.2\msvc2022_64`), Windows Driver Kit for the kernel driver.

```bat
spoofer\build.bat
```

Produces:

| Artifact | Purpose |
|---|---|
| `build\pqspoof.exe` | CLI engine |
| `build\vulnscan.exe` | Standalone vulnerable-driver scanner |
| `build\PorquaoSpoof.exe` | Qt6 UI (Main tab + Logs tab) |
| `spfs.sys` | Boot-start kernel driver |

## UI

Two tabs:

- **Main** (crosshair icon) — three toggle cards (Vava / Roblox / Mine), `Spoof Now`, `Restore`.
- **Logs** (clock icon) — colored engine log (errors surface here) plus the vulnerable-driver scan table: FILE / VENDOR / CVE / VERSION / PRIMITIVE / STATUS, refreshed with `Run Scan`.

## CLI

```
pqspoof [--vava|--roblox|--mine|--all] [--route-a] [--vol] [--restore]
        [--restore-on-boot] [--install-boot] [--vanguard-boot]
vulnscan
```

- `--route-a` — install/run boot driver path for Valorant
- `--vol` — include disk volume ID spoofing (unmounts volumes briefly)
- `--restore` — restore original registry identity from backup
- `--restore-on-boot` — silent restore, used by the logon agent
- `--install-boot` — install Route A driver
- `--vanguard-boot` — move Vanguard to demand start (Route B prep)

## Scanner

`vulnscan` (or the Logs tab) walks `System32\drivers` + `DriverStore\FileRepository`, matches the vulnerable-driver table by name, hashes what it finds (SHA256), and lists currently loaded kernel modules. The hash column is informational — community can extend `vuln_drivers.h` with verified hashes per version.

## Repo layout

```
spoofer/
├─ engine.h / spoofer.cpp   engine (registry, MAC, EDID, volume, kernel routes)
├─ byovd.h / byovd.cpp      BYOVD loader + kernel r/w primitives
├─ vuln_drivers.h           vulnerable-driver database
├─ scanner.cpp              standalone scanner
├─ spfs.c                   Route A boot-start kernel driver
├─ cli.cpp                  CLI front
├─ ui/                      Qt6 UI (mainwindow, toggleswitch, icons painted in QPainter)
├─ build.bat                full build (user-mode + driver)
└─ CMakeLists.txt           user-mode targets
```

## Notes and limitations

- Route A needs `bcdedit /set testsigning on` and a reboot. Driver signing: test mode loads it unsigned.
- Route B loads vendor drivers with known CVEs — the same public technique used across the ecosystem. It demotes Vanguard to demand start but a reboot into Route A is still the reliable path for ranked.
- Session profiles reset on reboot by design; registry values restored via the logon agent or manual `--restore`.
- TPM spoof is implemented as tpm.sys start=4 (disabled). EK spoofing is out of scope.
- The engine refuses to run without an administrator token (fail-closed, `-100`).

## License

Use at your own risk. Fork it, extend it, fix it — the whole point of open source here is that Vanguard moves, and the community moves faster.
