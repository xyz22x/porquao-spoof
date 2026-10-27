// engine.h — Porquao Spoof engine API
#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace engine {

enum Profiles : uint32_t {
    VAVA   = 1,   // Valorant (Vanguard)
    ROBLOX = 2,   // Roblox (Hyperion)
    MINE   = 4,   // Minecraft
    ALL    = 7,
};

using LogFn = void (*)(const char* level, const char* msg);

// Install a log sink; level: "info" "ok" "warn" "err"
void SetLog(LogFn fn);

// Spoof caller:
//   mask          — bitfield of Profiles
//   routeA        — true: boot driver (needs testsigning), false: BYOVD runtime
//   doVolumes     — rewrite NTFS/FAT volume serials (dismounts volumes briefly)
// Returns 0 on success, engine log carries details.
int Spoof(uint32_t mask, bool routeA, bool doVolumes);

// Restore originals captured at first run.
int Restore();

// Silent restore — called by the auto-start agent on logon (RestoreOnBoot flag).
int RestoreOnBootSilent();

// Route A service install: registers kernel driver as boot-start (Group "Extended Base").
int InstallBootDriver();

// Vanguard boot mode toggle: true=boot-start, false=demand-start (Route B requirement).
int SetVanguardBoot(bool boot);

// Run the vulnerable-driver scanner and return report text (also used by UI "Refresh").
std::string ScanVulnerableDrivers();

// Structured scan for the Logs tab: name/vendor/cve/version/primitive/present.
struct ScanRow {
    std::string name;
    std::string vendor;
    std::string cve;
    std::string version;
    std::string prim;
    bool present = false;
};
std::vector<ScanRow> ScanStructured();

} // namespace engine
