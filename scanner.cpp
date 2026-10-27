// scanner.cpp — standalone vulnerable-driver mapper for Win11 x64.
// Enumerates drivers on disk, hashes them, matches against the BYOVD DB,
// prints a full table: name, vendor, CVE, version, primitive, ioctl surface.
// Build: cl /std:c++20 /O2 /W4 /EHsc scanner.cpp /Fe:vulnscan.exe advapi32.lib
#include <windows.h>
#include <bcrypt.h>
#include <psapi.h>
#include <stdio.h>
#include <string>
#include <vector>
#include "vuln_drivers.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "version.lib")

// Hash a file with bcrypt (SHA256 + SHA1 + MD5 in one pass).
static bool HashFile(const std::wstring& path, std::string& sha256hex, std::string& sha1hex, std::string& md5hex) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    static const struct { LPCWSTR algid; std::string* out; DWORD len; } algs[] = {
        { BCRYPT_SHA256_ALGORITHM, &sha256hex, 32 },
        { BCRYPT_SHA1_ALGORITHM,   &sha1hex,   20 },
        { BCRYPT_MD5_ALGORITHM,    &md5hex,    16 },
    };

    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    std::vector<BYTE> buf((size_t)sz.QuadPart);
    DWORD rd = 0;
    if (!ReadFile(h, buf.data(), (DWORD)buf.size(), &rd, nullptr) || rd != buf.size()) { CloseHandle(h); return false; }
    CloseHandle(h);

    BCRYPT_ALG_HANDLE alg = nullptr;
    for (auto& a : algs) {
        if (BCryptOpenAlgorithmProvider(&alg, a.algid, nullptr, 0) != 0) return false;
        DWORD objlen = 0, cb = 0;
        BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objlen, sizeof(objlen), &cb, 0);
        std::vector<BYTE> obj(objlen);
        BCRYPT_HASH_HANDLE hh = nullptr;
        if (BCryptCreateHash(alg, &hh, obj.data(), objlen, nullptr, 0, 0) != 0) {
            BCryptCloseAlgorithmProvider(alg, 0); return false;
        }
        BCryptHashData(hh, buf.data(), (ULONG)buf.size(), 0);
        std::vector<BYTE> digest(a.len);
        BCryptFinishHash(hh, digest.data(), a.len, 0);
        BCryptDestroyHash(hh);
        BCryptCloseAlgorithmProvider(alg, 0);
        char tmp[4] = {};
        for (BYTE b : digest) { sprintf_s(tmp, "%02x", b); *a.out += tmp; }
    }
    return true;
}

// Read FileVersion from the version resource.
static std::wstring GetFileVersion(const std::wstring& path) {
    DWORD handle = 0;
    DWORD sz = GetFileVersionInfoSizeW(path.c_str(), &handle);
    if (!sz) return L"";
    std::vector<BYTE> data(sz);
    if (!GetFileVersionInfoW(path.c_str(), 0, sz, data.data())) return L"";
    wchar_t* ver = nullptr; UINT len = 0;
    if (!VerQueryValueW(data.data(), L"\\StringFileInfo\\040904B0\\FileVersion", (LPVOID*)&ver, &len) &&
        !VerQueryValueW(data.data(), L"\\StringFileInfo\\040904E4\\FileVersion", (LPVOID*)&ver, &len))
        return L"";
    return ver ? ver : L"";
}

static void PrintTable(const std::vector<const VulnDriverEntry*>& found,
                       const std::vector<std::wstring>& paths,
                       const std::vector<std::wstring>& versions) {
    printf("\n=== Vulnerable signed drivers found on disk ===\n");
    printf("%-20s %-12s %-16s %-10s %-12s %-14s %s\n",
           "FILE", "VENDOR", "CVE", "VERSION", "PRIMITIVE", "IOCTL_RW", "HEX(SHA256[:16])");
    printf("-------------------------------------------------------------------------------------------\n");
    for (size_t i = 0; i < found.size(); ++i) {
        const VulnDriverEntry* e = found[i];
        const char* prim = "NONE";
        switch (e->prim) {
            case PRIM::ARB_RW:       prim = "ARB_RW"; break;
            case PRIM::ARB_PHYS_MAP: prim = "PHYS_MAP"; break;
            case PRIM::ARB_ALLOC:    prim = "ARB_ALLOC"; break;
            case PRIM::ARB_EXEC:     prim = "ARB_EXEC"; break;
            case PRIM::MSR_RW:       prim = "MSR_RW"; break;
            case PRIM::IO_RW:        prim = "IO_RW"; break;
            default: break;
        }
        printf("%-20ws %-12hs %-16hs %-10ws %-12hs 0x%08X   %.16s\n",
               paths[i].c_str(), e->vendor, e->cve, versions[i].c_str(), prim, e->ioctl_rw, e->sha256);
        printf("    desc: %hs\n", e->ioctl_desc);
        if (e->ioctl_alloc) printf("    alloc: 0x%08X\n", e->ioctl_alloc);
        if (e->ioctl_exec)  printf("    exec:  0x%08X\n", e->ioctl_exec);
    }
    if (found.empty()) printf("  (none matched)\n");
}

// Also print currently loaded kernel modules with base + size (helps find inline targets).
// NtQuerySystemInformation(SystemModuleInformation) — works without admin, no psapi quirks.
static void PrintLoadedKernelModules() {
    struct RTL_PROCESS_MODULE_INFORMATION {
        HANDLE Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize;
        ULONG Flags; USHORT LoadOrderIndex; USHORT InitOrderIndex; USHORT LoadCount; USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    };
    struct RTL_PROCESS_MODULES { ULONG NumberOfModules; RTL_PROCESS_MODULE_INFORMATION Modules[1]; };
    ULONG sz = 0x40000, need = 0;
    std::vector<BYTE> buf(sz);
    NTSTATUS st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, buf.data(), sz, &need);
    if (need > sz) { sz = need + 0x1000; buf.resize(sz); st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, buf.data(), sz, &need); }
    if (st != 0) {
        printf("  (module list unavailable — NtQuerySystemInformation failed 0x%lX)\n", (unsigned long)st);
        return;
    }
    auto* m = (RTL_PROCESS_MODULES*)buf.data();
    printf("\n=== Loaded kernel drivers (%lu) ===\n", m->NumberOfModules);
    for (ULONG i = 0; i < m->NumberOfModules; ++i) {
        auto& mi = m->Modules[i];
        const char* nm = (const char*)mi.FullPathName + mi.OffsetToFileName;
        printf("  %-40hs base=0x%p size=%lu\n", nm, mi.ImageBase, mi.ImageSize);
    }
}

int main() {
    std::vector<std::wstring> dirs = {
        L"C:\\Windows\\System32\\drivers",
        L"C:\\Windows\\SysWOW64\\drivers",
        L"C:\\Windows\\System32\\DriverStore\\FileRepository",
    };
    // also scan the DriverStore recursively — many vendor drivers land there
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(L"C:\\Windows\\System32\\DriverStore\\FileRepository\\*\\*.sys", &fd);
    if (h != INVALID_HANDLE_VALUE) {
        // note: wildcard path needs per-directory enumeration, use a wider net below
        FindClose(h);
    }

    // walk FileRepository one level deep (fast enough, few thousand dirs)
    std::vector<std::wstring> repo_dirs;
    std::wstring root = L"C:\\Windows\\System32\\DriverStore\\FileRepository";
    std::wstring pat = root + L"\\*";
    h = FindFirstFileW(pat.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L".."))
                    repo_dirs.push_back(root + L"\\" + fd.cFileName);
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    for (auto& d : repo_dirs) dirs.push_back(d);

    printf("Scanning %zu directories for vulnerable signed drivers...\n", dirs.size());

    std::vector<const VulnDriverEntry*> found;
    std::vector<std::wstring> paths;
    std::vector<std::wstring> versions;

    // de-dup by filename
    std::vector<std::wstring> seen_names;
    for (auto& dir : dirs) {
        std::wstring p = dir + L"\\*.sys";
        WIN32_FIND_DATAW f{};
        HANDLE fh = FindFirstFileW(p.c_str(), &f);
        if (fh == INVALID_HANDLE_VALUE) continue;
        do {
            std::wstring nm = f.cFileName;
            bool already = false;
            for (auto& s : seen_names) if (_wcsicmp(s.c_str(), nm.c_str()) == 0) { already = true; break; }
            if (already) continue;
            for (int i = 0; i < g_vuln_count; ++i) {
                wchar_t wname[128] = {};
                MultiByteToWideChar(CP_UTF8, 0, g_vuln[i].name, -1, wname, 128);
                if (_wcsicmp(nm.c_str(), wname) == 0) {
                    std::wstring full = dir + L"\\" + nm;
                    std::string sha, s1, md5;
                    if (HashFile(full, sha, s1, md5)) {
                        std::wstring ver = GetFileVersion(full);
                        seen_names.push_back(nm);
                        found.push_back(&g_vuln[i]);
                        paths.push_back(full);
                        versions.push_back(ver);
                    }
                    break;
                }
            }
        } while (FindNextFileW(fh, &f));
        FindClose(fh);
    }

    PrintTable(found, paths, versions);
    PrintLoadedKernelModules();
    printf("\nTotal: %zu vulnerable drivers present.\n", found.size());
    return 0;
}
