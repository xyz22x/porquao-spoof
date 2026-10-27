// spoofer.cpp — Porquao Spoof engine (session-first)
// Session profiles (Roblox / Minecraft): spoof applies on toggle, originals are
// auto-restored on next logon (agent service), so a reboot resets everything.
// Vanguard (open-source route): Route A boot driver when testsigning is on,
// otherwise Route B BYOVD runtime + vanguard moved to demand-start.
#include "engine.h"
#include "byovd.h"
#include <windows.h>
#include <winternl.h>
#include <setupapi.h>
#include <devguid.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <random>
#include <algorithm>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "version.lib")

namespace engine {
namespace {

LogFn g_log = nullptr;

// primitive name + version resource reader (used by the structured scan below)
std::string PrimName(int prim) {
    switch (prim) {
        case 1: return "ARB_RW";
        case 2: return "PHYS_MAP";
        case 3: return "ARB_ALLOC";
        case 4: return "ARB_EXEC";
        case 5: return "MSR_RW";
        case 6: return "IO_RW";
        default: return "NONE";
    }
}

std::wstring GetFileVersionInfoLocal(const std::wstring& path) {
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

void Log(const char* level, const char* fmt, ...) {
    if (!g_log) return;
    char buf[512];
    va_list ap; va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    g_log(level, buf);
}

constexpr const char* SVC_DRV   = "SPFSdrv";      // route A kernel driver service
constexpr const char* SVC_AGENT = "PQSpoofAgent"; // auto-start agent: restores originals on logon
constexpr const char* BK_ROOT   = "SOFTWARE\\PQSpoof\\Backup";

bool ServiceExistsHelper(SC_HANDLE scm, const char* name) {
    SC_HANDLE svc = OpenServiceA(scm, name, SERVICE_QUERY_STATUS);
    if (svc) { CloseServiceHandle(svc); return true; }
    return false;
}

// ---------- helpers ----------
bool IsAdmin() {
    BOOL adm = FALSE; PSID grp = nullptr;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &grp)) return false;
    CheckTokenMembership(nullptr, grp, &adm);
    FreeSid(grp);
    return adm != FALSE;
}

std::mt19937_64& Rng() { static std::mt19937_64 r((uint64_t)GetTickCount64() ^ (uintptr_t)&g_log); return r; }
uint64_t Rand64() { return Rng()(); }

std::string RandHex(int chars) {
    static const char* hx = "0123456789ABCDEF";
    std::string s; s.reserve(chars);
    for (int i = 0; i < chars; ++i) s += hx[Rand64() & 0xF];
    return s;
}

std::string RandAlnum(int chars) {
    static const char* alnum = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
    std::string s; s.reserve(chars);
    for (int i = 0; i < chars; ++i) s += alnum[Rand64() % 34];
    return s;
}

const char* MANUFS[]  = { "ASUSTeK COMPUTER INC.", "Micro-Star International Co., Ltd.", "Gigabyte Technology Co., Ltd.", "ASRock Incorporation", "Dell Inc.", "HP", "Lenovo" };
const char* PRODUCTS[]= { "ProArt X670E-CREATOR WIFI", "MAG B650 TOMAHAWK WIFI", "Z790 AORUS ELITE AX", "B660M Phantom Gaming 4", "OptiPlex 7080", "EliteDesk 800 G6", "ThinkCentre M90t" };
const char* BIOSVND[] = { "American Megatrends International, LLC.", "AMI", "Insyde Software Corp.", "Phoenix Technologies Ltd." };

std::string PickFrom(const char** arr, int n) { return arr[Rand64() % n]; }

// ---------- registry helpers ----------
LONG RegGetStr(HKEY root, const char* sub, const char* val, std::string* out) {
    HKEY k; LONG r = RegOpenKeyExA(root, sub, 0, KEY_READ | KEY_WOW64_64KEY, &k);
    if (r != ERROR_SUCCESS) return r;
    DWORD sz = 0;
    r = RegGetValueA(k, nullptr, val, RRF_RT_REG_SZ, nullptr, nullptr, &sz);
    if (r == ERROR_SUCCESS && sz) {
        std::vector<char> b(sz);
        r = RegGetValueA(k, nullptr, val, RRF_RT_REG_SZ, nullptr, b.data(), &sz);
        if (r == ERROR_SUCCESS) *out = b.data();
    }
    RegCloseKey(k);
    return r;
}

LONG RegSetStr(HKEY root, const char* sub, const char* val, const char* data) {
    HKEY k; LONG r = RegCreateKeyExA(root, sub, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &k, nullptr);
    if (r != ERROR_SUCCESS) return r;
    r = RegSetValueExA(k, val, 0, REG_SZ, (const BYTE*)data, (DWORD)(strlen(data) + 1));
    RegCloseKey(k);
    return r;
}

LONG RegSetDword(HKEY root, const char* sub, const char* val, DWORD data) {
    HKEY k; LONG r = RegCreateKeyExA(root, sub, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &k, nullptr);
    if (r != ERROR_SUCCESS) return r;
    r = RegSetValueExA(k, val, 0, REG_DWORD, (const BYTE*)&data, 4);
    RegCloseKey(k);
    return r;
}

LONG RegGetDword(HKEY root, const char* sub, const char* val, DWORD* out) {
    HKEY k; LONG r = RegOpenKeyExA(root, sub, 0, KEY_READ | KEY_WOW64_64KEY, &k);
    if (r != ERROR_SUCCESS) return r;
    DWORD sz = 4; r = RegGetValueA(k, nullptr, val, RRF_RT_REG_DWORD, nullptr, out, &sz);
    RegCloseKey(k);
    return r;
}

// backup original (or absence-marker) then write spoofed value
void BackupAndSetStr(const char* sub, const char* val, const char* spoofed) {
    char bk[512];
    std::string cur;
    if (RegGetStr(HKEY_LOCAL_MACHINE, sub, val, &cur) == ERROR_SUCCESS && !cur.empty()) {
        sprintf_s(bk, "SOFTWARE\\PQSpoof\\Backup\\%s", sub);
        RegSetStr(HKEY_LOCAL_MACHINE, bk, val, cur.c_str());
    } else {
        sprintf_s(bk, "SOFTWARE\\PQSpoof\\Backup\\%s", sub);
        RegSetStr(HKEY_LOCAL_MACHINE, bk, val, "\x01");
    }
    RegSetStr(HKEY_LOCAL_MACHINE, sub, val, spoofed);
}

bool BackupGetStr(const char* sub, const char* val, std::string* out) {
    char bk[512];
    sprintf_s(bk, "SOFTWARE\\PQSpoof\\Backup\\%s", sub);
    std::string s;
    if (RegGetStr(HKEY_LOCAL_MACHINE, bk, val, &s) != ERROR_SUCCESS || s.empty()) return false;
    if (s == "\x01") return false;
    *out = s;
    return true;
}

void MarkSessionPending() {
    RegSetDword(HKEY_LOCAL_MACHINE, "SOFTWARE\\PQSpoof", "RestoreOnBoot", 1);
}

// ---------- disk serials (originals) ----------
struct DiskInfo {
    std::string origSerial;
    std::string spoofSerial;
    int diskNum = -1;
};

bool QueryDiskSerial(HANDLE dev, std::string* serial) {
    BYTE buf[1024] = {};
    STORAGE_PROPERTY_QUERY q{};
    q.PropertyId = StorageDeviceProperty;
    q.QueryType = PropertyStandardQuery;
    DWORD ret = 0;
    if (!DeviceIoControl(dev, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q), buf, sizeof(buf), &ret, nullptr))
        return false;
    STORAGE_DEVICE_DESCRIPTOR* d = (STORAGE_DEVICE_DESCRIPTOR*)buf;
    if (d->SerialNumberOffset == 0 || d->SerialNumberOffset >= ret) return false;
    char* s = (char*)buf + d->SerialNumberOffset;
    size_t len = strnlen(s, (size_t)(ret - d->SerialNumberOffset));
    while (len && (s[len - 1] == ' ' || s[len - 1] == '\0')) --len;
    if (!len) return false;
    serial->assign(s, len);
    return true;
}

bool GetDisks(std::vector<DiskInfo>* out) {
    *out = {};
    for (int i = 0; i < 32; ++i) {
        char name[64]; sprintf_s(name, "\\\\.\\PhysicalDrive%d", i);
        HANDLE h = CreateFileA(name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) break;
        DiskInfo d{}; d.diskNum = i;
        if (QueryDiskSerial(h, &d.origSerial)) {
            d.spoofSerial = RandAlnum((int)d.origSerial.size());
            out->push_back(d);
        }
        CloseHandle(h);
    }
    return !out->empty();
}

// ---------- Route B: kernel data patch via BYOVD rw ----------
// x64 offsets stable since Vista: FILE_OBJECT.DeviceObject 0x08,
// DEVICE_OBJECT.DriverObject 0x08 / NextDevice 0x10 / AttachedDevice 0x18 / DeviceExtension 0x40.
constexpr uint64_t FO_DEVICE_OBJECT    = 0x08;
constexpr uint64_t DO_NEXT_DEVICE      = 0x10;
constexpr uint64_t DO_ATTACHED_DEVICE  = 0x18;
constexpr uint64_t DO_DEVICE_EXTENSION = 0x40;

bool GetKernelObjectOfHandle(HANDLE file, uint64_t* kernelObj) {
    struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
        ULONG_PTR Object; ULONG_PTR UniqueProcessId; ULONG_PTR HandleValue;
        ULONG GrantedAccess; USHORT CreatorBackTraceIndex; USHORT ObjectTypeIndex;
        ULONG HandleAttributes; ULONG Reserved;
    };
    struct SYSTEM_HANDLE_INFORMATION_EX {
        ULONG_PTR HandleCount; SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
    };
    ULONG sz = 0x800000;
    std::vector<BYTE> buf;
    for (int attempt = 0; attempt < 3; ++attempt) {
        buf.resize(sz);
        ULONG need = 0;
        NTSTATUS st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)64, buf.data(), sz, &need);
        if (st == (NTSTATUS)0xC0000004L /* INFO_LENGTH_MISMATCH */ && need > sz) { sz = need + 0x100000; continue; }
        if (st != 0) return false;
        break;
    }
    auto* t = (SYSTEM_HANDLE_INFORMATION_EX*)buf.data();
    ULONG_PTR me = (ULONG_PTR)GetCurrentProcessId();
    ULONG_PTR target = (ULONG_PTR)file;
    for (ULONG_PTR i = 0; i < t->HandleCount; ++i) {
        auto& e = t->Handles[i];
        if (e.UniqueProcessId == me && e.HandleValue == target && e.Object) {
            *kernelObj = (uint64_t)e.Object;
            return true;
        }
    }
    return false;
}

// find orig ASCII inside [base, base+span), replace with equal-length spoof
bool KernelPatchFindReplace(uint64_t base, size_t span, const std::string& orig, const std::string& spoof, uint64_t* patchAddr) {
    if (orig.empty() || orig.size() != spoof.size()) return false;
    for (size_t off = 0; off + orig.size() <= span; off += 8) {
        BYTE q[8] = {};
        if (!byovd::KernelRead(base + off, q, 8)) return false;
        if (memcmp(q, orig.data(), std::min<size_t>(8, orig.size())) == 0) {
            if (!byovd::KernelWrite(base + off, spoof.data(), std::min<size_t>(8, spoof.size()))) return false;
            *patchAddr = base + off;
            return true;
        }
    }
    return false;
}

// walk the device stack of an opened disk device, patch serial in extensions holding it
int PatchDiskSerialKernel(const DiskInfo& d, std::string* status) {
    HANDLE h = CreateFileA(("\\\\.\\PhysicalDrive" + std::to_string(d.diskNum)).c_str(),
                           GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) { *status = "open failed"; return -1; }
    uint64_t fo = 0;
    bool ok = GetKernelObjectOfHandle(h, &fo);
    CloseHandle(h);
    if (!ok || !fo) { *status = "FILE_OBJECT not in handle table"; return -2; }

    uint64_t dev = 0;
    if (!byovd::KernelRead(fo + FO_DEVICE_OBJECT, &dev, 8) || !dev) { *status = "bad DeviceObject"; return -3; }

    uint64_t chain[16] = {};
    int n = 0;
    chain[n++] = dev;
    {
        uint64_t up = 0, down = 0;
        if (byovd::KernelRead(dev + DO_ATTACHED_DEVICE, &up, 8) && up) chain[n++] = up;
        if (byovd::KernelRead(dev + DO_NEXT_DEVICE, &down, 8) && down) chain[n++] = down;
    }

    int patched = 0;
    for (int i = 0; i < n; ++i) {
        uint64_t ext = 0;
        if (!byovd::KernelRead(chain[i] + DO_DEVICE_EXTENSION, &ext, 8) || !ext) continue;
        uint64_t at = 0;
        if (KernelPatchFindReplace(ext, 0x2000, d.origSerial, d.spoofSerial, &at)) {
            ++patched;
            Log("ok", "disk%d: serial patched at ext 0x%llX (dev 0x%llX)", d.diskNum, (unsigned long long)at, (unsigned long long)chain[i]);
        }
    }
    if (!patched) *status = "serial bytes not found in scanned extensions";
    return patched > 0 ? 0 : -4;
}

// patch SMBIOS strings behind \Device\SmbiosData
int PatchSmbiosKernel(const std::vector<std::pair<std::string, std::string>>& pairs) {
    HANDLE h = CreateFileA("\\\\.\\GLOBALROOT\\Device\\SmbiosData", GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        h = CreateFileA("\\\\.\\SmbiosData", GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) { Log("warn", "SmbiosData device not openable — SMBIOS kernel patch skipped"); return -1; }
    }
    uint64_t fo = 0;
    bool ok = GetKernelObjectOfHandle(h, &fo);
    CloseHandle(h);
    if (!ok || !fo) { Log("warn", "no FILE_OBJECT for SmbiosData — skipped"); return -2; }

    uint64_t dev = 0;
    if (!byovd::KernelRead(fo + FO_DEVICE_OBJECT, &dev, 8) || !dev) return -3;
    uint64_t ext = 0;
    if (!byovd::KernelRead(dev + DO_DEVICE_EXTENSION, &ext, 8) || !ext) return -4;

    int patched = 0;
    auto tryPatch = [&](uint64_t base, size_t span) {
        for (auto& p : pairs) {
            uint64_t at = 0;
            if (KernelPatchFindReplace(base, span, p.first, p.second, &at)) ++patched;
        }
    };
    tryPatch(ext, 0x8000);
    // chase plausible pointers in the extension; SMBIOS table starts { 0x00, 0x18 }
    for (uint64_t off = 0; off < 0x100; off += 8) {
        uint64_t ptr = 0;
        if (!byovd::KernelRead(ext + off, &ptr, 8)) break;
        if (ptr > 0xFFFF800000000000ULL && ptr < 0xFFFFFFFFFFFF0000ULL) {
            BYTE hdr[2] = {};
            if (byovd::KernelRead(ptr, hdr, 2) && hdr[0] == 0x00 && hdr[1] == 0x18) {
                tryPatch(ptr, 0x8000);
            }
        }
    }
    Log(patched ? "ok" : "warn", "smbios kernel patch: %d strings replaced", patched);
    return patched;
}

} // anonymous namespace

// ---------- public ----------
void SetLog(LogFn fn) { g_log = fn; }

int SpoofRegistrySet(const std::string& manuf, const std::string& prod, const std::string& sysVer,
                     const std::string& family, const std::string& sku,
                     const std::string& biosV, const std::string& biosVn, const std::string& biosDate,
                     const std::string& baseMan, const std::string& baseProd, const std::string& baseVer,
                     const std::string& guid) {
    BackupAndSetStr("HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemManufacturer", manuf.c_str());
    BackupAndSetStr("HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemProductName", prod.c_str());
    BackupAndSetStr("HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemVersion", sysVer.c_str());
    BackupAndSetStr("HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemFamily", family.c_str());
    BackupAndSetStr("HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemSKU", sku.c_str());
    BackupAndSetStr("HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVendor", biosV.c_str());
    BackupAndSetStr("HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVersion", biosVn.c_str());
    BackupAndSetStr("HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSReleaseDate", biosDate.c_str());
    BackupAndSetStr("HARDWARE\\DESCRIPTION\\System\\BIOS", "BaseBoardManufacturer", baseMan.c_str());
    BackupAndSetStr("HARDWARE\\DESCRIPTION\\System\\BIOS", "BaseBoardProduct", baseProd.c_str());
    BackupAndSetStr("HARDWARE\\DESCRIPTION\\System\\BIOS", "BaseBoardVersion", baseVer.c_str());

    BackupAndSetStr("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemManufacturer", manuf.c_str());
    BackupAndSetStr("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName", prod.c_str());
    BackupAndSetStr("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemVersion", sysVer.c_str());
    BackupAndSetStr("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemFamily", family.c_str());
    BackupAndSetStr("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemSKU", sku.c_str());
    BackupAndSetStr("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "BIOSVendor", biosV.c_str());
    BackupAndSetStr("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "BIOSVersion", biosVn.c_str());
    BackupAndSetStr("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "BIOSReleaseDate", biosDate.c_str());
    BackupAndSetStr("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "BaseBoardManufacturer", baseMan.c_str());
    BackupAndSetStr("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "BaseBoardProduct", baseProd.c_str());
    BackupAndSetStr("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "BaseBoardVersion", baseVer.c_str());

    BackupAndSetStr("SOFTWARE\\Microsoft\\Cryptography", "MachineGuid", guid.c_str());
    return 0;
}

// ---------- MAC spoof (registry + adapter restart) ----------
int SpoofMac() {
    static const char* hx = "0123456789ABCDEF";
    std::string mac = "02"; // locally administered, unicast
    for (int i = 0; i < 5; ++i) { mac += hx[Rand64() & 0xF]; mac += hx[Rand64() & 0xF]; }

    HKEY cls; LONG r = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
                                     0, KEY_READ | KEY_WOW64_64KEY, &cls);
    if (r != ERROR_SUCCESS) { Log("err", "NIC class key open failed"); return -1; }
    DWORD idx = 0; char sub[32] = {}; int patched = 0;
    while (RegEnumKeyA(cls, idx++, sub, sizeof(sub)) == ERROR_SUCCESS) {
        std::string key = std::string("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\") + sub;
        std::string drvDesc;
        if (RegGetStr(HKEY_LOCAL_MACHINE, key.c_str(), "DriverDesc", &drvDesc) != ERROR_SUCCESS) continue;
        if (drvDesc.find("WAN Miniport") != std::string::npos) continue;
        BackupAndSetStr(key.c_str(), "NetworkAddress", mac.c_str());
        ++patched;
    }
    RegCloseKey(cls);
    Log("ok", "MAC set on %d adapters (%hs)", patched, mac.c_str());
    return patched;
}

int RestartAdapters() {
    HDEVINFO set = SetupDiGetClassDevsA(&GUID_DEVCLASS_NET, nullptr, nullptr, DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) { Log("err", "SetupDiGetClassDevs failed"); return -1; }
    SP_DEVINFO_DATA did{ sizeof(SP_DEVINFO_DATA) };
    int restarted = 0;
    for (DWORD i = 0; SetupDiEnumDeviceInfo(set, i, &did); ++i) {
        wchar_t id[256] = {};
        if (!SetupDiGetDeviceInstanceIdW(set, &did, id, 256, nullptr)) continue;
        if (wcsstr(id, L"WAN Miniport")) continue;
        bool ok = true;
        for (int pass = 0; pass < 2; ++pass) {
            SP_PROPCHANGE_PARAMS pc{};
            pc.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
            pc.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
            pc.StateChange = (pass == 0) ? DICS_DISABLE : DICS_ENABLE;
            pc.Scope = DICS_FLAG_CONFIGSPECIFIC;
            pc.HwProfile = 0;
            if (!SetupDiSetClassInstallParams(set, &did, &pc.ClassInstallHeader, sizeof(pc))) { ok = false; break; }
            if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, set, &did)) { ok = false; break; }
        }
        if (ok) ++restarted;
    }
    SetupDiDestroyDeviceInfoList(set);
    Log("ok", "%d adapters restarted", restarted);
    return restarted;
}

// ---------- EDID (monitor serial) spoof ----------
int SpoofEdid() {
    HKEY cls; LONG r = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\DISPLAY", 0, KEY_READ | KEY_WOW64_64KEY, &cls);
    if (r != ERROR_SUCCESS) { Log("warn", "no DISPLAY enum — EDID skip"); return 0; }
    DWORD idx = 0; char mon[32] = {};
    int patched = 0;
    while (RegEnumKeyA(cls, idx++, mon, sizeof(mon)) == ERROR_SUCCESS) {
        HKEY monK; if (RegOpenKeyExA(cls, mon, 0, KEY_READ, &monK) != ERROR_SUCCESS) continue;
        std::string base = std::string("SYSTEM\\CurrentControlSet\\Enum\\DISPLAY\\") + mon;
        DWORD j = 0; char inst[64] = {};
        while (RegEnumKeyA(monK, j++, inst, sizeof(inst)) == ERROR_SUCCESS) {
            std::string edidKey = base + "\\" + inst + "\\Device Parameters";
            HKEY ek; if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, edidKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &ek) != ERROR_SUCCESS) continue;
            DWORD sz = 0;
            if (RegQueryValueExA(ek, "EDID", nullptr, nullptr, nullptr, &sz) == ERROR_SUCCESS && sz >= 128) {
                std::vector<BYTE> e(sz);
                if (RegQueryValueExA(ek, "EDID", nullptr, nullptr, e.data(), &sz) == ERROR_SUCCESS) {
                    // serial number: offset 0x08, 4 bytes LE
                    DWORD sn = (DWORD)(Rand64() & 0xFFFFFFFF);
                    e[8] = (BYTE)(sn & 0xFF); e[9] = (BYTE)((sn >> 8) & 0xFF);
                    e[10] = (BYTE)((sn >> 16) & 0xFF); e[11] = (BYTE)((sn >> 24) & 0xFF);
                    // descriptor string blocks carrying serial (type 0xFF): 0x5C and 0x7C
                    for (int dstart : { 0x5C, 0x7C }) {
                        if (dstart + 18 <= (int)sz && e[dstart] == 0xFF) {
                            for (int k = dstart + 5; k < dstart + 5 + 13; ++k)
                                e[k] = (BYTE)('A' + (Rand64() % 26));
                        }
                    }
                    // checksum over first 128 bytes
                    e[0x7F] = 0; BYTE sum = 0;
                    for (int c = 0; c < 0x80; ++c) sum += e[c];
                    e[0x7F] = (BYTE)(0x100 - sum);
                    char bk[512]; sprintf_s(bk, "SOFTWARE\\PQSpoof\\Backup\\EDID_%d", patched);
                    RegSetStr(HKEY_LOCAL_MACHINE, bk, "EDID", "y");
                    RegSetValueExA(ek, "EDID", 0, REG_BINARY, e.data(), sz);
                    ++patched;
                }
            }
            RegCloseKey(ek);
        }
        RegCloseKey(monK);
    }
    RegCloseKey(cls);
    Log("ok", "EDID patched on %d monitors", patched);
    return patched;
}

// ---------- volume serials ----------
int SpoofVolumeSerials() {
    // NTFS serial: 8 bytes at 0x48. FAT32 serial: 4 bytes at 0x27.
    std::vector<std::wstring> vols;
    wchar_t vname[MAX_PATH] = {};
    HANDLE h = FindFirstVolumeW(vname, MAX_PATH);
    if (h == INVALID_HANDLE_VALUE) return -1;
    do {
        size_t l = wcslen(vname);
        if (l && vname[l - 1] == L'\\') vname[l - 1] = 0;
        vols.push_back(vname);
    } while (FindNextVolumeW(h, vname, MAX_PATH));
    FindVolumeClose(h);

    int done = 0;
    for (auto& v : vols) {
        HANDLE dv = CreateFileW(v.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, 0, nullptr);
        if (dv == INVALID_HANDLE_VALUE) continue;
        DWORD ret = 0;
        DeviceIoControl(dv, FSCTL_DISMOUNT_VOLUME, nullptr, 0, nullptr, 0, &ret, nullptr);
        BYTE bs[512] = {};
        DWORD rd = 0;
        SetFilePointer(dv, 0, nullptr, FILE_BEGIN);
        if (!ReadFile(dv, bs, 512, &rd, nullptr) || rd != 512) { CloseHandle(dv); continue; }
        bool ntfs = memcmp(bs + 3, "NTFS    ", 8) == 0;
        bool fat32 = memcmp(bs + 0x52, "FAT32   ", 8) == 0;
        if (ntfs) {
            UINT64 s64 = (UINT64)Rand64() << 32 | (UINT64)Rand64();
            memcpy(bs + 0x48, &s64, 8);
        } else if (fat32) {
            DWORD vsn = (DWORD)(Rand64() & 0xFFFFFFFF);
            memcpy(bs + 0x27, &vsn, 4);
        } else {
            CloseHandle(dv);
            continue;
        }
        SetFilePointer(dv, 0, nullptr, FILE_BEGIN);
        DWORD wr = 0;
        if (WriteFile(dv, bs, 512, &wr, nullptr) && wr == 512) ++done;
        CloseHandle(dv);
        // reopen triggers remount
        HANDLE rm = CreateFileW(v.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (rm != INVALID_HANDLE_VALUE) CloseHandle(rm);
    }
    Log("ok", "%d volume serials rewritten", done);
    return done;
}

// ---------- Route A: boot driver ----------
int InstallBootDriver() {
    DWORD test = 0;
    if (RegGetDword(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\CI", "TestSigning", &test) == ERROR_SUCCESS && !test) {
        Log("warn", "TestSigning OFF — run: bcdedit /set testsigning on, then reboot. Route A blocked until then.");
    }
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring dir = self;
    size_t slash = dir.find_last_of(L'\\');
    if (slash != std::wstring::npos) dir = dir.substr(0, slash);
    std::wstring src = dir + L"\\spfs.sys";
    if (GetFileAttributesW(src.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Log("err", "spfs.sys not found next to the exe — build driver first");
        return -1;
    }
    std::wstring dst = L"C:\\Windows\\System32\\drivers\\spfs.sys";
    if (!CopyFileW(src.c_str(), dst.c_str(), FALSE)) {
        Log("err", "copy spfs.sys to drivers failed (admin?)");
        return -2;
    }
    char dstA[MAX_PATH] = {};
    WideCharToMultiByte(CP_ACP, 0, dst.c_str(), -1, dstA, MAX_PATH, nullptr, nullptr);
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { Log("err", "OpenSCManager failed"); return -3; }
    if (ServiceExistsHelper(scm, SVC_DRV)) {
        SC_HANDLE d = OpenServiceA(scm, SVC_DRV, DELETE);
        if (d) { DeleteService(d); CloseServiceHandle(d); }
    }
    SC_HANDLE svc = CreateServiceA(scm, SVC_DRV, "PQ System Fabric", SERVICE_ALL_ACCESS,
                                   SERVICE_KERNEL_DRIVER, SERVICE_BOOT_START, SERVICE_ERROR_NORMAL,
                                   dstA, "Extended Base", nullptr, nullptr, nullptr, nullptr);
    if (!svc) { Log("err", "CreateService(boot) failed"); CloseServiceHandle(scm); return -4; }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    Log("ok", "boot driver registered (Start=0, Group=Extended Base) — loads before vanguard");
    return 0;
}

int RunBootDriverOnce() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return -1;
    SC_HANDLE svc = OpenServiceA(scm, SVC_DRV, SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return -2; }
    ChangeServiceConfigA(svc, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    SERVICE_STATUS st{};
    if (!StartServiceA(svc, 0, nullptr)) {
        Log("err", "boot driver demand-start failed — build spfs.sys first");
        ChangeServiceConfigA(svc, SERVICE_NO_CHANGE, SERVICE_BOOT_START, SERVICE_NO_CHANGE,
                             nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        CloseServiceHandle(svc); CloseServiceHandle(scm);
        return -3;
    }
    Sleep(500);
    QueryServiceStatus(svc, &st);
    if (st.dwCurrentState == SERVICE_RUNNING) ControlService(svc, SERVICE_CONTROL_STOP, &st);
    ChangeServiceConfigA(svc, SERVICE_NO_CHANGE, SERVICE_BOOT_START, SERVICE_NO_CHANGE,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    Log("ok", "boot driver executed once (cache+spoof), restored to boot-start");
    return 0;
}

// ---------- auto-restore agent ----------
int InstallBootRestoreAgent() {
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::string cmd;
    {
        char a[MAX_PATH] = {};
        WideCharToMultiByte(CP_ACP, 0, self, -1, a, MAX_PATH, nullptr, nullptr);
        cmd = std::string("\"") + a + "\" --restore-on-boot";
    }
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return -1;
    if (ServiceExistsHelper(scm, SVC_AGENT)) {
        SC_HANDLE d = OpenServiceA(scm, SVC_AGENT, DELETE);
        if (d) { DeleteService(d); CloseServiceHandle(d); }
    }
    SC_HANDLE svc = CreateServiceA(scm, SVC_AGENT, "PQ Spoof Agent", SERVICE_ALL_ACCESS,
                                   SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE,
                                   cmd.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc) { CloseServiceHandle(scm); return -2; }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    Log("ok", "boot-restore agent installed — originals return on next logon");
    return 0;
}

// ---------- vanguard boot mode ----------
int SetVanguardBoot(bool boot) {
    DWORD start = boot ? 0 : 3; // 0=boot, 3=demand
    const char* svcs[] = { "vgk", "vgc" };
    int done = 0;
    for (auto* s : svcs) {
        char sub[128]; sprintf_s(sub, "SYSTEM\\CurrentControlSet\\Services\\%s", s);
        char bk[160]; sprintf_s(bk, "SOFTWARE\\PQSpoof\\Backup\\Services\\%s", s);
        DWORD cur = 0;
        if (RegGetDword(HKEY_LOCAL_MACHINE, sub, "Start", &cur) == ERROR_SUCCESS) {
            char tmp[16]; sprintf_s(tmp, "%lu", cur);
            RegSetStr(HKEY_LOCAL_MACHINE, bk, "Start", tmp);
        }
        if (RegSetDword(HKEY_LOCAL_MACHINE, sub, "Start", start) == ERROR_SUCCESS) ++done;
    }
    Log(done ? "ok" : "warn", "vanguard set to %hs start (%d touched)", boot ? "boot" : "demand", done);
    return done;
}

// ---------- main spoof entry ----------
int Spoof(uint32_t mask, bool routeA, bool doVolumes) {
    if (!IsAdmin()) { Log("err", "administrator token required"); return -100; }

    uint32_t sessionMask = mask & (ROBLOX | MINE);
    bool wantVava = (mask & VAVA) != 0;

    Log("info", "=== Porquao Spoof — session profile 0x%X %hs ===",
        mask, routeA ? "(route A boot driver)" : "(route B BYOVD runtime)");

    // 1. originals
    std::vector<DiskInfo> disks;
    if (!GetDisks(&disks)) Log("warn", "no disk serials readable");

    // 2. registry identity (backed up — agent restores on next logon for session mode)
    std::string manuf  = PickFrom(MANUFS, 7);
    std::string prod   = PickFrom(PRODUCTS, 7);
    std::string sysVer = "1.0.0.0";
    std::string family = "Consumer";
    std::string sku    = "SKU-" + RandHex(6);
    std::string biosV  = PickFrom(BIOSVND, 4);
    std::string biosVn = "1." + RandHex(2) + ".0." + RandHex(4);
    std::string biosDate = "01/" + RandHex(2) + "/2024";
    std::string baseMan  = manuf;
    std::string baseProd = prod;
    std::string baseVer  = "Rev 1.0";
    std::string guid = RandHex(8) + "-" + RandHex(4) + "-4" + RandHex(3) + "-8" + RandHex(2) + "-" + RandHex(12);

    SpoofRegistrySet(manuf, prod, sysVer, family, sku, biosV, biosVn, biosDate, baseMan, baseProd, baseVer, guid);
    Log("ok", "registry identity applied (manuf=%hs)", manuf.c_str());

    // 3. MAC + adapters
    SpoofMac();
    RestartAdapters();

    // 4. EDID
    SpoofEdid();

    // 5. volumes (optional)
    if (doVolumes) SpoofVolumeSerials();
    else Log("info", "volume serials skipped (off)");

    // 6. kernel-side
    if (routeA && wantVava) {
        int r = RunBootDriverOnce();
        if (r != 0) Log("warn", "route A did not run — falling back to route B kernel patch");
    }
    {
        std::string err;
        if (byovd::Load(&err) == 0) {
            Log("info", "BYOVD loaded: %hs", byovd::LoadedDriver()->name);
            for (auto& dsk : disks) {
                std::string st;
                if (PatchDiskSerialKernel(dsk, &st) != 0) Log("warn", "disk%d kernel patch: %hs", dsk.diskNum, st.c_str());
            }
            // SMBIOS — patch with same-length generated strings
            std::vector<std::pair<std::string, std::string>> pairs;
            auto addPair = [&](const std::string& orig) {
                if (orig.size() >= 8) pairs.push_back({ orig, RandAlnum((int)orig.size()) });
            };
            std::string o;
            if (BackupGetStr("HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemManufacturer", &o)) addPair(o);
            if (BackupGetStr("HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemProductName", &o)) addPair(o);
            if (BackupGetStr("HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVendor", &o)) addPair(o);
            if (BackupGetStr("HARDWARE\\DESCRIPTION\\System\\BIOS", "BaseBoardManufacturer", &o)) addPair(o);
            PatchSmbiosKernel(pairs);
        } else {
            Log("warn", "BYOVD unavailable: %hs — kernel patch skipped", err.c_str());
        }
    }

    // 7. session vs boot semantics
    if (sessionMask) {
        MarkSessionPending();                       // next logon restores originals
        InstallBootRestoreAgent();
        Log("ok", "session spoof armed for %hs — originals restore on next logon/reboot",
            sessionMask == ROBLOX ? "roblox" : (sessionMask == MINE ? "minecraft" : "roblox+minecraft"));
    }
    if (wantVava) {
        if (routeA) {
            SetVanguardBoot(true);                  // boot driver spoofs before vanguard loads
        } else {
            SetVanguardBoot(false);                 // vanguard demand start — spoof first, then load
            Log("warn", "vanguard demand start — ranked may require boot mode; Route A avoids this");
        }
    }

    Log("ok", "=== spoof complete (mask=0x%X) ===", mask);
    return 0;
}

// ---------- restore ----------
int Restore() {
    if (!IsAdmin()) { Log("err", "administrator token required"); return -100; }
    HKEY bk; LONG r = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\PQSpoof\\Backup", 0, KEY_READ | KEY_WOW64_64KEY, &bk);
    if (r != ERROR_SUCCESS) { Log("warn", "no backup present"); return -1; }
    std::vector<std::string> keys;
    char sub[256] = {}; DWORD i = 0;
    while (RegEnumKeyA(bk, i++, sub, sizeof(sub)) == ERROR_SUCCESS) keys.push_back(sub);
    RegCloseKey(bk);
    for (auto& k : keys) {
        char bkSub[512]; sprintf_s(bkSub, "SOFTWARE\\PQSpoof\\Backup\\%s", k.c_str());
        HKEY bks; if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, bkSub, 0, KEY_READ | KEY_WOW64_64KEY, &bks) != ERROR_SUCCESS) continue;
        DWORD j = 0; char val[256] = {}; DWORD vtype = 0; DWORD vlen = 0;
        while (RegEnumValueA(bks, j++, val, nullptr, nullptr, &vtype, nullptr, &vlen) == ERROR_SUCCESS) {
            std::string orig;
            if (vtype == REG_DWORD) {
                DWORD d = 0; DWORD sz = 4;
                if (RegGetValueA(bks, nullptr, val, RRF_RT_REG_DWORD, nullptr, &d, &sz) == ERROR_SUCCESS) {
                    RegSetDword(HKEY_LOCAL_MACHINE, k.c_str(), val, d);
                }
                continue;
            }
            if (BackupGetStr(k.c_str(), val, &orig)) {
                RegSetStr(HKEY_LOCAL_MACHINE, k.c_str(), val, orig.c_str());
            } else {
                HKEY t; if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, k.c_str(), 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &t) == ERROR_SUCCESS) {
                    RegDeleteValueA(t, val);
                    RegCloseKey(t);
                }
            }
        }
        RegCloseKey(bks);
    }
    // clear pending flag + remove agent
    RegSetDword(HKEY_LOCAL_MACHINE, "SOFTWARE\\PQSpoof", "RestoreOnBoot", 0);
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = OpenServiceA(scm, SVC_AGENT, DELETE);
        if (svc) { DeleteService(svc); CloseServiceHandle(svc); }
        CloseServiceHandle(scm);
    }
    Log("ok", "restore complete — reboot for full effect");
    return 0;
}

// silent restore used by the boot agent
int RestoreOnBootSilent() {
    DWORD pend = 0;
    if (RegGetDword(HKEY_LOCAL_MACHINE, "SOFTWARE\\PQSpoof", "RestoreOnBoot", &pend) != ERROR_SUCCESS || !pend)
        return 0; // nothing pending — session spoof not armed
    return Restore();
}

// ---------- scanner (text report) ----------
std::string ScanVulnerableDrivers() {
    std::string out;
    char line[512];
    for (int i = 0; i < g_vuln_count; ++i) {
        const VulnDriverEntry* e = &g_vuln[i];
        wchar_t wname[128] = {};
        MultiByteToWideChar(CP_UTF8, 0, e->name, -1, wname, 128);
        std::wstring p = L"C:\\Windows\\System32\\drivers\\" + std::wstring(wname);
        if (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES) {
            sprintf_s(line, "FOUND  %-16hs %-12hs %-16hs prim=%d\n", e->name, e->vendor, e->cve, (int)e->prim);
        } else {
            sprintf_s(line, "ABSENT %-16hs %-12hs %-16hs\n", e->name, e->vendor, e->cve);
        }
        out += line;
    }
    return out;
}

// ---------- structured scan (UI Logs tab) ----------
std::vector<ScanRow> ScanStructured() {
    std::vector<ScanRow> rows;
    for (int i = 0; i < g_vuln_count; ++i) {
        const VulnDriverEntry* e = &g_vuln[i];
        ScanRow r;
        r.name = e->name;
        r.vendor = e->vendor;
        r.cve = e->cve;
        r.prim = PrimName((int)e->prim);
        wchar_t wname[128] = {};
        MultiByteToWideChar(CP_UTF8, 0, e->name, -1, wname, 128);
        std::wstring p = L"C:\\Windows\\System32\\drivers\\" + std::wstring(wname);
        if (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES) {
            r.present = true;
            std::wstring v = GetFileVersionInfoLocal(p);
            char va[64] = {};
            WideCharToMultiByte(CP_UTF8, 0, v.c_str(), -1, va, 64, nullptr, nullptr);
            r.version = va;
        }
        rows.push_back(r);
    }
    return rows;
}

} // namespace engine
