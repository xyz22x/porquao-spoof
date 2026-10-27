// spfs.c — Porquao Spoof boot-start kernel driver (Route A)
// Loads at boot (Start=0, Group "Extended Base") before vanguard/hyperion:
//   1. disables tpm.sys (Start=4) — no TPM anchor for anticheats
//   2. patches disk FDO DeviceExtensions with equal-length spoofed serials
//   3. patches the SMBIOS table buffer behind \Device\SmbiosData
//   4. rewrites registry identity (BIOS desc, SystemInformation, MachineGuid)
// IOCTL_CACHE_AND_SPOOF: user-mode trigger for the first run (cache originals
// into the service Seed key; boot runs reuse the cache if a query fails).
// Compile as C (WDK). No lambdas, no C++ runtime.
#include <ntddk.h>
#include <ntddstor.h>
#include <ntstrsafe.h>

// undocumented kernel exports — present in ntoskrnl.lib, absent from the WDK headers
// (the 5th arg of ObReferenceObjectByName is PVOID so it accepts the const OBJECT_TYPE*
// the WDK headers declare for IoDriverObjectType/IoDeviceObjectType)
extern POBJECT_TYPE IoDriverObjectType;
extern POBJECT_TYPE IoDeviceObjectType;
extern NTSTATUS ObReferenceObjectByName(
    PUNICODE_STRING ObjectName, ULONG Attributes,
    PACCESS_STATE AccessState, ACCESS_MASK DesiredAccess,
    PVOID ObjectType, KPROCESSOR_MODE AccessMode,
    PVOID ParseContext, PVOID* Object);
extern NTSTATUS IoEnumerateDeviceObjectList(
    PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT* DeviceObjectList,
    ULONG DeviceObjectCount, PULONG ActualNumberDeviceObjects);
extern ULONG RtlRandomEx(PULONG seed);

#define SPFS_DEVICE_NAME L"\\Device\\SPFSdrv"
#define SPFS_SYMLINK     L"\\DosDevices\\SPFSdrv"
#define IOCTL_CACHE_AND_SPOOF CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STATUS          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// x64 offsets stable since Vista
#define FO_DEVICE_OBJECT    0x08
#define DO_DEVICE_EXTENSION 0x40

typedef struct _SPFS_CONTEXT {
    PDEVICE_OBJECT self;
    BOOLEAN spoofed;
} SPFS_CONTEXT;

static ULONG g_state = 0x13579BDF;

static ULONG SpfsRand(void) {
    g_state = RtlRandomEx(&g_state);
    return g_state;
}

static VOID SpfsGenAscii(CHAR* out, ULONG len) {
    static const char* alnum = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
    for (ULONG i = 0; i < len; ++i) out[i] = alnum[SpfsRand() % 34];
}

// ---------- registry helpers ----------
static NTSTATUS SpfsSetStringRoot(PCWSTR root, PCWSTR val, PWSTR data) {
    UNICODE_STRING rp = { 0 };
    WCHAR rpBuf[512];
    RtlStringCchCopyW(rpBuf, 512, root);
    RtlInitUnicodeString(&rp, rpBuf);
    HANDLE k;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &rp, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    NTSTATUS st = ZwCreateKey(&k, KEY_SET_VALUE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(st)) return st;
    UNICODE_STRING n;
    RtlInitUnicodeString(&n, val);
    st = ZwSetValueKey(k, &n, 0, REG_SZ, data, (ULONG)((wcslen(data) + 1) * sizeof(WCHAR)));
    ZwClose(k);
    return st;
}

static NTSTATUS SpfsSetDwordRoot(PCWSTR root, PCWSTR val, ULONG data) {
    UNICODE_STRING rp = { 0 };
    WCHAR rpBuf[512];
    RtlStringCchCopyW(rpBuf, 512, root);
    RtlInitUnicodeString(&rp, rpBuf);
    HANDLE k;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &rp, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    NTSTATUS st = ZwCreateKey(&k, KEY_SET_VALUE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(st)) return st;
    UNICODE_STRING n;
    RtlInitUnicodeString(&n, val);
    st = ZwSetValueKey(k, &n, 0, REG_DWORD, &data, 4);
    ZwClose(k);
    return st;
}

// ---------- disk patch ----------
// Query the serial via STORAGE_QUERY_PROPERTY on the FDO, then locate those exact
// bytes in the DeviceExtension and replace equal-length. Cache into the Seed key.
static NTSTATUS SpfsPatchDisk(PDEVICE_OBJECT fdo, ULONG diskIdx) {
    ULONG outLen = 1024;
    PUCHAR out = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, outLen, 'sPfs');
    if (!out) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(out, outLen);

    STORAGE_PROPERTY_QUERY q;
    RtlZeroMemory(&q, sizeof(q));
    q.PropertyId = StorageDeviceProperty;
    q.QueryType = PropertyStandardQuery;

    PIRP irp = IoBuildDeviceIoControlRequest(IOCTL_STORAGE_QUERY_PROPERTY, fdo,
                                             &q, sizeof(q), out, outLen, FALSE, NULL, NULL);
    if (!irp) { ExFreePoolWithTag(out, 'sPfs'); return STATUS_INSUFFICIENT_RESOURCES; }

    KEVENT ev; KeInitializeEvent(&ev, NotificationEvent, FALSE);
    IO_STATUS_BLOCK iosb;
    irp->UserIosb = &iosb;
    irp->UserEvent = &ev;
    NTSTATUS st = IoCallDriver(fdo, irp);
    if (st == STATUS_PENDING) KeWaitForSingleObject(&ev, Executive, KernelMode, FALSE, NULL);
    st = iosb.Status;

    if (!NT_SUCCESS(st)) { ExFreePoolWithTag(out, 'sPfs'); return st; }

    STORAGE_DEVICE_DESCRIPTOR* d = (STORAGE_DEVICE_DESCRIPTOR*)out;
    if (d->SerialNumberOffset == 0 || d->SerialNumberOffset >= outLen) {
        ExFreePoolWithTag(out, 'sPfs');
        return STATUS_NOT_FOUND;
    }
    char* serial = (char*)out + d->SerialNumberOffset;
    // validate length (ATA-style: fixed width, space-padded)
    ULONG slen = 0;
    while (slen < 32 && serial[slen] != '\0') ++slen;
    if (slen < 8 || slen > 32) { ExFreePoolWithTag(out, 'sPfs'); return STATUS_NOT_FOUND; }

    // find these exact bytes in the DeviceExtension and replace equal-length
    PVOID ext = fdo->DeviceExtension;
    CHAR news[33];
    SpfsGenAscii(news, slen);
    news[slen] = '\0';

    BOOLEAN patched = FALSE;
    __try {
        for (ULONG off = 0; off + slen < 0x2000; ++off) {
            UCHAR* p = (PUCHAR)ext + off;
            if (RtlCompareMemory(p, serial, slen) == slen) {
                RtlCopyMemory(p, news, slen);
                patched = TRUE;
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }

    ExFreePoolWithTag(out, 'sPfs');

    // cache into the Seed key for boot reuse
    WCHAR seedPathBuf[256];
    UNICODE_STRING seedPath = { 0 };
    RtlStringCchCopyW(seedPathBuf, 256, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\SPFSdrv\\Seed");
    RtlInitUnicodeString(&seedPath, seedPathBuf);
    HANDLE k;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &seedPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (NT_SUCCESS(ZwCreateKey(&k, KEY_SET_VALUE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL))) {
        WCHAR valName[32];
        RtlStringCchPrintfW(valName, 32, L"Disk%lu_Orig", diskIdx);
        WCHAR wOrigBuf[64], wSpoofBuf[64];
        for (ULONG c = 0; c < slen; ++c) { wOrigBuf[c] = (WCHAR)serial[c]; wSpoofBuf[c] = (WCHAR)news[c]; }
        wOrigBuf[slen] = 0; wSpoofBuf[slen] = 0;
        UNICODE_STRING vn; RtlInitUnicodeString(&vn, valName);
        ZwSetValueKey(k, &vn, 0, REG_SZ, wOrigBuf, (ULONG)((slen + 1) * sizeof(WCHAR)));
        RtlStringCchPrintfW(valName, 32, L"Disk%lu_Spoof", diskIdx);
        RtlInitUnicodeString(&vn, valName);
        ZwSetValueKey(k, &vn, 0, REG_SZ, wSpoofBuf, (ULONG)((slen + 1) * sizeof(WCHAR)));
        ZwClose(k);
    }
    return patched ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

static VOID SpfsPatchAllDisks(void) {
    PDRIVER_OBJECT diskDrv = NULL;
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
    NTSTATUS st = ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE, NULL, 0, IoDriverObjectType, KernelMode, NULL, (PVOID*)&diskDrv);
    if (!NT_SUCCESS(st)) return;

    PDEVICE_OBJECT list[32]; ULONG got = 0;
    st = IoEnumerateDeviceObjectList(diskDrv, list, 32, &got);
    ObfDereferenceObject(diskDrv);
    if (!NT_SUCCESS(st) || got == 0) return;

    for (ULONG i = 0; i < got; ++i) {
        SpfsPatchDisk(list[i], i);
        ObfDereferenceObject(list[i]);
    }
}

// ---------- SMBIOS patch ----------
static VOID SpfsPatchSmbios(void) {
    PDEVICE_OBJECT sm = NULL;
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Device\\SmbiosData");
    NTSTATUS st = ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE, NULL, 0, IoDeviceObjectType, KernelMode, NULL, (PVOID*)&sm);
    if (!NT_SUCCESS(st)) return;
    PVOID ext = sm->DeviceExtension;
    ObfDereferenceObject(sm);
    if (!ext) return;

    // SMBIOS structures: find type0 header { 0x00, 0x18 } — chase ext pointers first
    PCHAR table = NULL;
    __try {
        for (ULONG off = 0; off < 0x100 && !table; off += 8) {
            PVOID cand = *(PVOID*)((PUCHAR)ext + off);
            if ((uintptr_t)cand < 0xFFFF800000000000ULL) continue;
            UCHAR h0 = ((PUCHAR)cand)[0], h1 = ((PUCHAR)cand)[1];
            if (h0 == 0x00 && h1 == 0x18) table = (PCHAR)cand;
        }
        if (!table) {
            for (ULONG off = 0; off < 0x8000 - 2; ++off) {
                UCHAR* p = (PUCHAR)ext + off;
                if (p[0] == 0x00 && p[1] == 0x18) { table = (PCHAR)p; break; }
            }
        }
        if (!table) return;

        // rewrite type1 (System Information) strings: manuf, product, version, serial, SKU, family
        PCHAR p = table;
        for (ULONG walk = 0; walk < 0x4000; ) {
            UCHAR type = p[0], len = p[1];
            if (type == 127 && len == 4) break;
            if (len == 0) break;
            if (type == 1) {
                PCHAR s = p + len;
                for (int idx = 0; idx < 6; ++idx) {
                    size_t slen = strnlen(s, 64);
                    if (slen == 0) break;
                    if (slen >= 8) {
                        CHAR news[64];
                        SpfsGenAscii(news, (ULONG)slen);
                        news[slen] = '\0';
                        RtlCopyMemory(s, news, slen + 1); // include NUL terminator
                    }
                    s += slen + 1;
                }
            }
            PCHAR s = p + len;
            while (*s) s = s + strlen(s) + 1;
            s += 2;
            walk = (ULONG)(s - table);
            p = s;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
}

// ---------- registry identity ----------
static VOID SpfsWriteRegistryIdentity(void) {
    CHAR manuf[40] = "ASUS PQ Systems";
    CHAR prod[40]  = "PQ PLATFORM Z9";
    CHAR vend[40]  = "AMI PQ";
    CHAR date[40]  = "01/01/2025";
    CHAR ver[40]; SpfsGenAscii(ver, 12); ver[12] = 0;
    CHAR guid[64];
    RtlStringCchPrintfA(guid, sizeof(guid), "%08X-%04X-4%03X-8%03X-%012X",
              SpfsRand(), SpfsRand() & 0xFFFF, SpfsRand() & 0xFFF, SpfsRand() & 0xFFF, SpfsRand() % 1000000000000ULL);

    WCHAR wmanuf[40], wprod[40], wvend[40], wver[40], wdate[40], wguid[64];
    for (int i = 0; i < 40; ++i) { wmanuf[i] = (WCHAR)manuf[i]; if (!manuf[i]) break; }
    for (int i = 0; i < 40; ++i) { wprod[i] = (WCHAR)prod[i]; if (!prod[i]) break; }
    for (int i = 0; i < 40; ++i) { wvend[i] = (WCHAR)vend[i]; if (!vend[i]) break; }
    for (int i = 0; i < 40; ++i) { wver[i] = (WCHAR)ver[i]; if (!ver[i]) break; }
    for (int i = 0; i < 40; ++i) { wdate[i] = (WCHAR)date[i]; if (!date[i]) break; }
    for (int i = 0; i < 64; ++i) { wguid[i] = (WCHAR)guid[i]; if (!guid[i]) break; }

    PCWSTR biosRoot = L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS";
    SpfsSetStringRoot(biosRoot, L"SystemManufacturer", wmanuf);
    SpfsSetStringRoot(biosRoot, L"SystemProductName", wprod);
    SpfsSetStringRoot(biosRoot, L"BIOSVendor", wvend);
    SpfsSetStringRoot(biosRoot, L"BIOSVersion", wver);
    SpfsSetStringRoot(biosRoot, L"BIOSReleaseDate", wdate);

    PCWSTR siRoot = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation";
    SpfsSetStringRoot(siRoot, L"SystemManufacturer", wmanuf);
    SpfsSetStringRoot(siRoot, L"SystemProductName", wprod);
    SpfsSetStringRoot(siRoot, L"BIOSVendor", wvend);
    SpfsSetStringRoot(siRoot, L"BIOSVersion", wver);

    PCWSTR crypt = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography";
    SpfsSetStringRoot(crypt, L"MachineGuid", wguid);

    // TPM disable — anticheats see no TPM anchor this boot
    SpfsSetDwordRoot(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\tpm", L"Start", 4);
}

// ---------- spoof entry ----------
static VOID SpfsDoSpoof(void) {
    SpfsPatchAllDisks();
    SpfsPatchSmbios();
    SpfsWriteRegistryIdentity();
}

// ---------- dispatch ----------
static NTSTATUS SpfsCreateClose(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS SpfsDeviceControl(PDEVICE_OBJECT dev, PIRP irp) {
    SPFS_CONTEXT* ctx = (SPFS_CONTEXT*)dev->DeviceExtension;
    PIO_STACK_LOCATION st = IoGetCurrentIrpStackLocation(irp);
    ULONG code = st->Parameters.DeviceIoControl.IoControlCode;

    if (code == IOCTL_CACHE_AND_SPOOF) {
        SpfsDoSpoof();
        ctx->spoofed = TRUE;
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
    } else if (code == IOCTL_STATUS) {
        PULONG o = (PULONG)irp->AssociatedIrp.SystemBuffer;
        if (o && st->Parameters.DeviceIoControl.OutputBufferLength >= 4) {
            *o = ctx->spoofed ? 1 : 0;
            irp->IoStatus.Information = 4;
        }
        irp->IoStatus.Status = STATUS_SUCCESS;
    } else {
        irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        irp->IoStatus.Information = 0;
    }
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}

// ---------- entry ----------
NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    UNREFERENCED_PARAMETER(reg);
    g_state ^= (ULONG)(uintptr_t)drv;

    drv->MajorFunction[IRP_MJ_CREATE] = SpfsCreateClose;
    drv->MajorFunction[IRP_MJ_CLOSE] = SpfsCreateClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SpfsDeviceControl;
    drv->DriverUnload = NULL;

    UNICODE_STRING dn = RTL_CONSTANT_STRING(SPFS_DEVICE_NAME);
    PDEVICE_OBJECT dev = NULL;
    NTSTATUS st = IoCreateDevice(drv, sizeof(SPFS_CONTEXT), &dn, FILE_DEVICE_UNKNOWN, 0, FALSE, &dev);
    if (!NT_SUCCESS(st)) return st;

    UNICODE_STRING sl = RTL_CONSTANT_STRING(SPFS_SYMLINK);
    IoCreateSymbolicLink(&sl, &dn);

    SPFS_CONTEXT* ctx = (SPFS_CONTEXT*)dev->DeviceExtension;
    ctx->self = dev;
    ctx->spoofed = FALSE;

    SpfsDoSpoof();
    ctx->spoofed = TRUE;

    return STATUS_SUCCESS;
}
