// cli.cpp — pqspoof.exe command-line front (same engine the UI uses)
#include "engine.h"
#include <cstdio>
#include <string>

int main(int argc, char** argv) {
    using namespace engine;
    SetLog([](const char* level, const char* msg) {
        printf("[%hs] %hs\n", level, msg);
    });

    uint32_t mask = 0;
    bool routeA = false, vol = false, restore = false, restoreSilent = false, install = false, bootVava = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--vava")   mask |= VAVA;
        if (a == "--roblox") mask |= ROBLOX;
        if (a == "--mine")   mask |= MINE;
        if (a == "--all")    mask |= ALL;
        if (a == "--route-a")     routeA = true;
        if (a == "--vol")         vol = true;
        if (a == "--restore")     restore = true;
        if (a == "--restore-on-boot") restoreSilent = true;
        if (a == "--install-boot")    install = true;
        if (a == "--vanguard-boot")   bootVava = true;
    }

    if (restoreSilent) return RestoreOnBootSilent();
    if (restore)       return Restore();
    if (install)       return InstallBootDriver();
    if (bootVava)      return SetVanguardBoot(true);

    if (!mask) {
        printf("usage: pqspoof [--roblox|--mine|--vava|--all] [--route-a] [--vol] [--restore] [--install-boot] [--vanguard-boot]\n");
        return 0;
    }
    return Spoof(mask, routeA, vol);
}
