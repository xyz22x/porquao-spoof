# Porquao Spoof — user-mode targets (driver built separately by build.bat via WDK libs)
cmake_minimum_required(VERSION 3.24)
project(PorquaoSpoof LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

# shared engine sources (no main here — mains live in cli.cpp / ui/main.cpp)
set(ENGINE_SOURCES spoofer.cpp byovd.cpp)

# ---- pqspoof.exe — CLI front ----
add_executable(pqspoof cli.cpp ${ENGINE_SOURCES})
target_link_libraries(pqspoof PRIVATE advapi32 setupapi ntdll bcrypt psapi user32)
target_compile_options(pqspoof PRIVATE /W4 /permissive- /O2)

# ---- vulnscan.exe — standalone vulnerable-driver scanner (hash + table) ----
add_executable(vulnscan scanner.cpp)
target_link_libraries(vulnscan PRIVATE bcrypt advapi32 psapi ntdll user32)
target_compile_options(vulnscan PRIVATE /W4 /permissive- /O2)

# ---- PorquaoSpoof.exe — Qt6 native UI ----
find_package(Qt6 REQUIRED COMPONENTS Widgets)
qt_standard_project_setup()
add_executable(PorquaoSpoof WIN32
    ui/main.cpp
    ui/mainwindow.cpp
    ui/toggleswitch.cpp
    ${ENGINE_SOURCES}
)
target_link_libraries(PorquaoSpoof PRIVATE Qt6::Widgets advapi32 setupapi ntdll bcrypt psapi user32)
target_include_directories(PorquaoSpoof PRIVATE ${CMAKE_SOURCE_DIR})
target_compile_options(PorquaoSpoof PRIVATE /W4 /permissive- /O2)
