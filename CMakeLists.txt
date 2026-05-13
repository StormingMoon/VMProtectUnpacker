cmake_minimum_required(VERSION 3.16)
project(vmp_unpacker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Sources

set(SOURCES
    main.cpp
    common.cpp
    debugger.cpp
    antidebug.cpp
    dump_pe.cpp
    iat_fix.cpp
)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/HookLibraryx64.dll")
    list(APPEND SOURCES scyllahide_bundle.rc)
    message(STATUS "Embedding HookLibraryx64.dll into vmp_unpacker")
else()
    message(STATUS "HookLibraryx64.dll not found; building without bundled ScyllaHide")
endif()

# Executable

add_executable(vmp_unpacker ${SOURCES})

# Windows libs

target_link_libraries(vmp_unpacker PRIVATE
    kernel32
    user32
    psapi
    advapi32
)

# MSVC specific

if(MSVC)
    target_compile_options(vmp_unpacker PRIVATE /O2 /W3 /EHsc)
    target_compile_definitions(vmp_unpacker PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    # Force x64
    set_target_properties(vmp_unpacker PROPERTIES
        LINK_FLAGS "/MACHINE:X64 /SUBSYSTEM:CONSOLE"
    )
endif()

message(STATUS "Configure done. Build with: cmake --build . --config Release")
