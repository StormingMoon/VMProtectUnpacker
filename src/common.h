#pragma once
//
// Shared types
//


#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <cstdint>
#include <cstdio>
#include <cassert>


struct SectionInfo {
    char     name[9];          // null-terminated
    uint32_t vaddr;            // RVA
    uint32_t vsize;
    uint32_t raw_offset;       // 0 = virtual-only (to be dumped)
    uint32_t raw_size;
    uint32_t flags;

    bool is_virtual() const { return raw_size == 0; }
    bool is_executable() const { return (flags & 0x20000000) != 0; }
};


struct PEInfo {
    std::string              path;
    bool                     is_64bit;
    uint64_t                 image_base;
    uint32_t                 ep_rva;
    uint32_t                 image_size;
    uint16_t                 characteristics = 0;   // PE Characteristics field
    std::vector<SectionInfo> sections;
    // VMP-specific
    uint32_t loader_section_va     = 0;
    uint32_t loader_section_end_va = 0;
    std::string loader_section_name;

    int virtual_section_count() const {
        int n = 0;
        for (auto& s : sections) if (s.is_virtual()) n++;
        return n;
    }

    const SectionInfo* section_for_rva(uint32_t rva) const {
        for (auto& s : sections) {
            uint32_t end = s.vaddr + std::max(s.vsize, s.raw_size);
            if (rva >= s.vaddr && rva < end)
                return &s;
        }
        return nullptr;
    }
};


struct MemRegion {
    uint64_t             base_va;    // virtual address in child
    uint32_t             rva;        // relative to image base
    std::vector<uint8_t> data;
    std::string          section_name;
};

struct MemoryDump {
    std::vector<MemRegion> regions;
    size_t total_bytes() const {
        size_t n = 0;
        for (auto& r : regions) n += r.data.size();
        return n;
    }
    const MemRegion* region_for_rva(uint32_t rva, size_t size = 0) const {
        for (auto& r : regions)
            if (r.rva <= rva && rva < r.rva + r.data.size())
                return &r;
        return nullptr;
    }
};


bool parse_pe_header(const char* path, PEInfo& out);
