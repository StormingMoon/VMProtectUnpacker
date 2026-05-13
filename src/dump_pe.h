#pragma once
/*
 * dump_pe.h  –  PE reconstruction from dumped memory regions
 */
#include "common.h"

// ──────────────────────────────────────────────────────────────────────────────
// PERebuilder
// ──────────────────────────────────────────────────────────────────────────────
class PERebuilder {
public:
    PERebuilder(const std::string& original_path,
                const PEInfo&     pe_info,
                const MemoryDump& dump);

    void set_oep(uint32_t oep_rva) { m_oep_rva = oep_rva; }

    // Reconstruct and write the output PE
    bool rebuild(const std::string& out_path);

private:
    std::string       m_orig_path;
    const PEInfo&     m_pe;
    const MemoryDump& m_dump;
    uint32_t          m_oep_rva = 0;

    // The working copy of the on-disk file
    std::vector<uint8_t> m_image;

    bool load_original();
    bool patch_sections();
    bool patch_entry_point();
    bool write_out(const std::string& path);

    uint32_t align_to(uint32_t value, uint32_t alignment) const {
        return (value + alignment - 1) & ~(alignment - 1);
    }

    static void write_u32(uint8_t* p, uint32_t v) { memcpy(p, &v, 4); }
    static void write_u16(uint8_t* p, uint16_t v) { memcpy(p, &v, 2); }
    static uint32_t read_u32(const uint8_t* p) { uint32_t v; memcpy(&v,p,4); return v; }
    static uint16_t read_u16(const uint8_t* p) { uint16_t v; memcpy(&v,p,2); return v; }
};
