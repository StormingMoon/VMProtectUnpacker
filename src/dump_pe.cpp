//
// PE reconstruction logic
//


#include "dump_pe.h"
#include <algorithm>
#include <cstdio>


PERebuilder::PERebuilder(const std::string& original_path,
                         const PEInfo&      pe_info,
                         const MemoryDump&  dump)
    : m_orig_path(original_path), m_pe(pe_info), m_dump(dump)
{}


bool PERebuilder::load_original()
{
    FILE* f = fopen(m_orig_path.c_str(), "rb");
    if (!f) { fprintf(stderr, "[-] Cannot open original: %s\n", m_orig_path.c_str()); return false; }
    fseek(f, 0, SEEK_END);
    size_t sz = (size_t)ftell(f);
    rewind(f);
    m_image.resize(sz);
    bool ok = fread(m_image.data(), 1, sz, f) == sz;
    fclose(f);
    return ok;
}

// fix section headers and append data

bool PERebuilder::patch_sections()
{
    uint8_t* p      = m_image.data();
    uint32_t pe_off = read_u32(p + 0x3C);
    uint16_t opt_sz = read_u16(p + pe_off + 20);
    uint16_t n_sec  = read_u16(p + pe_off + 6);
    uint32_t sec_tbl = pe_off + 24 + opt_sz;

    // File alignment from optional header
    uint32_t file_align = read_u32(p + pe_off + 24 + 60);   // FileAlignment
    if (file_align == 0) file_align = 0x200;

    // Current end of file (we'll append after here)
    uint32_t file_end = (uint32_t)m_image.size();
    // Pad to file_align boundary
    uint32_t pad = align_to(file_end, file_align) - file_end;
    m_image.insert(m_image.end(), pad, 0x00);
    file_end = (uint32_t)m_image.size();
    p = m_image.data();

    int patched = 0;

    for (int i = 0; i < (int)n_sec; i++) {
        p = m_image.data();
        uint8_t* sh       = p + sec_tbl + i * 40;
        uint32_t raw_sz   = read_u32(sh + 16);
        uint32_t raw_off  = read_u32(sh + 20);
        uint32_t vaddr    = read_u32(sh + 12);
        uint32_t vsize    = read_u32(sh + 8);

        // Find the dump region for this section
        const MemRegion* region = m_dump.region_for_rva(vaddr);

        if (!region) {
            if (raw_sz != 0) {
                // If it already has data on disk and we didn't dump anything new, keep it
                continue;
            }
            fprintf(stderr, "[!] No dump data for virtual section[%d] '%.*s' (RVA=0x%X)\n",
                    i, 8, sh, vaddr);
            continue;
        }

        // Trim dump to virtual size (page-round)
        uint32_t actual_sz = std::min((uint32_t)region->data.size(), vsize);
        uint32_t aligned_sz = align_to(actual_sz, file_align);

        // Patch section header
        // p may be stale after resize – recompute
        p  = m_image.data();
        sh = p + sec_tbl + i * 40;
        char sec_name[9] = {};
        memcpy(sec_name, sh, 8);

        file_end = (uint32_t)m_image.size();
        write_u32(sh + 20, file_end);     // PointerToRawData
        write_u32(sh + 16, aligned_sz);   // SizeOfRawData

        // Append data
        m_image.insert(m_image.end(),
                        region->data.data(),
                        region->data.data() + actual_sz);
        // Pad to file alignment
        uint32_t padding = aligned_sz - actual_sz;
        m_image.insert(m_image.end(), padding, 0x00);

        printf("    Patched section '%s'  RawOff=0x%X  RawSz=0x%X\n",
               sec_name, file_end, aligned_sz);
        patched++;
    }

    printf("[+] Patched %d virtual sections\n", patched);
    return patched > 0;
}


bool PERebuilder::patch_entry_point()
{
    if (m_oep_rva == 0) return false;

    uint8_t* p      = m_image.data();
    uint32_t pe_off = read_u32(p + 0x3C);
    // AddressOfEntryPoint is at pe_off + 24 + 16
    uint32_t old_ep = read_u32(p + pe_off + 24 + 16);
    write_u32(p + pe_off + 24 + 16, m_oep_rva);

    printf("[*] Entry point patched: 0x%X → 0x%X\n", old_ep, m_oep_rva);
    return true;
}


bool PERebuilder::write_out(const std::string& path)
{
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) { fprintf(stderr, "[-] Cannot create output: %s\n", path.c_str()); return false; }
    bool ok = fwrite(m_image.data(), 1, m_image.size(), f) == m_image.size();
    fclose(f);
    if (ok) printf("[+] Written %zu bytes to '%s'\n", m_image.size(), path.c_str());
    return ok;
}


bool PERebuilder::rebuild(const std::string& out_path)
{
    if (!load_original()) return false;

    // Also fix SizeOfImage in case our appended sections push it beyond
    // the original headers' declared size
    uint8_t* p      = m_image.data();
    uint32_t pe_off = read_u32(p + 0x3C);
    uint16_t opt_sz = read_u16(p + pe_off + 20);
    uint32_t sec_align = read_u32(p + pe_off + 24 + 56);  // SectionAlignment
    if (sec_align == 0) sec_align = 0x1000;

    if (!patch_sections()) return false;
    patch_entry_point();

    // Recalculate SizeOfImage
    p = m_image.data();
    uint32_t max_end = 0;
    uint16_t n_sec   = read_u16(p + pe_off + 6);
    uint32_t sec_tbl = pe_off + 24 + opt_sz;
    for (int i = 0; i < (int)n_sec; i++) {
        uint8_t* sh   = p + sec_tbl + i * 40;
        uint32_t va   = read_u32(sh + 12);
        uint32_t vsz  = read_u32(sh + 8);
        uint32_t end  = align_to(va + vsz, sec_align);
        if (end > max_end) max_end = end;
    }
    write_u32(p + pe_off + 24 + 56, max_end);
    printf("[*] SizeOfImage updated to 0x%X\n", max_end);

    return write_out(out_path);
}
