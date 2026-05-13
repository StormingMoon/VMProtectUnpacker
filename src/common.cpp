//
// PE parsing
//


#include "common.h"
#include <cmath>
#include <algorithm>



static double calc_entropy(const uint8_t* buf, size_t len)
{
    if (!len) return 0.0;
    unsigned cnt[256] = {};
    for (size_t i = 0; i < len; i++) cnt[buf[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; i++) {
        if (cnt[i]) {
            double p = (double)cnt[i] / (double)len;
            e -= p * log2(p);
        }
    }
    return e;
}

static uint32_t read_u32(const uint8_t* p) { uint32_t v; memcpy(&v,p,4); return v; }
static uint16_t read_u16(const uint8_t* p) { uint16_t v; memcpy(&v,p,2); return v; }
static uint64_t read_u64(const uint8_t* p) { uint64_t v; memcpy(&v,p,8); return v; }


bool parse_pe_header(const char* path, PEInfo& out)
{
    out.path = path;

    // Read file
    FILE* f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "[-] Cannot open '%s'\n", path); return false; }
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);
    std::vector<uint8_t> data((size_t)file_size);
    if (fread(data.data(), 1, (size_t)file_size, f) != (size_t)file_size) {
        fclose(f); fprintf(stderr, "[-] Read error\n"); return false;
    }
    fclose(f);

    const uint8_t* p = data.data();

    // MZ check
    if (file_size < 0x40 || p[0] != 'M' || p[1] != 'Z') {
        fprintf(stderr, "[-] Not a valid PE (bad MZ)\n"); return false;
    }

    uint32_t pe_off = read_u32(p + 0x3C);
    if (pe_off + 24 > (uint32_t)file_size) {
        fprintf(stderr, "[-] PE offset out of range\n"); return false;
    }
    if (memcmp(p + pe_off, "PE\0\0", 4)) {
        fprintf(stderr, "[-] PE signature not found\n"); return false;
    }

    (void)read_u16(p + pe_off + 4);            // machine (unused directly)
    uint16_t num_sections  = read_u16(p + pe_off + 6);
    out.characteristics    = read_u16(p + pe_off + 22); // IMAGE_FILE_HEADER.Characteristics
    uint16_t opt_size      = read_u16(p + pe_off + 20);
    uint16_t opt_magic     = read_u16(p + pe_off + 24);

    out.is_64bit = (opt_magic == 0x20B);

    // Entry point, image base, image size
    out.ep_rva  = read_u32(p + pe_off + 24 + 16);
    if (out.is_64bit) {
        out.image_base  = read_u64(p + pe_off + 24 + 24);
        out.image_size  = read_u32(p + pe_off + 24 + 56);
    } else {
        out.image_base  = read_u32(p + pe_off + 24 + 28);
        out.image_size  = read_u32(p + pe_off + 24 + 52);
    }

    // Section table
    uint32_t sec_tbl = pe_off + 24 + opt_size;
    if (sec_tbl + (uint32_t)num_sections * 40 > (uint32_t)file_size) {
        fprintf(stderr, "[-] Section table truncated\n"); return false;
    }

    // Find best loader section: highest entropy, has raw data, EP inside OR
    // name has non-printable chars (VMP 3.x obfuscated names)
    double best_score = -1.0;
    int    loader_idx = -1;

    for (int i = 0; i < num_sections; i++) {
        const uint8_t* sh = p + sec_tbl + i * 40;

        SectionInfo si;
        memcpy(si.name, sh, 8);
        si.name[8]      = '\0';
        si.vsize        = read_u32(sh + 8);
        si.vaddr        = read_u32(sh + 12);
        si.raw_size     = read_u32(sh + 16);
        si.raw_offset   = read_u32(sh + 20);
        si.flags        = read_u32(sh + 36);
        out.sections.push_back(si);

        if (si.raw_size < 0x1000) continue;   // skip tiny / empty sections

        uint32_t sample_sz = std::min((uint32_t)65536, si.raw_size);
        double e = calc_entropy(p + si.raw_offset, sample_sz);

        // Score: entropy × raw_size (in MB) — larger + more random wins
        double score = e * ((double)si.raw_size / (1024.0 * 1024.0));

        // Bonus if EP is inside this section
        uint32_t sec_end = si.vaddr + std::max(si.vsize, si.raw_size);
        if (out.ep_rva >= si.vaddr && out.ep_rva < sec_end) score *= 3.0;

        if (score > best_score) {
            best_score  = score;
            loader_idx  = i;
        }
    }

    if (loader_idx >= 0) {
        auto& ls = out.sections[loader_idx];
        out.loader_section_name   = ls.name;
        out.loader_section_va     = ls.vaddr;
        out.loader_section_end_va = ls.vaddr + std::max(ls.vsize, ls.raw_size);
        printf("[*] Identified VMP loader: section[%d] '%s'  "
               "VA=0x%X  entropy=%.2f\n",
               loader_idx, ls.name, ls.vaddr, best_score / ((double)ls.raw_size/(1024.0*1024.0)));
    } else {
        fprintf(stderr, "[!] Could not identify VMP loader section\n");
    }

    return true;
}
