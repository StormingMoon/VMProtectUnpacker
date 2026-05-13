//
// IAT scanner
//

#include "iat_fix.h"
#include <cstdio>
#include <cstring>


static uint32_t u32(const uint8_t* p) { uint32_t v; memcpy(&v,p,4); return v; }
static uint16_t u16(const uint8_t* p) { uint16_t v; memcpy(&v,p,2); return v; }
static uint64_t u64(const uint8_t* p) { uint64_t v; memcpy(&v,p,8); return v; }


IATScanner::IATScanner(const std::string& pe_path, const PEInfo& original_pe)
    : m_path(pe_path), m_pe(original_pe) {}

bool IATScanner::load()
{
    FILE* f = fopen(m_path.c_str(), "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    size_t sz = (size_t)ftell(f);
    rewind(f);
    m_data.resize(sz);
    bool ok = fread(m_data.data(), 1, sz, f) == sz;
    fclose(f);
    return ok;
}

uint32_t IATScanner::rva_to_offset(uint32_t rva) const
{
    const uint8_t* p = m_data.data();
    uint32_t pe_off  = u32(p + 0x3C);
    uint16_t n_sec   = u16(p + pe_off + 6);
    uint16_t opt_sz  = u16(p + pe_off + 20);
    uint32_t sec_tbl = pe_off + 24 + opt_sz;
    for (int i = 0; i < (int)n_sec; i++) {
        const uint8_t* sh = p + sec_tbl + i * 40;
        uint32_t va   = u32(sh + 12);
        uint32_t vsz  = u32(sh + 8);
        uint32_t roff = u32(sh + 20);
        uint32_t rsz  = u32(sh + 16);
        if (rva >= va && rva < va + std::max(vsz, rsz) && rsz > 0)
            return roff + (rva - va);
    }
    return 0;
}

std::string IATScanner::read_sz(uint32_t offset) const
{
    if (offset >= m_data.size()) return "";
    std::string s;
    while (offset < m_data.size() && m_data[offset])
        s += (char)m_data[offset++];
    return s;
}


void IATScanner::scan_and_report()
{
    if (!load()) {
        fprintf(stderr, "[-] IATScanner: cannot load rebuilt PE\n");
        return;
    }

    const uint8_t* p = m_data.data();
    uint32_t pe_off  = u32(p + 0x3C);
    uint16_t opt_magic = u16(p + pe_off + 24);
    bool is64 = (opt_magic == 0x20B);

    // Data directory offset
    uint32_t dd_off = pe_off + 24 + (is64 ? 112 : 96);

    uint32_t imp_rva = u32(p + dd_off + 1 * 8);
    uint32_t imp_sz  = u32(p + dd_off + 1 * 8 + 4);

    if (!imp_rva) {
        puts("[!] No import directory found in rebuilt PE");
        return;
    }

    uint32_t imp_off = rva_to_offset(imp_rva);
    if (!imp_off) {
        puts("[!] Import directory RVA cannot be resolved");
        return;
    }

    // VMP loader section range (for trampoline detection)
    uint32_t vmp_start = m_pe.loader_section_va;
    uint32_t vmp_end   = m_pe.loader_section_end_va;

    int total = 0, vmp_thunks = 0, ok_thunks = 0;

    printf("%-30s  %-50s  %s\n", "DLL", "Function", "Status");
    printf("%s\n", std::string(100, '-').c_str());

    int i = 0;
    while (true) {
        const uint8_t* desc = p + imp_off + i * 20;
        if ((uint32_t)(i * 20 + 20) > imp_sz + 100) break;  // safety
        uint32_t orig_ft  = u32(desc);
        uint32_t name_rva = u32(desc + 12);
        uint32_t first_ft = u32(desc + 16);
        if (!orig_ft && !name_rva && !first_ft) break;

        uint32_t name_off = rva_to_offset(name_rva);
        std::string dll = name_off ? read_sz(name_off) : "<unknown>";

        // Walk thunks
        uint32_t thunk_rva = orig_ft ? orig_ft : first_ft;
        uint32_t iat_rva   = first_ft;
        int k = 0;
        while (true) {
            uint32_t thunk_off = rva_to_offset(thunk_rva + (is64 ? k*8 : k*4));
            uint32_t iat_off   = rva_to_offset(iat_rva   + (is64 ? k*8 : k*4));
            if (!thunk_off || !iat_off) break;

            uint64_t thunk_val = is64 ? u64(p + thunk_off) : u32(p + thunk_off);
            uint64_t iat_val   = is64 ? u64(p + iat_off)   : u32(p + iat_off);
            if (!thunk_val) break;

            // Determine function name
            std::string func;
            if (thunk_val & (is64 ? 0x8000000000000000ULL : 0x80000000ULL)) {
                // Ordinal import
                func = "ord#" + std::to_string(thunk_val & 0xFFFF);
            } else {
                uint32_t hint_rva = (uint32_t)(thunk_val & 0x7FFFFFFF);
                uint32_t hint_off = rva_to_offset(hint_rva);
                func = hint_off ? read_sz(hint_off + 2) : "<unknown>";
            }

            // Classify the IAT slot
            uint32_t iat_as_rva = (uint32_t)(iat_val - m_pe.image_base);
            bool is_vmp = (iat_as_rva >= vmp_start && iat_as_rva < vmp_end);
            const char* status = is_vmp ? "VMP_TRAMPOLINE" : "OK";

            if (is_vmp) vmp_thunks++; else ok_thunks++;
            total++;

            if (total <= 60 || is_vmp) {  // print first 60 + all VMP ones
                printf("%-30s  %-50s  %s\n",
                       dll.substr(0, 29).c_str(),
                       func.substr(0, 49).c_str(),
                       status);
            }
            k++;
        }
        i++;
    }

    printf("\n[+] IAT Summary: %d total  |  %d OK  |  %d VMP trampolines (need Scylla)\n",
           total, ok_thunks, vmp_thunks);

    if (vmp_thunks > 0) {
        puts("\n  To fix IAT trampolines:");
        puts("    1. Run x64dbg, attach to a process that has loaded the rebuilt PE");
        puts("    2. Open Scylla plugin → IAT Autosearch → Get Imports");
        puts("    3. Fix Dump on the rebuilt PE file");
        puts("    4. Save the fixed dump");
    }
}
