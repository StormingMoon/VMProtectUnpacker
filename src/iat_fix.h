#pragma once
//
// IAT scanner
//

#include "common.h"

struct ImportEntry {
    std::string dll_name;
    std::string func_name;
    uint32_t    rva;            // RVA of IAT slot
    uint64_t    current_value;  // what currently sits in the IAT slot
    bool        resolved;       // do we recognise it?
};

class IATScanner {
public:
    IATScanner(const std::string& pe_path, const PEInfo& original_pe);
    void scan_and_report();

private:
    std::string   m_path;
    const PEInfo& m_pe;
    std::vector<uint8_t> m_data;

    bool load();
    uint32_t rva_to_offset(uint32_t rva) const;
    std::string read_sz(uint32_t offset) const;
};
