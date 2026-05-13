#pragma once
//
// Debug engine
//


#include "common.h"
#include "antidebug.h"
#include <unordered_map>
#include <unordered_set>



struct Breakpoint {
    uint64_t address;
    uint8_t  saved_byte;   // original byte before INT3 patch
    bool     active;
    std::string label;
};


class Debugger {
public:
    explicit Debugger(const std::string& target_path, const PEInfo& pe_info,
                      const std::string& scylla_hide_path = "");
    ~Debugger();

    // Spawn child process with DEBUG_PROCESS flag
    bool launch();

    // Run the debug loop until OEP is reached.
    bool run_until_oep(DWORD& oep_rva, DWORD64& oep_abs);

    // Dump all virtual sections from child memory into a MemoryDump
    bool dump_sections(MemoryDump& out);

    void kill();

private:
    std::string   m_target;
    const PEInfo& m_pe;

    HANDLE  m_hProcess  = INVALID_HANDLE_VALUE;
    HANDLE  m_hThread   = INVALID_HANDLE_VALUE;
    DWORD   m_pid       = 0;
    DWORD   m_tid       = 0;
    uint64_t m_image_base_child = 0;
    std::string m_scylla_hide_path;

    // Anti-debug bypass engine (created after process spawned)
    AntiDebugBypass* m_adb = nullptr;

    // breakpoints

    std::unordered_map<uint64_t, Breakpoint> m_breakpoints;

    bool set_bp(uint64_t va, const char* label);
    bool remove_bp(uint64_t va);
    void restore_bp(uint64_t va);        // re-arm after single-step

    // handlers

    enum class BpAction { Continue, OEPReached, Error };
    BpAction on_breakpoint(DWORD thread_id, uint64_t va,
                            DWORD& oep_rva, DWORD64& oep_abs);

    // hook addresses

    uint64_t m_va_VirtualAlloc   = 0;
    uint64_t m_va_VirtualProtect = 0;
    uint64_t m_va_VirtualAllocEx = 0;
    uint64_t m_va_VirtualProtectEx = 0;
    uint64_t m_va_NtAllocateVirtualMemory = 0;
    uint64_t m_va_NtProtectVirtualMemory = 0;
    uint64_t m_va_NtQueryInformationProcess = 0;
    uint64_t m_va_NtQuerySystemInformation = 0;
    uint64_t m_va_NtSetInformationThread = 0;
    uint64_t m_va_IsDebuggerPresent = 0;
    uint64_t m_va_CheckRemoteDebuggerPresent = 0;
    uint64_t m_va_OutputDebugStringA = 0;
    uint64_t m_va_OutputDebugStringW = 0;
    uint64_t m_va_MessageBoxA = 0;
    uint64_t m_va_MessageBoxW = 0;
    uint64_t m_va_MessageBoxExA = 0;
    uint64_t m_va_MessageBoxExW = 0;
    uint64_t m_va_MessageBoxTimeoutA = 0;
    uint64_t m_va_MessageBoxTimeoutW = 0;
    uint64_t m_va_MessageBoxIndirectA = 0;
    uint64_t m_va_MessageBoxIndirectW = 0;

    bool resolve_and_hook_apis();

    // OEP hunt state

    std::unordered_map<uint32_t, MemRegion> m_captured_regions; // RVA -> data
    std::unordered_set<uint64_t> m_executable_pages;  // pages marked exec by VMP
    int   m_expected_virtual_secs = 0;
    int   m_populated_secs        = 0;
    bool  m_oep_hunting           = false;     // true after all secs populated
    uint64_t m_single_step_after  = 0;         // VA of BP to restore after step

    // memory access

    bool read_mem(uint64_t va, void* buf, size_t len);
    bool write_mem(uint64_t va, const void* buf, size_t len);

    // context helpers

    bool get_context(DWORD tid, CONTEXT& ctx);
    bool set_context(DWORD tid, CONTEXT& ctx);
    void enable_single_step(DWORD tid);

    // VA/RVA helpers

    uint32_t to_rva(uint64_t va) const {
        return (uint32_t)(va - m_image_base_child);
    }
    uint64_t to_va(uint32_t rva) const {
        return m_image_base_child + rva;
    }

    bool is_in_loader(uint64_t va) const {
        uint32_t rva = to_rva(va);
        return rva >= m_pe.loader_section_va && rva < m_pe.loader_section_end_va;
    }
};
