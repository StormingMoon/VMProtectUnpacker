//
// Debug engine logic
//


#include "debugger.h"
#include <algorithm>
#include <cstdio>

static const DWORD DEBUG_TIMEOUT_MS = 120'000; // 2 minutes max
static const DWORD DEBUG_IDLE_LOG_MS = 5'000;
static const DWORD DEBUG_IDLE_TIMEOUT_MS = 45'000;


Debugger::Debugger(const std::string &target_path, const PEInfo &pe_info,
                   const std::string &scylla_hide_path)
    : m_target(target_path), m_pe(pe_info),
      m_scylla_hide_path(scylla_hide_path) {
  m_expected_virtual_secs = pe_info.virtual_section_count();
}

Debugger::~Debugger() { kill(); }


bool Debugger::read_mem(uint64_t va, void *buf, size_t len) {
  SIZE_T read = 0;
  return ReadProcessMemory(m_hProcess, (LPCVOID)va, buf, len, &read) &&
         read == len;
}

bool Debugger::write_mem(uint64_t va, const void *buf, size_t len) {
  DWORD old;
  VirtualProtectEx(m_hProcess, (LPVOID)va, len, PAGE_EXECUTE_READWRITE, &old);
  SIZE_T written = 0;
  bool ok = WriteProcessMemory(m_hProcess, (LPVOID)va, buf, len, &written) &&
            written == len;
  VirtualProtectEx(m_hProcess, (LPVOID)va, len, old, &old);
  FlushInstructionCache(m_hProcess, (LPCVOID)va, len);
  return ok;
}


bool Debugger::get_context(DWORD tid, CONTEXT &ctx) {
  HANDLE ht = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                             THREAD_SUSPEND_RESUME,
                         FALSE, tid);
  if (!ht)
    return false;
  ctx.ContextFlags = CONTEXT_ALL;
  bool ok = GetThreadContext(ht, &ctx) != FALSE;
  CloseHandle(ht);
  return ok;
}

bool Debugger::set_context(DWORD tid, CONTEXT &ctx) {
  HANDLE ht = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                             THREAD_SUSPEND_RESUME,
                         FALSE, tid);
  if (!ht)
    return false;
  bool ok = SetThreadContext(ht, &ctx) != FALSE;
  CloseHandle(ht);
  return ok;
}

void Debugger::enable_single_step(DWORD tid) {
  CONTEXT ctx = {};
  get_context(tid, ctx);
  ctx.EFlags |= 0x100; // Trap Flag
  set_context(tid, ctx);
}


bool Debugger::set_bp(uint64_t va, const char *label) {
  auto existing = m_breakpoints.find(va);
  if (existing != m_breakpoints.end()) {
    if (existing->second.active)
      return true;
    uint8_t int3 = 0xCC;
    if (!write_mem(va, &int3, 1))
      return false;
    existing->second.active = true;
    return true;
  }

  uint8_t saved = 0;
  if (!read_mem(va, &saved, 1))
    return false;
  uint8_t int3 = 0xCC;
  if (!write_mem(va, &int3, 1))
    return false;
  m_breakpoints[va] = {va, saved, true, label ? label : ""};
  return true;
}

bool Debugger::remove_bp(uint64_t va) {
  auto it = m_breakpoints.find(va);
  if (it == m_breakpoints.end())
    return false;
  write_mem(va, &it->second.saved_byte, 1);
  it->second.active = false;
  return true;
}

void Debugger::restore_bp(uint64_t va) {
  auto it = m_breakpoints.find(va);
  if (it == m_breakpoints.end())
    return;
  uint8_t int3 = 0xCC;
  write_mem(va, &int3, 1);
  it->second.active = true;
}


bool Debugger::launch() {
  bool is_dll = (m_pe.characteristics & 0x2000) != 0;

  char cmdline[MAX_PATH * 2] = {};
  if (is_dll) {
    char self_path[MAX_PATH] = {};
    char target_path[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, self_path, MAX_PATH);
    DWORD n = GetFullPathNameA(m_target.c_str(), MAX_PATH, target_path, nullptr);
    const char *dll_path = (n > 0 && n < MAX_PATH) ? target_path : m_target.c_str();
    if (!m_scylla_hide_path.empty()) {
      snprintf(cmdline, sizeof(cmdline), "\"%s\" --host-dll \"%s\" \"%s\"",
               self_path, dll_path, m_scylla_hide_path.c_str());
    } else {
      snprintf(cmdline, sizeof(cmdline), "\"%s\" --host-dll \"%s\"",
               self_path, dll_path);
    }
  } else {
    snprintf(cmdline, sizeof(cmdline), "\"%s\"", m_target.c_str());
  }

  STARTUPINFOA si = {};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi = {};

  DWORD flags = DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE;

  if (!CreateProcessA(nullptr, cmdline, nullptr, nullptr, FALSE, flags, nullptr,
                      nullptr, &si, &pi)) {
    fprintf(stderr, "[-] CreateProcess failed: %lu\n", GetLastError());
    return false;
  }

  m_hProcess = pi.hProcess;
  m_hThread = pi.hThread;
  m_pid = pi.dwProcessId;
  m_tid = pi.dwThreadId;

  printf("[*] Child PID=%lu  TID=%lu\n", m_pid, m_tid);
  return true;
}


bool Debugger::resolve_and_hook_apis() {
  if (GetEnvironmentVariableA("VMP_UNPACKER_NO_API_BPS", nullptr, 0) > 0)
    return true;

  HANDLE snap =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid);
  if (snap == INVALID_HANDLE_VALUE)
    return false;

  uint64_t k32_base = 0;
  uint64_t ntdll_base = 0;
  uint64_t user32_base = 0;
  MODULEENTRY32W me = {};
  me.dwSize = sizeof(me);
  if (Module32FirstW(snap, &me)) {
    do {
      if (_wcsicmp(me.szModule, L"KERNEL32.DLL") == 0) {
        k32_base = (uint64_t)me.modBaseAddr;
      } else if (_wcsicmp(me.szModule, L"ntdll.dll") == 0) {
        ntdll_base = (uint64_t)me.modBaseAddr;
      } else if (_wcsicmp(me.szModule, L"user32.dll") == 0) {
        user32_base = (uint64_t)me.modBaseAddr;
      }
    } while (Module32NextW(snap, &me));
  }
  CloseHandle(snap);

  HMODULE local_k32 = GetModuleHandleW(L"KERNEL32.DLL");
  HMODULE local_nt = GetModuleHandleW(L"ntdll.dll");
  HMODULE local_user32 = GetModuleHandleW(L"user32.dll");
  if (!local_user32 && user32_base)
    local_user32 = LoadLibraryW(L"user32.dll");

  auto va_offset = [&](HMODULE local_mod, uint64_t child_base, const char *fn) -> uint64_t {
    if (!local_mod || !child_base) return 0;
    FARPROC local_fn = GetProcAddress(local_mod, fn);
    if (!local_fn)
      return 0;
    uint64_t offset = (uint64_t)local_fn - (uint64_t)local_mod;
    return child_base + offset;
  };

  if (k32_base) {
    m_va_VirtualAlloc = va_offset(local_k32, k32_base, "VirtualAlloc");
    m_va_VirtualProtect = va_offset(local_k32, k32_base, "VirtualProtect");
    m_va_VirtualAllocEx = va_offset(local_k32, k32_base, "VirtualAllocEx");
    m_va_VirtualProtectEx = va_offset(local_k32, k32_base, "VirtualProtectEx");
  }

  if (ntdll_base) {
    m_va_NtAllocateVirtualMemory = va_offset(local_nt, ntdll_base, "NtAllocateVirtualMemory");
    m_va_NtProtectVirtualMemory = va_offset(local_nt, ntdll_base, "NtProtectVirtualMemory");
    m_va_NtQueryInformationProcess = va_offset(local_nt, ntdll_base, "NtQueryInformationProcess");
    m_va_NtQuerySystemInformation = va_offset(local_nt, ntdll_base, "NtQuerySystemInformation");
    m_va_NtSetInformationThread = va_offset(local_nt, ntdll_base, "NtSetInformationThread");
  }

  if (k32_base) {
    m_va_IsDebuggerPresent = va_offset(local_k32, k32_base, "IsDebuggerPresent");
    m_va_CheckRemoteDebuggerPresent =
        va_offset(local_k32, k32_base, "CheckRemoteDebuggerPresent");
    m_va_OutputDebugStringA = va_offset(local_k32, k32_base, "OutputDebugStringA");
    m_va_OutputDebugStringW = va_offset(local_k32, k32_base, "OutputDebugStringW");
  }

  if (user32_base) {
    m_va_MessageBoxA = va_offset(local_user32, user32_base, "MessageBoxA");
    m_va_MessageBoxW = va_offset(local_user32, user32_base, "MessageBoxW");
    m_va_MessageBoxExA = va_offset(local_user32, user32_base, "MessageBoxExA");
    m_va_MessageBoxExW = va_offset(local_user32, user32_base, "MessageBoxExW");
    m_va_MessageBoxTimeoutA =
        va_offset(local_user32, user32_base, "MessageBoxTimeoutA");
    m_va_MessageBoxTimeoutW =
        va_offset(local_user32, user32_base, "MessageBoxTimeoutW");
    m_va_MessageBoxIndirectA =
        va_offset(local_user32, user32_base, "MessageBoxIndirectA");
    m_va_MessageBoxIndirectW =
        va_offset(local_user32, user32_base, "MessageBoxIndirectW");
  }

  if (m_va_VirtualAlloc) set_bp(m_va_VirtualAlloc, "VirtualAlloc");
  if (m_va_VirtualProtect) set_bp(m_va_VirtualProtect, "VirtualProtect");
  if (m_va_VirtualAllocEx) set_bp(m_va_VirtualAllocEx, "VirtualAllocEx");
  if (m_va_VirtualProtectEx) set_bp(m_va_VirtualProtectEx, "VirtualProtectEx");
  if (m_va_NtAllocateVirtualMemory) set_bp(m_va_NtAllocateVirtualMemory, "NtAllocateVirtualMemory");
  if (m_va_NtProtectVirtualMemory) set_bp(m_va_NtProtectVirtualMemory, "NtProtectVirtualMemory");
  if (m_va_NtQueryInformationProcess) set_bp(m_va_NtQueryInformationProcess, "NtQueryInformationProcess");
  if (m_va_NtQuerySystemInformation) set_bp(m_va_NtQuerySystemInformation, "NtQuerySystemInformation");
  if (m_va_NtSetInformationThread) set_bp(m_va_NtSetInformationThread, "NtSetInformationThread");
  if (m_va_IsDebuggerPresent) set_bp(m_va_IsDebuggerPresent, "IsDebuggerPresent");
  if (m_va_CheckRemoteDebuggerPresent) set_bp(m_va_CheckRemoteDebuggerPresent, "CheckRemoteDebuggerPresent");
  if (m_va_OutputDebugStringA) set_bp(m_va_OutputDebugStringA, "OutputDebugStringA");
  if (m_va_OutputDebugStringW) set_bp(m_va_OutputDebugStringW, "OutputDebugStringW");
  if (m_va_MessageBoxA) set_bp(m_va_MessageBoxA, "MessageBoxA");
  if (m_va_MessageBoxW) set_bp(m_va_MessageBoxW, "MessageBoxW");
  if (m_va_MessageBoxExA) set_bp(m_va_MessageBoxExA, "MessageBoxExA");
  if (m_va_MessageBoxExW) set_bp(m_va_MessageBoxExW, "MessageBoxExW");
  if (m_va_MessageBoxTimeoutA) set_bp(m_va_MessageBoxTimeoutA, "MessageBoxTimeoutA");
  if (m_va_MessageBoxTimeoutW) set_bp(m_va_MessageBoxTimeoutW, "MessageBoxTimeoutW");
  if (m_va_MessageBoxIndirectA) set_bp(m_va_MessageBoxIndirectA, "MessageBoxIndirectA");
  if (m_va_MessageBoxIndirectW) set_bp(m_va_MessageBoxIndirectW, "MessageBoxIndirectW");

  return (m_va_VirtualProtect != 0 || m_va_NtProtectVirtualMemory != 0);
}


Debugger::BpAction Debugger::on_breakpoint(DWORD thread_id, uint64_t va,
                                           DWORD &oep_rva, DWORD64 &oep_abs) {
  auto it = m_breakpoints.find(va);
  if (it == m_breakpoints.end())
    return BpAction::Continue;

  std::string lbl = it->second.label;

  CONTEXT ctx = {};
  get_context(thread_id, ctx);
  ctx.Rip--;
  remove_bp(va);

  auto skip_function = [&](uint64_t return_value) -> bool {
    uint64_t ret_addr = 0;
    if (!read_mem(ctx.Rsp, &ret_addr, sizeof(ret_addr)))
      return false;
    ctx.Rax = return_value;
    ctx.Rip = ret_addr;
    ctx.Rsp += sizeof(ret_addr);
    set_context(thread_id, ctx);
    restore_bp(va);
    return true;
  };

  bool is_protection = (lbl == "VirtualProtect" || lbl == "VirtualProtectEx" || lbl == "NtProtectVirtualMemory");
  bool is_allocation = (lbl == "VirtualAlloc" || lbl == "VirtualAllocEx" || lbl == "NtAllocateVirtualMemory");

  if (lbl == "IsDebuggerPresent") {
    printf("[AD] Spoofed IsDebuggerPresent\n");
    if (skip_function(0))
      return BpAction::Continue;
  }

  if (lbl == "CheckRemoteDebuggerPresent") {
    uint32_t not_debugged = 0;
    if (ctx.Rdx)
      write_mem(ctx.Rdx, &not_debugged, sizeof(not_debugged));
    printf("[AD] Spoofed CheckRemoteDebuggerPresent\n");
    if (skip_function(1))
      return BpAction::Continue;
  }

  if (lbl == "OutputDebugStringA" || lbl == "OutputDebugStringW") {
    printf("[AD] Suppressed %s\n", lbl.c_str());
    if (skip_function(0))
      return BpAction::Continue;
  }

  if (lbl == "NtSetInformationThread") {
    DWORD thread_info_class = (DWORD)ctx.Rdx;
    if (thread_info_class == 0x11) {
      printf("[AD] Blocked NtSetInformationThread(ThreadHideFromDebugger)\n");
      if (skip_function(0))
        return BpAction::Continue;
    }
  }

  if (lbl == "MessageBoxA" || lbl == "MessageBoxW" ||
      lbl == "MessageBoxExA" || lbl == "MessageBoxExW" ||
      lbl == "MessageBoxTimeoutA" || lbl == "MessageBoxTimeoutW" ||
      lbl == "MessageBoxIndirectA" || lbl == "MessageBoxIndirectW") {
    printf("[AD] Suppressed %s\n", lbl.c_str());
    if (skip_function(1))
      return BpAction::Continue;
  }

  if (lbl == "NtQuerySystemInformation") {
    DWORD info_class = (DWORD)ctx.Rcx;
    uint64_t info_ptr = ctx.Rdx;
    uint32_t info_len = (uint32_t)ctx.R8;
    uint64_t return_len_ptr = 0;
    read_mem(ctx.Rsp + 0x28, &return_len_ptr, sizeof(return_len_ptr));
    if (info_class == 35 && info_ptr && info_len >= 2) {
      uint8_t kernel_debugger[2] = {0, 1};
      if (write_mem(info_ptr, kernel_debugger, sizeof(kernel_debugger))) {
        if (return_len_ptr) {
          uint32_t return_len = 2;
          write_mem(return_len_ptr, &return_len, sizeof(return_len));
        }
        printf("[AD] Spoofed NtQuerySystemInformation(SystemKernelDebuggerInformation)\n");
        if (skip_function(0))
          return BpAction::Continue;
      }
    }

    set_context(thread_id, ctx);
    enable_single_step(thread_id);
    m_single_step_after = va;
    return BpAction::Continue;
  }

  if (lbl == "NtQueryInformationProcess") {
    DWORD info_class = (DWORD)ctx.Rdx;
    uint64_t info_ptr = ctx.R8;
    uint32_t info_len = (uint32_t)ctx.R9;
    uint64_t return_len_ptr = 0;
    read_mem(ctx.Rsp + 0x28, &return_len_ptr, sizeof(return_len_ptr));
    bool spoofed = false;
    uint32_t spoofed_len = 0;

    if (info_ptr) {
      if (info_class == 7 && info_len >= sizeof(uint32_t)) {
        // ProcessDebugPort: return 0 / no debug port.
        uint64_t no_debug_port = 0;
        spoofed_len =
            (info_len >= sizeof(uint64_t)) ? sizeof(uint64_t) : sizeof(uint32_t);
        spoofed = write_mem(info_ptr, &no_debug_port, spoofed_len);
      } else if (info_class == 30 && info_len >= sizeof(uint32_t)) {
        // ProcessDebugObjectHandle: return null handle.
        uint64_t no_debug_object = 0;
        spoofed_len =
            (info_len >= sizeof(uint64_t)) ? sizeof(uint64_t) : sizeof(uint32_t);
        spoofed =
            write_mem(info_ptr, &no_debug_object, spoofed_len);
      } else if (info_class == 31 && info_len >= sizeof(uint32_t)) {
        // ProcessDebugFlags: bit 0 set means "not debugged".
        uint32_t debug_flags = 1;
        spoofed = write_mem(info_ptr, &debug_flags, sizeof(debug_flags));
        spoofed_len = sizeof(debug_flags);
      }
    }

    if (spoofed) {
      if (return_len_ptr && spoofed_len)
        write_mem(return_len_ptr, &spoofed_len, sizeof(spoofed_len));
      uint64_t ret_addr = 0;
      if (read_mem(ctx.Rsp, &ret_addr, sizeof(ret_addr))) {
        printf("[AD] Spoofed NtQueryInformationProcess class %lu\n",
               info_class);
        ctx.Rax = 0;
        ctx.Rip = ret_addr;
        ctx.Rsp += sizeof(ret_addr);
        set_context(thread_id, ctx);
        restore_bp(va);
        return BpAction::Continue;
      }
    }

    set_context(thread_id, ctx);
    enable_single_step(thread_id);
    m_single_step_after = va;
    return BpAction::Continue;
  }

  if (is_protection) {
    uint64_t lp_address = 0;
    DWORD fl_new_prot = 0;

    if (lbl == "NtProtectVirtualMemory") {
      // NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
      // RCX = ProcessHandle, RDX = PVOID* BaseAddress, R8 = PSIZE_T RegionSize, R9 = NewProtect
      uint64_t va_base_ptr = ctx.Rdx;
      read_mem(va_base_ptr, &lp_address, 8);
      fl_new_prot = (DWORD)ctx.R9;
    } else if (lbl == "VirtualProtectEx") {
      // BOOL VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
      lp_address = ctx.Rdx;
      fl_new_prot = (DWORD)ctx.R9;
    } else {
      // BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
      lp_address = ctx.Rcx;
      fl_new_prot = (DWORD)ctx.R8;
    }

    bool makes_exec =
        (fl_new_prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    
    // VERBOSE DEBUGGING: Log all protection changes that target virtual sections
    bool in_target_image =
        m_image_base_child && lp_address >= m_image_base_child &&
        lp_address < m_image_base_child + m_pe.image_size;
    uint32_t rva = in_target_image ? to_rva(lp_address) : 0;
    const SectionInfo *sec = in_target_image ? m_pe.section_for_rva(rva) : nullptr;
    if (sec && sec->is_virtual()) {
      printf("[DEBUG] %s targeting '%s' (VA=0x%llX, prot=0x%X, exec=%d)\n",
             lbl.c_str(), sec->name, (unsigned long long)lp_address, fl_new_prot, makes_exec);
    }

    if (makes_exec) {
      if (sec) {
        // If it's a known virtual section or any non-loader section being marked exec,
        // it's likely decrypted and ready. Capture it NOW before it can be ephemeral.
        if (sec->is_virtual() || rva != m_pe.loader_section_va) {
            uint32_t dump_size = std::max(sec->vsize, sec->raw_size);
            if (dump_size > 0) {
                dump_size = (dump_size + 0xFFF) & ~0xFFFu;
                MemRegion region;
                region.base_va = lp_address;
                region.rva = sec->vaddr;
                region.section_name = sec->name;
                region.data.resize(dump_size, 0);

                SIZE_T br = 0;
                if (ReadProcessMemory(m_hProcess, (LPCVOID)lp_address, region.data.data(), dump_size, &br) && br > 0) {
                    m_captured_regions[sec->vaddr] = std::move(region);
                    printf("    [VMP] Captured section '%s' data (VA=0x%llX, size=0x%X)\n",
                           sec->name, (unsigned long long)lp_address, dump_size);
                }
            }
        }

        if (sec->is_virtual() && m_executable_pages.find(lp_address) == m_executable_pages.end()) {
          m_executable_pages.insert(lp_address);
          m_populated_secs++;
          printf("    [VMP] Section '%s' marked executable (VA=0x%llX, prot=0x%X) [%d/%d]\n",
                 sec->name, (unsigned long long)lp_address, fl_new_prot,
                 m_populated_secs, m_expected_virtual_secs);

          if (m_populated_secs >= m_expected_virtual_secs) {
            printf(
                "[+] All virtual sections populated – entering OEP hunt mode\n");
            m_oep_hunting = true;
          }
        }
      }
    }

    set_context(thread_id, ctx);
    enable_single_step(thread_id);
    m_single_step_after = va;
    return BpAction::Continue;
  }

  if (is_allocation) {
    set_context(thread_id, ctx);
    enable_single_step(thread_id);
    m_single_step_after = va;
    return BpAction::Continue;
  }

  set_context(thread_id, ctx);
  return BpAction::Continue;
}

// Main debug loop

bool Debugger::run_until_oep(DWORD &oep_rva, DWORD64 &oep_abs) {
  bool initial_bp_seen = false; // true after we handle the loader BP
  bool dll_loaded = false;
  bool apis_hooked = false;
  DWORD continue_status = DBG_CONTINUE;

  DWORD start_tick = GetTickCount();
  DWORD last_event_tick = start_tick;
  DWORD last_idle_log_tick = start_tick;

  while (true) {
    if (GetTickCount() - start_tick > DEBUG_TIMEOUT_MS) {
      fprintf(stderr, "[-] Timeout waiting for OEP\n");
      return false;
    }

    DEBUG_EVENT de = {};
    if (!WaitForDebugEvent(&de, 1000)) {
      DWORD now = GetTickCount();
      if (now - last_idle_log_tick >= DEBUG_IDLE_LOG_MS) {
        printf("[DEBUG] Waiting... dll_loaded=%d apis_hooked=%d populated=%d/%d oep_hunting=%d\n",
               dll_loaded ? 1 : 0, apis_hooked ? 1 : 0, m_populated_secs,
               m_expected_virtual_secs, m_oep_hunting ? 1 : 0);
        last_idle_log_tick = now;
      }
      if (dll_loaded && now - last_event_tick >= DEBUG_IDLE_TIMEOUT_MS) {
        fprintf(stderr,
                "[-] No debug events for %lu ms after target DLL load; "
                "target is likely blocked or running past our hooks\n",
                (unsigned long)(now - last_event_tick));
        return false;
      }
      continue;
    }

    last_event_tick = GetTickCount();

    continue_status = DBG_CONTINUE;

    switch (de.dwDebugEventCode) {


    case CREATE_PROCESS_DEBUG_EVENT: {
      auto &info = de.u.CreateProcessInfo;
      CloseHandle(info.hFile);
      m_image_base_child = (uint64_t)info.lpBaseOfImage;
      printf("[*] Child process image base: 0x%llX\n",
             (unsigned long long)m_image_base_child);

      // Create the anti-debug engine immediately.
      // PEB patch happens here — main thread is still suspended at the
      // loader breakpoint so we have a clean window.
      if (!m_adb) {
        m_adb = new AntiDebugBypass(m_hProcess, m_pid, m_scylla_hide_path);
        m_adb->init_peb_patch();
      }
      break;
    }

    case CREATE_THREAD_DEBUG_EVENT:
      // Clear debug registers on every new thread VMP creates
      if (m_adb) {
        m_adb->clear_debug_registers(de.dwThreadId);
      }
      break;

    case EXIT_THREAD_DEBUG_EVENT:
      break;


    case LOAD_DLL_DEBUG_EVENT: {
      auto &info = de.u.LoadDll;
      if (info.hFile)
        CloseHandle(info.hFile);

      // Detect our target DLL
      uint64_t dll_base = (uint64_t)info.lpBaseOfDll;
      if (!dll_loaded) {
        uint16_t mz = 0;
        if (ReadProcessMemory(m_hProcess, (LPCVOID)dll_base, &mz, 2, nullptr) &&
            mz == 0x5A4D) {
          uint32_t pe_off_c = 0;
          ReadProcessMemory(m_hProcess, (LPCVOID)(dll_base + 0x3C), &pe_off_c,
                            4, nullptr);
          uint32_t ep_rva_c = 0;
          ReadProcessMemory(m_hProcess,
                            (LPCVOID)(dll_base + pe_off_c + 24 + 16), &ep_rva_c,
                            4, nullptr);
          if (ep_rva_c == m_pe.ep_rva) {
            m_image_base_child = dll_base;
            dll_loaded = true;
            printf("[*] Target DLL loaded at 0x%llX (EP_RVA=0x%X confirmed)\n",
                   (unsigned long long)dll_base, ep_rva_c);
            
            // If the target is loaded, we MUST have hooks ready.
            if (!apis_hooked && resolve_and_hook_apis())
              apis_hooked = true;
          }
        }
      }

      // Re-install anti-debug hooks on every DLL load.
      // We don't wait for initial_bp_seen anymore because some hosts/VMP versions
      // might execute checks before or during the loader BP.
      if (m_adb) {
        m_adb->install_api_hooks();
      }

      if (!apis_hooked) {
        if (resolve_and_hook_apis()) {
          apis_hooked = true;
        }
      }
      break;
    }

    case UNLOAD_DLL_DEBUG_EVENT:
      break;


    case EXCEPTION_DEBUG_EVENT: {
      auto &exc = de.u.Exception;
      DWORD code = exc.ExceptionRecord.ExceptionCode;
      uint64_t addr = (uint64_t)exc.ExceptionRecord.ExceptionAddress;

      // Log suspicious exceptions that might be VMP anti-debug or crashes
      if (code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP && code != 0x4000001F) {
         if (code != 0xC0000008) { // Ignore EXCEPTION_INVALID_HANDLE
           const char* type = "Unknown";
           if (code == 0xC0000005) {
             type = (exc.ExceptionRecord.ExceptionInformation[0] == 0) ? "READ" :
                    (exc.ExceptionRecord.ExceptionInformation[0] == 1) ? "WRITE" : "EXEC";
           }
           printf("[DEBUG] Exception 0x%08X (%s) at 0x%llX (TargetAddr=0x%llX, FirstChance=%d)\n", 
                  code, type, addr, (uint64_t)exc.ExceptionRecord.ExceptionInformation[1], exc.dwFirstChance);
         }
      }

      // Silently eat EXCEPTION_INVALID_HANDLE and similar VMP tricks
      if (m_adb && m_adb->should_silently_continue(code, addr)) {
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
        continue;
      }

      if (m_adb && code != EXCEPTION_BREAKPOINT &&
          code != EXCEPTION_SINGLE_STEP &&
          m_adb->handle_injection_exception(de.dwThreadId, code, addr)) {
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
        continue;
      }

      if (code == EXCEPTION_BREAKPOINT || code == 0x4000001F) {


        // This is the very first BP: ntdll!LdrpDoDebuggerBreak.
        // It fires before any TLS callback or DllMain.
        // THIS IS THE CORRECT TIME to install all anti-debug hooks.
        if (!initial_bp_seen) {
          initial_bp_seen = true;
          printf("[*] Initial loader breakpoint hit – anti-debug prep\n");

          puts("[AD] Built-in anti-debug spoofing active; host preloads ScyllaHide when configured");

          // Also try to hook VirtualAlloc/VirtualProtect now
          if (!apis_hooked && resolve_and_hook_apis()) {
            apis_hooked = true;
          }

          ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
          continue;
        }


        // IMPORTANT: do NOT pre-decrement ctx.Rip here.
        // handle_breakpoint() expects Rip = addr+1 (the CPU's post-INT3
        // value) and performs the single Rip-- internally to land at addr.
        // A pre-decrement here caused a double-decrement that corrupted
        // passthrough single-step paths (Rip ended up at addr-1).
        auto it = m_breakpoints.find(addr);
        if (it == m_breakpoints.end()) {
          if (m_adb && m_adb->is_our_hook(addr)) {
            CONTEXT ctx = {};
            get_context(de.dwThreadId, ctx);
            // ctx.Rip is addr+1 here – handle_breakpoint corrects it
            if (m_adb->handle_breakpoint(de.dwThreadId, addr, ctx)) {
              ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
              continue;
            }
          }
          continue_status = DBG_EXCEPTION_NOT_HANDLED;
          break;
        }

        BpAction action = on_breakpoint(de.dwThreadId, addr, oep_rva, oep_abs);

        if (action == BpAction::OEPReached) {
          ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
          return true;
        }

      } else if (code == EXCEPTION_SINGLE_STEP) {

        // Clear DR registers on every single-step to stop VMP reading them
        if (m_adb) {
          m_adb->clear_debug_registers(de.dwThreadId);
        }

        // Let anti-debug engine claim pass-through single-steps
        if (m_adb) {
          CONTEXT ctx = {};
          get_context(de.dwThreadId, ctx);
          if (m_adb->handle_single_step(de.dwThreadId, addr, ctx)) {
            ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
            continue;
          }
        }

        // Re-arm BP we just single-stepped over
        if (m_single_step_after) {
          restore_bp(m_single_step_after);
          m_single_step_after = 0;
        }

        // OEP hunt: leaving the VMP loader section = OEP
        if (m_oep_hunting && !is_in_loader(addr)) {
          oep_rva = to_rva(addr);
          oep_abs = addr;
          printf("[+] Left VMP loader at 0x%llX (RVA=0x%X) — OEP!\n",
                 (unsigned long long)addr, oep_rva);
          ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
          return true;
        }

        if (m_oep_hunting) {
          enable_single_step(de.dwThreadId);
        }

      } else {
        // VMP often uses intentional exceptions (like Access Violations 0xC0000005)
        // to detect debuggers or as part of its internal control flow.
        // We MUST pass these back to the child (DBG_EXCEPTION_NOT_HANDLED) so
        // VMP's own Structured Exception Handler (SEH) can catch them.
        // If the debugger "eats" them, VMP knows it's being debugged or crashes.
        if (exc.dwFirstChance) {
          continue_status = DBG_EXCEPTION_NOT_HANDLED;
        } else {
          // If it's a second-chance exception, the process is actually crashing.
          continue_status = DBG_EXCEPTION_NOT_HANDLED;
        }
      }
      break;
    }

    case EXIT_PROCESS_DEBUG_EVENT:
      printf("[!] Child process exited with code %lu\n",
             de.u.ExitProcess.dwExitCode);
      ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
      if (m_hProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hProcess);
        m_hProcess = INVALID_HANDLE_VALUE;
      }
      if (m_hThread != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hThread);
        m_hThread = INVALID_HANDLE_VALUE;
      }
      return false;

    case OUTPUT_DEBUG_STRING_EVENT: {
      auto &info = de.u.DebugString;
      if (info.lpDebugStringData && info.nDebugStringLength) {
        std::vector<char> buf((size_t)info.nDebugStringLength + 2, 0);
        SIZE_T got = 0;
        if (ReadProcessMemory(m_hProcess, info.lpDebugStringData, buf.data(),
                              info.nDebugStringLength, &got) &&
            got > 0) {
          if (info.fUnicode) {
            std::wstring ws((wchar_t *)buf.data(),
                            got / sizeof(wchar_t));
            std::string narrow;
            narrow.resize(ws.size() * 4 + 1);
            int n = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1,
                                        narrow.data(),
                                        (int)narrow.size(), nullptr, nullptr);
            if (n > 0)
              printf("[ODS] %s", narrow.c_str());
          } else {
            printf("[ODS] %s", buf.data());
          }
        }
      }
      break;
    }
    case RIP_EVENT:
    default:
      break;
    }

    ContinueDebugEvent(de.dwProcessId, de.dwThreadId, continue_status);
  }

  return false;
}

// ──────────────────────────────────────────────────────────────────────────────
// dump_sections()
// ──────────────────────────────────────────────────────────────────────────────
bool Debugger::dump_sections(MemoryDump &out) {
  if (m_image_base_child == 0) {
    fprintf(stderr, "[-] Unknown child image base – cannot dump\n");
    return false;
  }

  for (auto &sec : m_pe.sections) {
    uint64_t va = m_image_base_child + sec.vaddr;
    uint32_t dump_size = std::max(sec.vsize, sec.raw_size);
    if (dump_size == 0)
      continue;

    dump_size = (dump_size + 0xFFF) & ~0xFFFu;

    MemRegion region;
    region.base_va = va;
    region.rva = sec.vaddr;
    region.section_name = sec.name;
    region.data.resize(dump_size, 0);

    SIZE_T bytes_read = 0;
    BOOL ok = ReadProcessMemory(m_hProcess, (LPCVOID)va, region.data.data(),
                                dump_size, &bytes_read);
    if (!ok || bytes_read == 0) {
      fprintf(
          stderr,
          "[!] Failed to read section '%s' (VA=0x%llX, size=0x%X): err=%lu\n",
          sec.name, (unsigned long long)va, dump_size, GetLastError());
      bytes_read = 0;
      for (uint32_t off = 0; off < dump_size; off += 0x1000) {
        SIZE_T rb = 0;
        ReadProcessMemory(m_hProcess, (LPCVOID)(va + off),
                          region.data.data() + off,
                          std::min((uint32_t)0x1000, dump_size - off), &rb);
        bytes_read += rb;
      }
    }

    printf("    Dumped '%s'  VA=0x%llX  size=0x%X  (read=%zu bytes)\n",
           sec.name, (unsigned long long)va, dump_size, bytes_read);

    out.regions.push_back(std::move(region));
  }

  return !out.regions.empty();
}

// ──────────────────────────────────────────────────────────────────────────────
// kill()
// ──────────────────────────────────────────────────────────────────────────────
void Debugger::kill() {
  if (m_hProcess != INVALID_HANDLE_VALUE) {
    DWORD exit_code = 0;
    if (GetExitCodeProcess(m_hProcess, &exit_code) && exit_code == STILL_ACTIVE)
      TerminateProcess(m_hProcess, 0);
    CloseHandle(m_hProcess);
    if (m_hThread != INVALID_HANDLE_VALUE)
      CloseHandle(m_hThread);
    m_hProcess = INVALID_HANDLE_VALUE;
    m_hThread = INVALID_HANDLE_VALUE;
  }
  // Avoid teardown-time crashes after abnormal debuggee exits. This object owns
  // only debugger-side bookkeeping and the process is exiting immediately after
  // unpack/rebuild, so leaking it is safer than losing the fallback path.
  // delete m_adb;
  m_adb = nullptr;
}
