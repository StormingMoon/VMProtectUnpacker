//
// ScyllaHide bridge
//


#include "antidebug.h"
#include <cstdio>
#include <cstring>

AntiDebugBypass::AntiDebugBypass(HANDLE hProcess, DWORD pid,
                                 const std::string &scylla_path)
    : m_hProcess(hProcess), m_pid(pid), m_scylla_path(scylla_path) {}

bool AntiDebugBypass::write_mem(uint64_t va, const void *buf, size_t len) {
  SIZE_T written = 0;
  return WriteProcessMemory(m_hProcess, (LPVOID)va, buf, len, &written) &&
         written == len;
}

bool AntiDebugBypass::read_mem(uint64_t va, void *buf, size_t len) {
  SIZE_T read = 0;
  return ReadProcessMemory(m_hProcess, (LPCVOID)va, buf, len, &read) &&
         read == len;
}

bool AntiDebugBypass::get_ctx(DWORD tid, CONTEXT &ctx) {
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

bool AntiDebugBypass::set_ctx(DWORD tid, CONTEXT &ctx) {
  HANDLE ht = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                             THREAD_SUSPEND_RESUME,
                         FALSE, tid);
  if (!ht)
    return false;
  bool ok = SetThreadContext(ht, &ctx) != FALSE;
  CloseHandle(ht);
  return ok;
}

uint64_t AntiDebugBypass::resolve_in_child(const char *dll_name,
                                           const char *fn_name) {
  HANDLE snap =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid);
  if (snap == INVALID_HANDLE_VALUE)
    return 0;

  uint64_t child_base = 0;
  MODULEENTRY32W me = {};
  me.dwSize = sizeof(me);

  wchar_t wdll[MAX_PATH] = {};
  MultiByteToWideChar(CP_ACP, 0, dll_name, -1, wdll, MAX_PATH);

  if (Module32FirstW(snap, &me)) {
    do {
      if (_wcsicmp(me.szModule, wdll) == 0) {
        child_base = (uint64_t)me.modBaseAddr;
        break;
      }
    } while (Module32NextW(snap, &me));
  }
  CloseHandle(snap);

  if (!child_base)
    return 0;

  HMODULE local_mod = GetModuleHandleA(dll_name);
  if (!local_mod)
    local_mod = LoadLibraryA(dll_name);
  if (!local_mod)
    return 0;

  FARPROC local_fn = GetProcAddress(local_mod, fn_name);
  if (!local_fn)
    return 0;

  return child_base + ((uint64_t)local_fn - (uint64_t)local_mod);
}

void AntiDebugBypass::init_peb_patch() {
  using NtQueryInformationProcessFn =
      LONG(WINAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);

  struct PROCESS_BASIC_INFORMATION_LOCAL {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
  };

  auto nt_query = (NtQueryInformationProcessFn)GetProcAddress(
      GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
  if (nt_query) {
    PROCESS_BASIC_INFORMATION_LOCAL pbi = {};
    if (nt_query(m_hProcess, 0, &pbi, sizeof(pbi), nullptr) >= 0 &&
        pbi.PebBaseAddress) {
      uint64_t peb = (uint64_t)pbi.PebBaseAddress;
      uint8_t being_debugged = 0;
      DWORD nt_global_flag = 0;
      write_mem(peb + 0x2, &being_debugged, sizeof(being_debugged));
      write_mem(peb + 0xBC, &nt_global_flag, sizeof(nt_global_flag));

      uint64_t process_heap = 0;
      if (read_mem(peb + 0x30, &process_heap, sizeof(process_heap)) &&
          process_heap) {
        DWORD heap_flags = HEAP_GROWABLE;
        DWORD heap_force_flags = 0;
        write_mem(process_heap + 0x70, &heap_flags, sizeof(heap_flags));
        write_mem(process_heap + 0x74, &heap_force_flags,
                  sizeof(heap_force_flags));
      }

      printf("[AD] Patched remote PEB debug fields at 0x%llX\n",
             (unsigned long long)peb);
    } else {
      fprintf(stderr, "[AD] Could not query child PEB for debug field patch\n");
    }
  }

  if (m_scylla_path.empty()) {
    puts("[AD] ScyllaHide disabled: no hook DLL was configured.");
    puts("[AD] Pass --scyllahide <HookLibraryx64.dll> or set SCYLLAHIDE_DLL.");
    return;
  }

  printf("[AD] ScyllaHide hook DLL: %s\n", m_scylla_path.c_str());
}

bool AntiDebugBypass::begin_scylla_hide_injection(DWORD thread_id) {
  if (m_scylla_path.empty() || m_injection_failed || m_injection_started ||
      m_injected)
    return m_injected;

  DWORD attrs = GetFileAttributesA(m_scylla_path.c_str());
  if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
    fprintf(stderr, "[AD] ScyllaHide DLL not found: %s\n",
            m_scylla_path.c_str());
    return false;
  }

  uint64_t load_library = resolve_in_child("KERNEL32.DLL", "LoadLibraryA");
  if (!load_library) {
    fprintf(stderr, "[AD] Could not resolve child KERNEL32!LoadLibraryA\n");
    return false;
  }

  CONTEXT ctx = {};
  if (!get_ctx(thread_id, ctx)) {
    fprintf(stderr, "[AD] Could not read thread context for ScyllaHide load\n");
    return false;
  }

  m_saved_ctx = ctx;
  m_injection_tid = thread_id;

  m_path_size = m_scylla_path.size() + 1;
  m_path_remote = (uint64_t)VirtualAllocEx(
      m_hProcess, nullptr, m_path_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!m_path_remote) {
    fprintf(stderr, "[AD] VirtualAllocEx failed for ScyllaHide path: %lu\n",
            GetLastError());
    return false;
  }

  if (!write_mem(m_path_remote, m_scylla_path.c_str(), m_path_size)) {
    fprintf(stderr, "[AD] Failed to write ScyllaHide path into child\n");
    cleanup_remote_allocations();
    return false;
  }

  uint8_t stub[64] = {};
  size_t off = 0;
  // The interrupted debug-break context can have either stack alignment.
  // Align explicitly before calling LoadLibraryA, keep the required x64 shadow
  // space, and restore the exact original RSP before returning to the saved
  // thread context.
  stub[off++] = 0x49; stub[off++] = 0x89; stub[off++] = 0xE4;
  stub[off++] = 0x48; stub[off++] = 0x83; stub[off++] = 0xE4; stub[off++] = 0xF0;
  stub[off++] = 0x48; stub[off++] = 0x83; stub[off++] = 0xEC; stub[off++] = 0x20;
  stub[off++] = 0x48; stub[off++] = 0xB9;
  memcpy(stub + off, &m_path_remote, sizeof(m_path_remote)); off += 8;
  stub[off++] = 0x48; stub[off++] = 0xB8;
  memcpy(stub + off, &load_library, sizeof(load_library)); off += 8;
  stub[off++] = 0xFF; stub[off++] = 0xD0;
  stub[off++] = 0x4C; stub[off++] = 0x89; stub[off++] = 0xE4;
  stub[off++] = 0xCC;

  m_stub_size = off;
  m_stub_base = (uint64_t)VirtualAllocEx(m_hProcess, nullptr, 0x1000,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE);
  if (!m_stub_base) {
    fprintf(stderr, "[AD] VirtualAllocEx failed for ScyllaHide loader stub: %lu\n",
            GetLastError());
    cleanup_remote_allocations();
    return false;
  }

  if (!write_mem(m_stub_base, stub, m_stub_size)) {
    fprintf(stderr, "[AD] Failed to write ScyllaHide loader stub\n");
    cleanup_remote_allocations();
    return false;
  }

  FlushInstructionCache(m_hProcess, (LPCVOID)m_stub_base, m_stub_size);
  m_stub_break_va = m_stub_base + m_stub_size - 1;

  ctx.Rip = m_stub_base;
  if (!set_ctx(thread_id, ctx)) {
    fprintf(stderr, "[AD] Could not redirect thread to ScyllaHide loader stub\n");
    cleanup_remote_allocations();
    return false;
  }

  m_injection_started = true;
  printf("[AD] ScyllaHide injection scheduled at loader breakpoint "
         "(stub=0x%llX)\n",
         (unsigned long long)m_stub_base);
  return true;
}

bool AntiDebugBypass::install_api_hooks() { return true; }

void AntiDebugBypass::clear_debug_registers(DWORD) {}

bool AntiDebugBypass::is_our_hook(uint64_t va) const {
  return m_injection_started && va == m_stub_break_va;
}

bool AntiDebugBypass::handle_breakpoint(DWORD thread_id, uint64_t va,
                                        CONTEXT &ctx) {
  if (!is_our_hook(va))
    return false;

  if (thread_id != m_injection_tid) {
    fprintf(stderr, "[AD] ScyllaHide loader breakpoint hit on unexpected TID\n");
    return false;
  }

  HMODULE loaded = (HMODULE)ctx.Rax;
  set_ctx(thread_id, m_saved_ctx);
  m_injected = loaded != nullptr;

  if (m_injected) {
    printf("[AD] ScyllaHide loaded in child at 0x%llX\n",
           (unsigned long long)loaded);
  } else {
    fprintf(stderr, "[AD] LoadLibraryA failed for ScyllaHide DLL\n");
  }

  cleanup_remote_allocations();
  return true;
}

bool AntiDebugBypass::handle_single_step(DWORD, uint64_t, CONTEXT &) {
  return false;
}

bool AntiDebugBypass::handle_injection_exception(DWORD thread_id,
                                                 DWORD exception_code,
                                                 uint64_t exception_va) {
  if (!m_injection_started || m_injected || thread_id != m_injection_tid)
    return false;

  fprintf(stderr,
          "[AD] ScyllaHide injection faulted (exception=0x%08lX at 0x%llX); "
          "restoring target thread and continuing without it\n",
          exception_code, (unsigned long long)exception_va);
  abort_injection(thread_id);
  return true;
}

bool AntiDebugBypass::should_silently_continue(DWORD exception_code, uint64_t) {
  return exception_code == 0xC0000008;
}

void AntiDebugBypass::abort_injection(DWORD tid) {
  set_ctx(tid, m_saved_ctx);
  cleanup_remote_allocations();
  m_injection_started = false;
  m_injection_tid = 0;
  m_injection_failed = true;
}

void AntiDebugBypass::cleanup_remote_allocations() {
  if (m_stub_base) {
    VirtualFreeEx(m_hProcess, (LPVOID)m_stub_base, 0, MEM_RELEASE);
    m_stub_base = 0;
  }
  if (m_path_remote) {
    VirtualFreeEx(m_hProcess, (LPVOID)m_path_remote, 0, MEM_RELEASE);
    m_path_remote = 0;
  }
  m_stub_size = 0;
  m_stub_break_va = 0;
  m_path_size = 0;
}
