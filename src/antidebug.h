#pragma once
//
// ScyllaHide bridge
//


#include "common.h"

class AntiDebugBypass {
public:
  AntiDebugBypass(HANDLE hProcess, DWORD pid, const std::string &scylla_path);

  void init_peb_patch();
  bool begin_scylla_hide_injection(DWORD thread_id);
  bool install_api_hooks();
  void clear_debug_registers(DWORD tid);

  bool handle_breakpoint(DWORD thread_id, uint64_t va, CONTEXT &ctx);
  bool handle_single_step(DWORD thread_id, uint64_t va, CONTEXT &ctx);
  bool handle_injection_exception(DWORD thread_id, DWORD exception_code,
                                  uint64_t exception_va);
  bool should_silently_continue(DWORD exception_code, uint64_t va);
  bool is_our_hook(uint64_t va) const;

  bool configured() const { return !m_scylla_path.empty(); }
  bool injected() const { return m_injected; }

private:
  HANDLE m_hProcess = INVALID_HANDLE_VALUE;
  DWORD m_pid = 0;
  std::string m_scylla_path;

  bool m_injection_started = false;
  bool m_injected = false;
  DWORD m_injection_tid = 0;
  CONTEXT m_saved_ctx = {};
  uint64_t m_stub_base = 0;
  uint64_t m_stub_size = 0;
  uint64_t m_stub_break_va = 0;
  uint64_t m_path_remote = 0;
  uint64_t m_path_size = 0;
  bool m_injection_failed = false;

  bool write_mem(uint64_t va, const void *buf, size_t len);
  bool read_mem(uint64_t va, void *buf, size_t len);
  uint64_t resolve_in_child(const char *dll, const char *fn);
  bool get_ctx(DWORD tid, CONTEXT &ctx);
  bool set_ctx(DWORD tid, CONTEXT &ctx);
  void abort_injection(DWORD tid);
  void cleanup_remote_allocations();
};
