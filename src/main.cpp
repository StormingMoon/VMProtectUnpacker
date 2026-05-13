// VMProtect Dynamic Unpacker


#include "common.h"
#include "debugger.h"
#include "dump_pe.h"
#include "iat_fix.h"
#include "resource.h"
#include <algorithm>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

static bool file_exists(const std::string& path)
{
    DWORD attrs = GetFileAttributesA(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static bool dir_exists(const std::string& path)
{
    DWORD attrs = GetFileAttributesA(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static std::string join_path(const std::string& dir, const char* name)
{
    if (dir.empty()) return name;
    char last = dir[dir.size() - 1];
    if (last == '\\' || last == '/') return dir + name;
    return dir + "\\" + name;
}

static std::string full_path(const std::string& path)
{
    char buf[MAX_PATH] = {};
    DWORD n = GetFullPathNameA(path.c_str(), MAX_PATH, buf, nullptr);
    return (n > 0 && n < MAX_PATH) ? std::string(buf) : path;
}

static std::string extract_embedded_scylla_hide()
{
    HRSRC res = FindResourceA(nullptr, MAKEINTRESOURCEA(IDR_SCYLLAHIDE_X64), RT_RCDATA);
    if (!res)
        return "";

    HGLOBAL loaded = LoadResource(nullptr, res);
    DWORD size = SizeofResource(nullptr, res);
    const void* data = loaded ? LockResource(loaded) : nullptr;
    if (!data || size == 0)
        return "";

    char temp_dir[MAX_PATH] = {};
    DWORD n = GetTempPathA(MAX_PATH, temp_dir);
    if (n == 0 || n >= MAX_PATH)
        return "";

    std::string out_dir = join_path(temp_dir, "vmp_unpacker_scyllahide");
    CreateDirectoryA(out_dir.c_str(), nullptr);

    char file_name[64] = {};
    snprintf(file_name, sizeof(file_name), "HookLibraryx64_%lu.dll", GetCurrentProcessId());
    std::string out_path = join_path(out_dir, file_name);
    std::string ini_src = full_path("scylla_hide.ini");
    if (file_exists(ini_src))
        CopyFileA(ini_src.c_str(), join_path(out_dir, "scylla_hide.ini").c_str(), FALSE);

    HANDLE h = CreateFileA(out_path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return "";

    DWORD written = 0;
    BOOL ok = WriteFile(h, data, size, &written, nullptr);
    CloseHandle(h);

    if (!ok || written != size) {
        DeleteFileA(out_path.c_str());
        return "";
    }

    return out_path;
}

static std::string resolve_scylla_hide_path(const std::string& requested)
{
    std::vector<std::string> candidates;

    if (!requested.empty()) {
        candidates.push_back(requested);
        if (dir_exists(requested))
            candidates.push_back(join_path(requested, "HookLibraryx64.dll"));
    }

    char env[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableA("SCYLLAHIDE_DLL", env, MAX_PATH);
    if (n > 0 && n < MAX_PATH)
        candidates.push_back(env);

    n = GetEnvironmentVariableA("SCYLLAHIDE_PATH", env, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        candidates.push_back(env);
        candidates.push_back(join_path(env, "HookLibraryx64.dll"));
    }

    std::string embedded = extract_embedded_scylla_hide();
    if (!embedded.empty())
        return embedded;

    candidates.push_back("HookLibraryx64.dll");
    candidates.push_back("ScyllaHide\\HookLibraryx64.dll");
    candidates.push_back("ScyllaHide\\HookLibrary\\x64\\HookLibraryx64.dll");

    for (const auto& c : candidates) {
        if (file_exists(c))
            return full_path(c);
    }

    return requested.empty() ? "" : requested;
}

static void print_banner()
{
    puts("╔══════════════════════════════════════════════════════════════════╗");
    puts("║       VMProtect Dynamic Unpacker  v1.0  (x64)                    ║");
    puts("║       Supports: VMP 2.x / 3.x  packed DLLs and EXEs              ║");
    puts("╚══════════════════════════════════════════════════════════════════╝");
    puts("");
}

static bool find_module_base(DWORD pid, const std::string& target_full, uint64_t& base)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE)
        return false;

    MODULEENTRY32W me = {};
    me.dwSize = sizeof(me);
    char path[MAX_PATH] = {};
    bool found = false;

    if (Module32FirstW(snap, &me)) {
        do {
            WideCharToMultiByte(CP_ACP, 0, me.szExePath, -1, path, MAX_PATH, nullptr, nullptr);
            if (_stricmp(path, target_full.c_str()) == 0) {
                base = (uint64_t)me.modBaseAddr;
                found = true;
                break;
            }
        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);
    return found;
}

static bool passive_load_and_dump(const std::string& target, const std::string& scylla_hide,
                                  const PEInfo& pe_info, MemoryDump& dump,
                                  DWORD64& image_base)
{
    char self_path[MAX_PATH] = {};
    char target_path[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, self_path, MAX_PATH);
    DWORD n = GetFullPathNameA(target.c_str(), MAX_PATH, target_path, nullptr);
    std::string target_full = (n > 0 && n < MAX_PATH) ? target_path : full_path(target);

    char cmdline[MAX_PATH * 4] = {};
    if (!scylla_hide.empty()) {
        snprintf(cmdline, sizeof(cmdline), "\"%s\" --host-dll \"%s\" \"%s\"",
                 self_path, target_full.c_str(), scylla_hide.c_str());
    } else {
        snprintf(cmdline, sizeof(cmdline), "\"%s\" --host-dll \"%s\"",
                 self_path, target_full.c_str());
    }

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(nullptr, cmdline, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
        fprintf(stderr, "[-] Passive host CreateProcess failed: %lu\n", GetLastError());
        return false;
    }

    uint64_t base = 0;
    DWORD start = GetTickCount();
    while (GetTickCount() - start < 15000) {
        DWORD exit_code = 0;
        if (GetExitCodeProcess(pi.hProcess, &exit_code) && exit_code != STILL_ACTIVE) {
            fprintf(stderr, "[-] Passive host exited early with code %lu\n", exit_code);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }
        if (find_module_base(pi.dwProcessId, target_full, base))
            break;
        Sleep(200);
    }

    if (!base) {
        fprintf(stderr, "[-] Passive host did not load target within timeout\n");
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    printf("[+] Passive host loaded target at 0x%llX\n", (unsigned long long)base);
    Sleep(2000);

    for (auto& sec : pe_info.sections) {
        uint64_t va = base + sec.vaddr;
        uint32_t dump_size = std::max(sec.vsize, sec.raw_size);
        if (!dump_size)
            continue;
        dump_size = (dump_size + 0xFFF) & ~0xFFFu;

        MemRegion region;
        region.base_va = va;
        region.rva = sec.vaddr;
        region.section_name = sec.name;
        region.data.resize(dump_size, 0);

        SIZE_T bytes_read = 0;
        ReadProcessMemory(pi.hProcess, (LPCVOID)va, region.data.data(),
                          dump_size, &bytes_read);
        printf("    Passive dumped '%s' VA=0x%llX size=0x%X (read=%zu bytes)\n",
               sec.name, (unsigned long long)va, dump_size, bytes_read);
        dump.regions.push_back(std::move(region));
    }

    image_base = base;
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return !dump.regions.empty();
}

int main(int argc, char* argv[])
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    if (argc >= 3 && std::string(argv[1]) == "--host-dll") {
        if (argc >= 4 && argv[3][0]) {
            HMODULE hide = LoadLibraryA(argv[3]);
            if (!hide) {
                char msg[1024] = {};
                snprintf(msg, sizeof(msg), "[HOST] ScyllaHide preload failed for '%s': %lu\n", argv[3], GetLastError());
                OutputDebugStringA(msg);
                fputs(msg, stderr);
                fflush(stderr);
            } else {
                char msg[1024] = {};
                snprintf(msg, sizeof(msg), "[HOST] Preloaded ScyllaHide '%s' at 0x%p\n", argv[3], hide);
                OutputDebugStringA(msg);
                fputs(msg, stdout);
                fflush(stdout);
            }
        }

        HMODULE mod = LoadLibraryA(argv[2]);
        if (!mod) {
            DWORD err = GetLastError();
            char msg[1024] = {};
            snprintf(msg, sizeof(msg), "[-] Host LoadLibrary failed for '%s': %lu\n", argv[2], err);
            OutputDebugStringA(msg);
            fputs(msg, stderr);
            fflush(stderr);
            Sleep(30000);
            return err ? err : 100;
        }
        char msg[1024] = {};
        snprintf(msg, sizeof(msg), "[HOST] Loaded '%s' at 0x%p\n", argv[2], mod);
        OutputDebugStringA(msg);
        fputs(msg, stdout);
        fflush(stdout);
        Sleep(INFINITE);
        return 0;
    }

    print_banner();

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [--scyllahide <HookLibraryx64.dll>] <packed.dll|exe> [output_unpacked.dll]\n", argv[0]);
        fprintf(stderr, "  packed.dll      - VMProtect-protected PE file\n");
        fprintf(stderr, "  output.dll      - Reconstructed output (default: unpacked_<input>)\n");
        fprintf(stderr, "  --scyllahide    - ScyllaHide HookLibraryx64.dll path (optional if bundled)\n");
        return 1;
    }

    std::string requested_scylla;
    std::vector<std::string> positional;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--scyllahide" || arg == "-sh") {
            if (i + 1 >= argc) {
                fprintf(stderr, "[-] Missing value after %s\n", arg.c_str());
                return 1;
            }
            requested_scylla = argv[++i];
        } else {
            positional.push_back(arg);
        }
    }

    if (positional.empty()) {
        fprintf(stderr, "Usage: %s [--scyllahide <HookLibraryx64.dll>] <packed.dll|exe> [output_unpacked.dll]\n", argv[0]);
        return 1;
    }

    std::string target  = positional[0];
    std::string output  = (positional.size() >= 2) ? positional[1] : "unpacked_" + positional[0];
    std::string scylla_hide = resolve_scylla_hide_path(requested_scylla);

    printf("[*] Target  : %s\n", target.c_str());
    printf("[*] Output  : %s\n", output.c_str());
    if (!scylla_hide.empty())
        printf("[*] Hide DLL: %s\n", scylla_hide.c_str());
    else
        puts("[*] Hide DLL: <none>  (bundle HookLibraryx64.dll at build time, set SCYLLAHIDE_DLL, or pass --scyllahide)");
    puts("");

    // Parse on-disk PE

    PEInfo pe_info;
    if (!parse_pe_header(target.c_str(), pe_info)) {
        fprintf(stderr, "[-] Failed to parse PE header of '%s'\n", target.c_str());
        return 2;
    }

    printf("[*] Arch        : %s\n",    pe_info.is_64bit ? "x64" : "x86");
    printf("[*] Image base  : 0x%llX\n", (unsigned long long)pe_info.image_base);
    printf("[*] EP (RVA)    : 0x%X\n",  pe_info.ep_rva);
    printf("[*] Sections    : %d  (%d virtual-only)\n",
           (int)pe_info.sections.size(), pe_info.virtual_section_count());
    printf("[*] Loader sec  : '%s'  (VA=0x%X)\n",
           pe_info.loader_section_name.c_str(), pe_info.loader_section_va);
    puts("");

    DWORD oep_rva = 0;
    DWORD64 oep_abs = 0;
    MemoryDump dump;
    bool have_dump = false;

    bool force_passive = false;
    // ... logic to check for --passive flag if we wanted ...

    if (force_passive) {
        puts("[*] Passive no-debug load/dump path forced...");
        DWORD64 passive_base = 0;
        if (!passive_load_and_dump(target, scylla_hide, pe_info, dump, passive_base)) {
            fprintf(stderr, "[-] Passive dump failed\n");
            return 4;
        }
        oep_rva = pe_info.ep_rva;
        oep_abs = passive_base + oep_rva;
        have_dump = true;
        printf("[!] Passive DLL dump used; keeping original EP RVA=0x%X\n", oep_rva);
    } else {
        // Launch child and unpack

        puts("[*] Launching child process under debug control...");
        Debugger dbg(target, pe_info, scylla_hide);
        if (!dbg.launch()) {
            fprintf(stderr, "[-] Failed to launch child process\n");
            return 3;
        }

        puts("[*] Waiting for VMP loader to unpack (monitoring VirtualAlloc/VirtualProtect)...");
        if (!dbg.run_until_oep(oep_rva, oep_abs)) {
            fprintf(stderr, "[-] OEP detection failed - child may have crashed or timed out\n");
            dbg.kill();
            return 4;
        }
        printf("[+] OEP detected: absolute=0x%llX  RVA=0x%X\n",
               (unsigned long long)oep_abs, oep_rva);

        puts("\n[*] Dumping unpacked sections from child memory...");
        if (!dbg.dump_sections(dump)) {
            fprintf(stderr, "[-] Memory dump failed\n");
            dbg.kill();
            return 5;
        }
        dbg.kill();
        have_dump = true;
    }

    // Rebuild

    puts("\n[*] Rebuilding PE...");
    PERebuilder rebuilder(target, pe_info, dump);
    rebuilder.set_oep(oep_rva);
    if (!rebuilder.rebuild(output)) {
        fprintf(stderr, "[-] PE rebuild failed\n");
        return 6;
    }
    printf("[+] PE written to '%s'\n", output.c_str());

    // IAT scan

    puts("\n[*] Performing basic IAT stub scan...");
    IATScanner iat(output, pe_info);
    iat.scan_and_report();

    puts("\n[+] DONE");
    printf("    Unpacked file : %s\n", output.c_str());
    puts("    Next steps    : Load in Scylla (x64dbg plugin) to finalize IAT");
    puts("                    Run: Scylla -> Attach to <your_host> -> IAT Autosearch -> Get Imports -> Fix Dump");
    return 0;
}
