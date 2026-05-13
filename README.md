# VMProtect Unpacker Toolkit

A professional-grade toolset for static analysis and dynamic unpacking of **VMProtect 2.x / 3.x** protected Windows PE files (DLLs and EXEs).

---

## What's Inside

| File | Purpose |
|---|---|
| `vmp_analyze.py` | **Static analyzer** — parse the PE, identify VMP version, entropy map, export/import tables, produce JSON report |
| `vmp_unpacker/vmp_unpacker.exe` | **Dynamic unpacker** — spawn child under debug API, hook VirtualAlloc/VirtualProtect, detect OEP, dump + rebuild PE |
| `vmp_unpacker/*.cpp/.h` | Full C++ source for the unpacker |
| `analysis_report.json` | JSON report from the last static analysis run |

---

## Target: `packed.dll` (rise.dll)

Analysis of this specific sample revealed:

| Property | Value |
|---|---|
| **File** | `packed.dll` (20.14 MB) |
| **MD5** | `8a97f8d93ad114efcc473691c4ec4b8b` |
| **Architecture** | x64 PE32+ |
| **Image Base** | `0x180000000` |
| **VMP Version** | **3.x** — obfuscated section names + 5 virtual-only sections |
| **Original name** | `rise.dll` (from export directory) |
| **Exports** | 4,370 functions (OpenJDK/HotSpot JVM symbols) |
| **Imports** | 19 DLLs (KERNEL32, USER32, WS2_32, VCRUNTIME140, CRT…) |

### VMP Layout

```
Section     VAddr       VSize       Raw    Role
─────────────────────────────────────────────────────────────
.text       0x00001000  0x96D35C    NONE   ← original code  (stripped)
.rdata      0x0096F000  0x2D3A10    NONE   ← read-only data  (stripped)
.data       0x00C43000  0xCE240     NONE   ← writable data   (stripped)
.pdata      0x00D12000  0x73344     NONE   ← exception table (stripped)
.%`1        0x00D86000  0x9F81D1    NONE   ← VMP virtual code (stripped)
.z`t        0x0177F000  0x2F8       0x400  ← IAT stub (real)
.=Ha        0x01780000  0x1421D80   20 MB  ← VMP loader + encrypted payload ← EP
.rsrc       0x02BA2000  0x545       0x600  ← resources (real)
.reloc      0x02BA3000  0xB8        0x200  ← relocations (real)
```

**Key:** `.=Ha` is the VMP 3.x loader section. It:
1. Allocates memory for the 5 stripped sections
2. Decrypts/decompresses the original code into them
3. Resolves imports through its own trampoline system
4. Jumps to the **Original Entry Point (OEP)**

---

## Usage

### Step 1 — Static Analysis

```cmd
python vmp_analyze.py packed.dll --json report.json
```

Outputs: PE layout, VMP version, section entropy map, import/export tables, and unpacking strategy.

### Step 2 — Dynamic Unpacking

```cmd
vmp_unpacker\vmp_unpacker.exe packed.dll unpacked.dll
```

The unpacker will:
1. Launch `packed.dll` under the Windows Debug API
2. Hook `VirtualAlloc` + `VirtualProtect` to watch VMP populate sections
3. Detect OEP (first instruction outside `.=Ha`)
4. Dump all 9 sections from live memory
5. Rebuild a valid PE with correct section raw data and patched entry point

### Step 3 — IAT Reconstruction (Final Step)

After step 2, import trampolines still point into the VMP section.
Use **Scylla** (x64dbg plugin) to fix them:

```
1. Open x64dbg → attach to a process running unpacked.dll
2. Plugins → Scylla → IAT Autosearch
3. Get Imports
4. Fix Dump (point to unpacked.dll)
5. Save → final_unpacked.dll
```

---

## How VMP 3.x Packing Works

```
┌─────────────────────────────────────────────────────┐
│  On-Disk PE (packed.dll)                            │
│                                                     │
│  .text / .rdata / .data / .pdata / .%`1             │
│      RawOffset=0, RawSize=0  ← NO DATA ON DISK      │
│                                                     │
│  .=Ha  [20 MB, entropy=7.86]  ← EP POINTS HERE     │
│      ┌─────────────────────────────────────────┐   │
│      │ VMP Loader (obfuscated x64 asm)         │   │
│      │  + Key-stream encrypted original code   │   │
│      └─────────────────────────────────────────┘   │
│                                                     │
│  .z`t  [IAT stubs → VMP trampolines]                │
└─────────────────────────────────────────────────────┘
                        │  LoadLibrary / DllMain
                        ▼
┌─────────────────────────────────────────────────────┐
│  In-Memory (after VMP loader runs)                  │
│                                                     │
│  .text    → VirtualAlloc → decrypt → VirtualProtect │
│  .rdata   → VirtualAlloc → decrypt → VirtualProtect │
│  .data    → VirtualAlloc → decrypt                  │
│  .pdata   → VirtualAlloc → decrypt                  │
│  .%`1     → VirtualAlloc → decrypt → VirtualProtect │
│                                                     │
│  After all sections ready → JMP to OEP (.text)      │
└─────────────────────────────────────────────────────┘
```

---

## Building from Source

Requires **Visual Studio 2022** (any edition) with C++ workload.

```cmd
cd vmp_unpacker
build.bat
```

Or with CMake:
```cmd
cd vmp_unpacker
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

---

## Architecture of the Unpacker

```
main.cpp          Entry point, orchestrates phases 1–5
common.h/.cpp     PE header parser, shared types (PEInfo, SectionInfo, MemoryDump)
debugger.h/.cpp   Windows Debug API loop:
                    - CreateProcess(DEBUG_PROCESS)
                    - INT3 hooks on VirtualAlloc / VirtualProtect
                    - OEP detection via single-step + loader boundary check
                    - ReadProcessMemory dump of all sections
dump_pe.h/.cpp    PE rebuilder: appends dumped section data, fixes headers + EP
iat_fix.h/.cpp    IAT scanner: classifies thunks as OK or VMP_TRAMPOLINE
```

---

## Notes for Analysts

- **VMP 3.x** uses a per-binary polymorphic key-stream cipher — no two packed files decrypt the same way. Static decryption is impractical; dynamic dumping is the correct approach.
- The **IAT trampolines** in `.z`t` point into `.=Ha`; they resolve to real APIs at runtime. Scylla reads the live process memory to reconstruct the true import table.
- The **`characteristics` field** (`0x2022`) confirms this is a DLL (`IMAGE_FILE_DLL` = bit 13) with large addresses stripped and the executable bit set.
- Export symbols (`??_7…MetaspaceClosure`) are OpenJDK HotSpot C++ vtable entries — this is a packed JVM native library (`rise.dll`).
