# Native ARM64 (aarch64) BusyBox-w32 build — reproduction guide

Everything needed to rebuild and re-verify the native Windows-on-ARM `busybox.exe`
described in `VERIFICATION.md`, without any of the original session state.

**Result being reproduced:** the full stock `configs/mingw64a_defconfig` compiles clean
for `aarch64-w64-mingw32` with the WoA GCC chain under `CONFIG_WERROR=y` — **zero
warnings, zero errors, zero source changes** — producing a 179-applet `0xAA64` binary
that binds only `C:\Windows\System32` DLLs.

## Source revision

busybox-w32 commit **`d8d8bb397f1e200ba5a871dc6aa4af819b23f32a`**, **unmodified**.
No patches, no `-Wno-` suppressions, no defconfig edits were needed to build.

## Expected artefact identities

Binaries are deliberately **not** committed. These identities let a rebuild be checked.

| Artefact | SHA256 | Size | PE machine |
|---|---|---|---|
| `busybox.exe` | `67665B44DB934B574C95A600955482D35F1BB421A9498998DF3E5BAA96313AA8` | 756,224 | `0xAA64` |
| `busybox_unstripped.exe` | `EA9B3EC7F569A8BA5110DF0B169B730F113824E47C4FC890840E675359CE12FD` | 1,492,196 | `0xAA64` |

A rebuild is unlikely to be bit-identical (embedded version strings and timestamps), so
treat the hashes as provenance for *these* files and re-verify a new build against the
**acceptance bar** and the **property checks** below instead.

## Toolchain

Native ARM64 GCC from the `woarm64-native` pacman repo (`crutkas/gcc-woarm64`,
`crutkas/binutils-woarm64`):

- gcc **15.0.1 20250131 (experimental)**, target **`aarch64-w64-mingw32`**
- CRT **UCRT**, threads **posix**, `--with-arch=armv8-a --with-tune=generic`
- All host binaries `0xAA64` (`gcc.exe`, `as.exe`, `ld.exe`, `ar.exe`, `cc1.exe`)

Prove the toolchain with a **full compile → assemble → link → RUN** round trip before
trusting it. `gcc --version` succeeds on a broken prefix and proves nothing.

### Toolchain gotchas (each stage has its own dependency closure)

- `cc1.exe` binds libgmp, libisl, libmpc, libmpfr, zlib1, libzstd from separate packages;
  missing → `0xC0000135 DLL_NOT_FOUND`.
- `as.exe` binds **`libintl-8.dll`**. If absent, `gcc -S` passes (it stops at cc1) while
  `gcc -c` **fails silently at exit 1 with no diagnostic naming the DLL**. Fix: install
  `mingw-w64-aarch64-gettext-runtime`.
- **`-D_WIN32_WINNT=0x0A00` is required for `IsWow64Process2`.** The mingw-w64 headers at
  this rev do not declare it by default:
  ```
  error: implicit declaration of function 'IsWow64Process2'; did you mean 'IsWow64Process'?
  ```
  Only affects verification helpers, not the busybox build itself.

## Build

```sh
make mingw64a_defconfig
make CROSS_COMPILER=gcc HOST_COMPILER=gcc -j8 busybox.exe
```

**Both overrides are mandatory, and a partial fix is a trap.** `configs/mingw64a_defconfig`
pins *both* `CONFIG_CROSS_COMPILER="clang"` (line 84) and `CONFIG_HOST_COMPILER="clang"`
(line 83); it is the only mingw defconfig that does. Setting only `CROSS_COMPILER` clears
the first failure and still dies in the host-tool stage, because the two are read
independently at `Makefile:210-219` and `Makefile:199-208`. See CANDIDATE 2 in
`VERIFICATION.md` — including the silent-success behaviour where `make mingw64a_defconfig`
prints `aarch64-w64-mingw32-clang: command not found` and **still exits 0**.

`mingw64a-gcc.config` in this directory is the exact `.config` produced by the working
build; drop it in as `.config` to skip the defconfig step.

### ⚠️ Do not run `make distclean` on a checkout you care about

`Makefile:1132`'s `-o -size 0` predicate deletes **every zero-byte file in the tree**,
which is all 17 win32 POSIX-compat stub headers (`win32/netdb.h`, `win32/pwd.h`,
`win32/sys/socket.h`, …). The tree becomes unbuildable with
`fatal error: netdb.h: No such file or directory`, and `distclean` itself exits 0.
Recover with `git checkout -- win32`. Full write-up as CANDIDATE 1 in `VERIFICATION.md`.

### Build driver

MSYS2 `make` 4.4.1 plus Git for Windows' `usr/bin` for `sh`/`sed`/`awk`. On a WoA host
that driver is **x86-64 and runs emulated** — stated plainly, and it has no bearing on
output architecture, which is proven independently from the COFF header and from
`IsWow64Process2` on the running process. A native `aarch64` `mingw32-make` also works.

## Acceptance bar

```
ash.exe -c uname        ->  MINGW(BusyBox/Win32)   exit 0
PE header machine       ->  0xAA64
```
`ash.exe` is a byte copy of `busybox.exe`; applet dispatch is on `argv[0]`.

Read the PE machine **raw** — offset `0x3C` → PE signature `0x00004550` → `Machine` —
never from a tool's summary string:

```powershell
$fs=[IO.File]::OpenRead($path); $br=New-Object IO.BinaryReader($fs)
$fs.Position=0x3C; $o=$br.ReadUInt32(); $fs.Position=$o; $null=$br.ReadUInt32()
'0x{0:X4}' -f $br.ReadUInt16(); $fs.Dispose()
```

## Property checks worth re-running

1. **Applet count** — `busybox --list` → **179**.
2. **Nativity from the LIVE PROCESS**, not the file. Windows on ARM runs x64 transparently
   under emulation, so "it ran" proves nothing architectural. Start a long-running applet
   (`busybox sleep 12`) and call `IsWow64Process2` on it: expect
   `processMachine=0x0000, nativeMachine=0xAA64`.
3. **Module binding audit** — enumerate the live process's loaded modules and read each
   one's raw COFF machine. Expect **22 modules, all `0xAA64`, all from
   `C:\Windows\System32`**, and **no third-party DLL**: no `msys-2.0.dll`, no mingw
   runtime, no `libwinpthread-1.dll`, no `libgcc_s_*`. This is the runtime-free property
   MinGit-BusyBox exists for. Checking the *directory* instead of the *process* does not
   test this.
4. **Applets by effect, not exit code** — a command that exits 0 having done nothing is
   indistinguishable from success by exit code alone:
   ```sh
   busybox sed 's/alpha/OMEGA/g' in.txt > out.txt   # inspect out.txt contents
   busybox awk '{ print $2 }' in.txt                # inspect field extraction
   busybox sh -c 'printf "z\na\nm\n" | sort > s.txt; wc -l < s.txt'
   ```

## Integration test — `git clone` with a native ARM64 git.exe

The motivating defect: `git_shell_path()` calls `locate_in_PATH("sh")`, which returns NULL
when no `sh.exe` is on PATH, and passes it to `convert_slashes()`, whose `for(; *path; )`
dereferences NULL. **A shell on PATH is a hard precondition for a working native Git.**

`git.exe` used: pinned GCC-native build, SHA256
`69B1E704729CF69F0A0C029AA189EB9D38F74FC16EF37823048CB6A98B1523D1`, `0xAA64`, 4,723,261
bytes, `git version 2.47.1`.

**Neutralise the environment and PROVE the neutralisation took effect.** A WoA host
typically has `sh.exe`/`bash.exe` from `C:\Program Files\Git\bin` on the ambient PATH:

```powershell
$env:PATH = 'C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem'
Remove-Item Env:GIT_EXEC_PATH,Env:GIT_CONFIG_COUNT,Env:GIT_CONFIG_PARAMETERS -EA SilentlyContinue
```

**Negative control — without this the result is void.** `git submodule status` must FAIL:

```
fatal: 'submodule' appears to be a git command, but we were not
able to execute it. Maybe git-submodule is broken?
EXIT = 128
```

Only after 128 is observed does the positive arm mean anything. Install the binary under
the name Git actually searches for — **`sh.exe`** — and re-run.

### Measured A/B (single variable: our busybox on PATH)

| | Arm A: no shell | Arm B: our busybox as `sh.exe` |
|---|---|---|
| `git submodule status` | **exit 128** | exit 1 (shell found; hits CANDIDATE 3) |
| `git clone <local>` | **exit -1073741819 = `0xC0000005`** | **exit 0**, `done.` |
| Worktree files | **0** — 18 files of partial `.git` only | `README.md` 21 B, `second.txt` 30 B |
| Clone HEAD | — | **equals** source HEAD |
| `git fsck` | — | **exit 0** |
| `git status -sb` | — | `## master...origin/master`, clean |

`git_shell_path()` did **not** fault with a valid shell present, so this does not sharpen
the NULL-deref beyond "missing dependency".

## Defects — see `VERIFICATION.md` for filing-ready write-ups

| | Severity | Where |
|---|---|---|
| CANDIDATE 1 — `make distclean` deletes 17 tracked files | **high** | busybox-w32 `Makefile:1132` |
| CANDIDATE 2 — `mingw64a_defconfig` clang-pinned, stage one exits 0 while failing | medium | busybox-w32 `configs/mingw64a_defconfig:83-84` |
| CANDIDATE 3 — `*MINGW*` glob can't tell MSYS2 bash from BusyBox ash | medium | git-for-windows/git `git-sh-setup:292` |

CANDIDATE 3 is **pre-existing and architecture-independent** — verified by running the
same three probes against an independent upstream-lineage ARM64 busybox
(SHA256 `4E510E35E642A32CC6B5A0E676E78513C91108DF6143F33737ECF5C3EEEB0369`), which behaves
identically. Not introduced by this build.

**None of these has been filed or reported upstream.**

## Portability finding — busybox-w32 is clean

Every x86 reference in the tree is a `#if defined(__i386__) || defined(__x86_64__)` guarded
fast path with a generic C fallback (`libbb/hash_md5_sha.c`, `libbb/hash_sha*_x86-*.S`,
`networking/tls_*`, `libbb/dump.c`, `archival/libarchive/bz/compress.c`,
`modutils/modutils-24.c`, `procps/powertop.c`). `include/platform.h` correctly selects
memcpy-based unaligned accessors and int-sized `smallint` for non-x86, and hard-sets
little-endian for `ENABLE_PLATFORM_MINGW32` (lines 181-187). **No bare opcode literals and
no `#ifdef __x86_64__` in any build script.**
