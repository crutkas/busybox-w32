# ARM64 busybox-w32 — verification record

Date: 2026-09-03. Host: Windows 11 Pro 10.0.28000, ARM64.

## Deliverable

| | |
|---|---|
| Path | `C:\Users\crutkasLocal\.copilot\session-state\1e7a7fd3-02e7-432a-a09c-5502ed8992a6\files\handover\busybox.exe` |
| SHA256 | `67665B44DB934B574C95A600955482D35F1BB421A9498998DF3E5BAA96313AA8` |
| Size | 756,224 bytes |
| PE machine | `0xAA64` (raw: `0x3C` → PE sig `0x00004550` → `Machine`) |
| Applets | 179 |

Also staged: `busybox_unstripped.exe` (1,492,196 bytes, SHA256
`EA9B3EC7F569A8BA5110DF0B169B730F113824E47C4FC890840E675359CE12FD`) and
`mingw64a-gcc.config`.

## Provenance

- Source: busybox-w32 worktree HEAD `d8d8bb397`, clean tree, exported with
  `git archive` into the session folder. **The repo checkout was never written to.**
- Compiler: native ARM64 GCC 15.0.1 20250131, target `aarch64-w64-mingw32`,
  threads posix, `--with-arch=armv8-a`. Staged copy under `bb-arm64\toolchain`.
- Build driver: MSYS2 `make` 4.4.1 (`x86_64-pc-msys`, **emulated x64**) plus
  Git for Windows `usr\bin`. **MEASURED, and labelled: an emulated x64 driver
  invoking a native ARM64 compiler.** Driver architecture has no bearing on output
  architecture, which is proven independently below.
- Recipe (no source changes):
  ```
  make mingw64a_defconfig
  make CROSS_COMPILER=gcc HOST_COMPILER=gcc -j8 busybox.exe
  ```
- Result: **exit 0, zero warnings, zero errors** under `CONFIG_WERROR=y`.

## Toolchain proof (full compile → assemble → link → RUN)

`smoke.exe`, SHA256 `04ACA517334D20FE951461DC07CA49FE2558CCC75C27DCB2FF7123CE1839EC79`,
PE `0xAA64`, ran exit 0 printing `processMachine=0x0000 nativeMachine=0xAA64`,
`sizeof(void*)=8`, `__aarch64__ defined`. Import table UCRT-only, no msvcrt.

## Nativity — from the LIVE PROCESS

`IsWow64Process2` on running `busybox.exe` (pid 23924):
**`processMachine=0x0000, nativeMachine=0xAA64`** — native, not emulated.

## Module binding audit — what the process ACTUALLY BINDS

All 22 loaded modules `0xAA64`, **every one from `C:\Windows\System32`**:
ntdll, KERNEL32, KERNELBASE, ADVAPI32, msvcrt, sechost, RPCRT4, bcrypt, ucrtbase,
SHELL32, msvcp_win, USER32, win32u, GDI32, gdi32full, Secur32, WS2_32, CRYPTBASE,
SSPICLI, IMM32, shcore.

**Zero third-party DLLs. No `msys-2.0.dll`, no mingw runtime, no `libwinpthread-1.dll`,
no `libgcc_s_*`.** Import table is UCRT-only (`api-ms-win-crt-*-l1-1-0.dll`) plus
ADVAPI32 / bcrypt / KERNEL32 / Secur32 / SHELL32 / USER32 / WS2_32.

## Acceptance bar

- PE machine `0xAA64` — PASS
- `ash.exe -c uname` → `MINGW(BusyBox/Win32)`, exit 0 — PASS

## Applet runs — evidence of EFFECT, not exit codes

| Command | Exit | Effect |
|---|---|---|
| `busybox sh -c 'echo hello'` | 0 | printed `hello` |
| `busybox sed 's/alpha/OMEGA/g' in.txt > sed-out.txt` | 0 | **sed-out.txt, 37 B**: `OMEGA beta / gamma delta / OMEGA zeta` |
| `busybox awk '{ print $2 }' in.txt > awk-out.txt` | 0 | **awk-out.txt, 19 B**: `beta / delta / zeta` |
| `busybox sh -c 'printf "z\na\nm\n" \| sort > sorted.txt; wc -l < sorted.txt'` | 0 | printed `3`; **sorted.txt, 6 B**: `a / m / z` |
| `busybox --list` | 0 | 179 applets |

## Environment control + negative control

Neutralised: PATH reduced to `C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem`
(strips `C:\Program Files\Git\bin`, `…\Git\usr\bin`, and the bundled
`github-copilot-git-2.53.0-4` entries). `GIT_EXEC_PATH`, `GIT_CONFIG_COUNT`,
`GIT_CONFIG_PARAMETERS` removed from the environment.

Proof the control took effect: `Get-Command sh.exe/bash.exe` → **not found**, and
the established negative control

```
git submodule status
fatal: 'submodule' appears to be a git command, but we were not
able to execute it. Maybe git-submodule is broken?
EXIT CODE = 128
```

With our busybox as `sh.exe` the same command moves to **exit 1** with a shell
diagnostic from inside `git-sh-setup` — proving the shell is now found and executed.

## DECISIVE INTEGRATION TEST — `git clone`

**git.exe under test — the pinned GCC-native build, named explicitly:**

| | |
|---|---|
| Path | `…\2918d1f1-…\files\gcc-native\git-install-FROZEN-69b1e704\bin\git.exe` |
| SHA256 | `69B1E704729CF69F0A0C029AA189EB9D38F74FC16EF37823048CB6A98B1523D1` |
| PE machine | `0xAA64` |
| Size | 4,723,261 bytes |
| `git --version` | `git version 2.47.1` |

Obtained from session `2918d1f1`; **not built here, not found on PATH.**

> **Correction to the first draft of this record.** My initial run used
> `…\files\git-clang-install\bin\git.exe`, SHA256 `8F9F1D9FBDF4134F…`, 4,649,984 bytes —
> the **clang**-built git, *not* the pinned `69b1e704…` GCC build. Caught by hashing every
> `git.exe` in session `2918d1f1` instead of trusting the directory name. The whole A/B
> below was re-run from scratch against the pinned binary. Both produce the same result,
> but only the pinned one is reported.

Single variable = our busybox on PATH. Source repo HEAD
`e89204cd53de5625c56db2b5d1da7a354e48a8de`, two tracked files.

### Arm A — neutralised PATH, no shell

Leak check ran **first**: `sh.exe`, `bash.exe`, `sh`, `bash`, `busybox.exe` all **absent**
from PATH, and `GIT_EXEC_PATH` / `GIT_CONFIG_COUNT` / `GIT_CONFIG_PARAMETERS` all confirmed
unset **in the same process that ran the test**.

**A1 — negative control:**
```
git submodule status
fatal: 'submodule' appears to be a git command, but we were not
able to execute it. Maybe git-submodule is broken?
EXIT = 128
```

**A2 — clone:**
```
git clone <src> clone-noshell
Cloning into '...clone-noshell'...
EXIT = -1073741819        <-- 0xC0000005 ACCESS VIOLATION
```
Effect: **0 worktree files**; `README.md` absent, `second.txt` absent; 18 files of partial
`.git` left behind. **The brief's crash, reproduced exactly on the pinned binary.**

### Arm B — same PATH plus our busybox installed as `sh.exe`

**Applet name:** the shell directory contained **only `sh.exe`** (756,224 bytes) — the exact
name `git_shell_path()` looks for via `locate_in_PATH("sh")`. No `busybox.exe`, no
`ash.exe` alongside it, so dispatch cannot have succeeded under some other name.
`Get-Command sh.exe` resolved to that file and its SHA256 is
`67665B44DB934B574C95A600955482D35F1BB421A9498998DF3E5BAA96313AA8` — **identical to the
handover binary**, verified in place rather than assumed.

**B1 — positive control:** exit **1**, with the diagnostic coming from *inside*
`git-sh-setup`. Moving off 128 is what proves the shell is now found and executed; it then
hits FINDING-C below.

**B2 — clone:**
```
git clone <src> clone-ourshell
Cloning into '...clone-ourshell'...
done.
EXIT = 0
```

**Verified by EFFECT, not exit code:**
- `README.md` on disk, **21 bytes**, contents `hello arm64 busybox`
- `second.txt` on disk, **30 bytes**, contents `second file for effect check`
- clone HEAD `e89204cd53de5625c56db2b5d1da7a354e48a8de` **equals** source HEAD
- `git fsck` → **exit 0**, no corruption
- `git status --short --branch` → `## master...origin/master`, clean
- `git log --oneline` → `e89204c initial`

`git_shell_path()` did **not** fault with a valid shell present, so this run does not
sharpen the NULL-deref beyond "missing dependency".

## Defects

### DEFECT-A (busybox-w32, config) — `mingw64a_defconfig` is clang-only by construction
`configs/mingw64a_defconfig` is the **only** mingw defconfig pinning both
`CONFIG_CROSS_COMPILER="clang"` (line 84) and `CONFIG_HOST_COMPILER="clang"`.
mingw32 / mingw32w / mingw64 / mingw64u all say `"gcc"`.

Two-stage symptom; the second is the nasty one because the first does not stop the build:
1. `scripts/gcc-version.sh: line 11: aarch64-w64-mingw32-clang: command not found`
   during `make mingw64a_defconfig`, which nonetheless **exits 0**.
2. Host-tool stage dies: `clang: command not found` →
   `make[1]: *** [scripts/Makefile.host:123: scripts/basic/fixdep] Error 127`.

Fixing only `CROSS_COMPILER` is insufficient — `HOST_COMPILER` must be set too.
Workaround needs no source change (`Makefile:199-219` honours the command line ahead
of `.config`). Every prior ARM64 branch in the repo is clang-based, so this is very
likely the first GCC build of the aarch64 config.

### DEFECT-B (our toolchain, minor) — `IsWow64Process2` needs `_WIN32_WINNT=0x0A00`
mingw-w64 headers at this rev do not declare it by default:
`error: implicit declaration of function 'IsWow64Process2'; did you mean
'IsWow64Process'?`, exit 1. Fixed with `-D_WIN32_WINNT=0x0A00`. Header-default
finding, not a blocker; did not affect the busybox build.

### FINDING-C (git ↔ BusyBox ash, NOT ours, NOT architectural) — `git submodule` fails
`git-sh-setup:292` does `case $(uname -s) in *MINGW*)`. BusyBox `uname -s` returns
`MINGW(BusyBox/Win32)`, which **matches**, so the script takes the MSYS2-bash branch:
```
pwd () { builtin pwd -W ; }      # line 302-304
sort () { /usr/bin/sort "$@" ; } # line 295-297
find () { /usr/bin/find "$@" ; } # line 298-300
```
BusyBox ash has **no `builtin` command** and **no `pwd -W`**, and a BusyBox-only MinGit
has no `/usr/bin/sort` or `/usr/bin/find`. Result:
`git-sh-setup: line 303: builtin: not found` → `Unable to determine absolute path of
git directory`, exit 1.

**Verified NOT specific to our build.** The reference ARM64 busybox
(`…aabca41f…\tools\busybox.exe`, `0xAA64`, 336,384 B, SHA256 `4E510E35…`) behaves
**identically**: `uname -s` → `MINGW(BusyBox/Win32)`; `builtin pwd` → exit 127
`builtin: not found`; `pwd -W` → exit 2 `illegal option -W`. Inherent to BusyBox ash,
affects x86-64 busybox-w32 equally. Consistent with the known-broken MinGit-BusyBox
issues listed in `AGENTS.md` (e.g. git-for-windows/git#5184, #6107).

**Does not affect `git clone`**, which is a C builtin and only needs `sh` to exist.

### DEFECT-D (busybox-w32, build system, HIGH) — `make distclean` deletes 17 tracked files
`Makefile:1132`'s `-o -size 0` predicate deletes every zero-byte file in the tree. All 17
zero-byte tracked files — the win32 POSIX-compat stub headers — are destroyed, leaving the
tree unbuildable with `fatal error: netdb.h: No such file or directory`. `distclean` itself
exits 0. Architecture-independent. Full write-up as **CANDIDATE 1** below.

## Portability finding — busybox-w32 needed ZERO source changes

Every x86 hit in the tree is a `#if defined(__i386__) || defined(__x86_64__)` guarded
fast path with a generic C fallback: `libbb/hash_md5_sha.c`, `libbb/hash_sha*_x86-*.S`,
`networking/tls_*`, `libbb/dump.c`, `archival/libarchive/bz/compress.c`,
`modutils/modutils-24.c`, `procps/powertop.c`. `include/platform.h` correctly falls to
memcpy-based unaligned accessors and int-sized `smallint` for non-x86, and hard-sets
little-endian for `ENABLE_PLATFORM_MINGW32` (lines 181-187). **No bare opcode literals.
No `#ifdef __x86_64__` in any build script.**

## Comparison to the reference stand-in

| | Ours | Reference |
|---|---|---|
| PE machine | `0xAA64` | `0xAA64` |
| Size | 756,224 B | 336,384 B |
| Applets | **179** | 39 |
| `ash -c uname` | `MINGW(BusyBox/Win32)` | `MINGW(BusyBox/Win32)` |

Ours is a full shell layer (`ash sh bash sed awk grep sort cut tar gzip wget diff patch
find xargs less stty`, plus downstream `cygpath`), not a bootstrap subset.

## UPSTREAM-FILING CANDIDATES (filing-ready — NOT filed, NOT committed)

Three candidates. All symptoms verbatim. **None has been filed or committed; gates
unchanged. The decision to file is the user's.**

---

### CANDIDATE 1 — `make distclean` deletes 17 tracked source files, leaving the tree unbuildable

**Severity: high.** Architecture-independent — affects x86-64 and i686 identically.
Found accidentally while validating Candidate 2.

**File / line:** `Makefile:1128-1134`, specifically the predicate **`-o -size 0`** on line 1132.

```make
distclean: mrproper
	@find $(srctree) $(RCS_FIND_IGNORE) \
		\( -name '*.orig' -o -name '*.rej' -o -name '*~' \
		-o -name '*.bak' -o -name '#*#' -o -name '.*.orig' \
		-o -name '.*.rej' -o -name '*.tmp' -o -size 0 \
		-o -name '*%' -o -name '.*.cmd' -o -name 'core' \) \
		-type f -print | xargs rm -f
```

**Root cause:** `-size 0` matches **every zero-byte file in the tree**, with no regard for
whether it is a generated artefact or tracked source. busybox-w32's win32 POSIX-compat
layer deliberately ships **empty stub headers** so that `#include <netdb.h>` and friends
resolve to nothing on Windows. `distclean` deletes all of them.

**Blast radius — exact, and it is 100%.** The repo contains exactly **17** zero-byte
tracked files (mechanism: `git ls-files` + per-file length check at HEAD `d8d8bb397`), and
`distclean` deleted **all 17**:

```
win32/arpa/inet.h      win32/sys/inotify.h    win32/sys/socket.h
win32/grp.h            win32/sys/ioctl.h      win32/sys/syscall.h
win32/net/if.h         win32/sys/mman.h       win32/sys/sysmacros.h
win32/netdb.h          win32/sys/select.h     win32/sys/times.h
win32/netinet/in.h     win32/resources/dummy.c win32/sys/un.h
win32/pwd.h            win32/sys/wait.h
```

All 17 confirmed **git-tracked** (`git ls-files --error-unmatch` → exit 0 for each) and
**not gitignored** (`git check-ignore -v` → exit 1, no match). `win32/` drops from 75
tracked files to 58.

**Minimal reproducer** (any host, any arch):
```
git clone <busybox-w32> && cd busybox-w32
make mingw64a_defconfig
make distclean
git status --porcelain        # 17 deletions of tracked files
make mingw64a_defconfig && make busybox.exe
```

**Verbatim symptom:**
```
sed: can't read .../win32/resources/*.c: No such file or directory
  CC      applets/applets.o
In file included from include/busybox.h:8,
                 from applets/applets.c:9:
include/libbb.h:26:10: fatal error: netdb.h: No such file or directory
   26 | #include <netdb.h>
      |          ^~~~~~~~~
compilation terminated.
make[1]: *** [scripts/Makefile.build:198: applets/applets.o] Error 1
make: *** [Makefile:449: applets_dir] Error 2
```

**Fix:** drop `-size 0` from the predicate. It is the only clause matching on size rather
than on a build-artefact name pattern, and every other clause is a name glob. If the intent
was to sweep truncated build leftovers, scope it to generated output rather than `$(srctree)`.
`RCS_FIND_IGNORE` on line 1129 only excludes the `.git` directory itself; it gives no
protection to tracked files in the worktree.

**Note:** `git status` makes recovery obvious in a git checkout, so the damage is easily
undone — but it is silent from `make`'s point of view (`distclean` exits **0**), and in a
tarball-based build, or the PKGBUILD's extracted `src/busybox-w32/`, there is no `git
checkout` to recover with.

---

### CANDIDATE 2 — `configs/mingw64a_defconfig` is clang-only by construction

**Severity: medium.** Blocks any GCC build of the aarch64 configuration.

**File / lines:** `configs/mingw64a_defconfig:83` and `:84`.
```
CONFIG_HOST_COMPILER="clang"
CONFIG_CROSS_COMPILER="clang"
```
`mingw64a_defconfig` is the **only** mingw defconfig doing this. All four of
`mingw32_defconfig`, `mingw32w_defconfig`, `mingw64_defconfig`, `mingw64u_defconfig` say
`"gcc"` for both.

**⚠️ THE SILENT-SUCCESS PATTERN — CALL THIS OUT PROMINENTLY. STAGE ONE EXITS 0 WHILE
HAVING FAILED.** This is the single most consequential thing about this defect, and it is
the most recurring defect class in this programme:

```
$ make mingw64a_defconfig
...
.../scripts/gcc-version.sh: line 11: aarch64-w64-mingw32-clang: command not found
$ echo $?
0                          <-- FAILED, REPORTED SUCCESS
```

The compiler-probe failure is printed to stderr and then **discarded**; `make` returns 0
and writes a `.config` regardless. Anyone eyeballing exit codes — or any CI step gated on
`make defconfig` succeeding — sees a pass. The real failure surfaces much later, in a
different subsystem, with a message that does not mention the defconfig at all:

```
  clang -Wp,-MD,scripts/basic/.fixdep.d  -o scripts/basic/fixdep scripts/basic/fixdep.c
/bin/sh: line 1: clang: command not found
make[1]: *** [scripts/Makefile.host:123: scripts/basic/fixdep] Error 127
make: *** [Makefile:434: scripts_basic] Error 2
```

**A partial fix is a trap.** Setting only `CROSS_COMPILER=gcc` clears stage one and still
dies at stage two, because `CONFIG_HOST_COMPILER` is read independently
(`Makefile:199-208` vs `210-219`). Both must be set.

**Fix — one line each, and VERIFIED, not proposed:**
```diff
-CONFIG_HOST_COMPILER="clang"
-CONFIG_CROSS_COMPILER="clang"
+CONFIG_HOST_COMPILER="gcc"
+CONFIG_CROSS_COMPILER="gcc"
```
Applied to a staged copy and rebuilt from a clean `.config` with **zero command-line
overrides**: `make mingw64a_defconfig` (no `command not found`, no clang reference) then
`make -j8 busybox.exe` → **exit 0, zero warnings, zero errors**, output `0xAA64`,
`ash -c uname` → `MINGW(BusyBox/Win32)` exit 0.

**Command-line workaround needing no source change** (`Makefile:199-219` honours the
command line ahead of `.config`):
```
make CROSS_COMPILER=gcc HOST_COMPILER=gcc -j8 busybox.exe
```

**Context:** every prior ARM64 branch in this fork is clang-based, so this is very likely
the first GCC build of the aarch64 config. Aligning these two lines with the other four
defconfigs makes the config toolchain-agnostic; clang users already pass
`CROSS_COMPILER=clang` on other targets.

---

### CANDIDATE 3 — `git-sh-setup`'s `*MINGW*` glob cannot distinguish MSYS2 bash from BusyBox ash

**Severity: medium.** Repository: **git-for-windows/git**, not busybox-w32.
**Pre-existing and architecture-independent — NOT introduced by our build.**

**File / line:** `libexec/git-core/git-sh-setup:292` (shipped from
`git-sh-setup.sh` in the git tree).

```sh
case $(uname -s) in
*MINGW*)
	sort () { /usr/bin/sort "$@"; }      # 295-297
	find () { /usr/bin/find "$@"; }      # 298-300
	pwd  () { builtin pwd -W; }          # 302-304
	...
```

**Root cause:** the glob `*MINGW*` is intended to detect MSYS2 **bash**, but BusyBox's
`uname -s` returns `MINGW(BusyBox/Win32)`, which also matches. The branch then executes
three things BusyBox ash cannot provide: `builtin` (a bash builtin ash does not implement),
`pwd -W` (an MSYS2 bash extension), and absolute paths `/usr/bin/sort` and `/usr/bin/find`
which do not exist in a BusyBox-only MinGit.

**Verbatim symptom** (native ARM64 git `69b1e704…`, BusyBox as `sh` on PATH):
```
.../git-submodule: .../git-sh-setup: line 303: builtin: not found
Unable to determine absolute path of git directory
EXIT = 1
```

**Three-probe reproducer:**
```
busybox sh -c 'uname -s'    -> MINGW(BusyBox/Win32)   exit 0
busybox sh -c 'builtin pwd' -> sh: line 0: builtin: not found        exit 127
busybox sh -c 'pwd -W'      -> sh: pwd: line 0: illegal option -W    exit 2
```

**ATTRIBUTION CONTROL — this is the part that makes it a finding rather than a suspected
regression in our build.** The same three probes were run against an independent
upstream-lineage ARM64 busybox (`…aabca41f…\tools\busybox.exe`, `0xAA64`, 336,384 bytes,
SHA256 `4E510E35E642A32CC6B5A0E676E78513C91108DF6143F33737ECF5C3EEEB0369`) and produced
**identical results on all three** — `MINGW(BusyBox/Win32)`, exit 127, exit 2. The
limitation is therefore inherent to BusyBox ash, pre-existing, and equally present on
x86-64 busybox-w32. **Not ours.**

**Fix options** (git side): tighten the discriminator so it does not fire for BusyBox — e.g.
test for the bash capability directly (`type builtin >/dev/null 2>&1`) rather than pattern-
matching `uname -s`; or match the MSYS2-specific `uname -s` forms (`MINGW32_NT-*`,
`MINGW64_NT-*`, `MSYS_NT-*`) instead of the loose `*MINGW*`. Alternatively (busybox side)
`uname -s` could return a string that does not contain `MINGW`, but that would be a
compatibility break for other consumers and is the worse option.

**Scope:** does **not** affect `git clone`, which is a C builtin and only requires `sh` to
exist. Consistent with the known-broken MinGit-BusyBox issues in `AGENTS.md` —
git-for-windows/git#5184 (`!` aliases) and #6107 (`git push`, `-c: applet not found`) — and
may well be the shared root cause of that family.

## Labelling

All of the above is **MEASURED** unless stated. The only **DERIVED** claims are:
- FINDING-C / CANDIDATE 3 affects x86-64 busybox-w32 equally — derived from `builtin` and
  `pwd -W` being absent from BusyBox ash generally, corroborated by identical behaviour on
  an independent upstream-lineage reference binary.
- DEFECT-D / CANDIDATE 1 affects other architectures equally — derived from the `distclean`
  rule being architecture-independent and the 17 casualties being ordinary tracked files;
  the deletion itself was **MEASURED** on this host.

Nothing here is **PRESUMED**.

**Gates:** nothing was committed, pushed, PR'd, CI-triggered, merged, or sent upstream. The
repo worktree is clean at `d8d8bb397`. All builds, edits and tests happened inside the
session folder against a `git archive` export.
