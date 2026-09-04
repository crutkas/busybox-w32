# Raw session transcripts — native ARM64 BusyBox-w32

Verbatim command output captured 2026-09-03/04 on Windows 11 Pro 10.0.28000, ARM64.
Reproduced here so the evidence survives independently of session state.

---

## 1. Toolchain proof — full compile → assemble → link → RUN

```
$ gcc -v
COLLECT_LTO_WRAPPER=.../mingwarm64/bin/../lib/gcc/aarch64-w64-mingw32/15.0.1/lto-wrapper.exe
Target: aarch64-w64-mingw32
Configured with: ../gcc/configure --prefix=/mingwarm64 --build=aarch64-w64-mingw32
  --host=aarch64-w64-mingw32 --target=aarch64-w64-mingw32 --with-arch=armv8-a
  --with-tune=generic --enable-languages=c,lto,c++,fortran --enable-threads=posix ...
Thread model: posix
gcc version 15.0.1 20250131 (experimental) (Rev2, Built by MSYS2 project)
```

First compile attempt — **DEFECT-B**, header default:

```
$ gcc -O2 -o smoke.exe smoke.c
smoke.c: In function 'main':
smoke.c:5:5: error: implicit declaration of function 'IsWow64Process2'; did you mean 'IsWow64Process'? [-Wimplicit-function-declaration]
    5 |     IsWow64Process2(GetCurrentProcess(), &p, &n);
      |     ^~~~~~~~~~~~~~~
      |     IsWow64Process
gcc exit=1
```

With the fix:

```
$ gcc -O2 -D_WIN32_WINNT=0x0A00 -o smoke.exe smoke.c
gcc exit=0

$ ./smoke.exe
hello from busybox-session smoke test
processMachine=0x0000 nativeMachine=0xAA64
sizeof(void*)=8
compiler-macro: __aarch64__ defined
run exit=0

sha256 : 04ACA517334D20FE951461DC07CA49FE2558CCC75C27DCB2FF7123CE1839EC79
machine: 0xAA64

$ objdump -p smoke.exe | grep 'DLL Name'
        DLL Name: KERNEL32.dll
        DLL Name: api-ms-win-crt-environment-l1-1-0.dll
        DLL Name: api-ms-win-crt-heap-l1-1-0.dll
        DLL Name: api-ms-win-crt-math-l1-1-0.dll
        DLL Name: api-ms-win-crt-private-l1-1-0.dll
        DLL Name: api-ms-win-crt-runtime-l1-1-0.dll
        DLL Name: api-ms-win-crt-stdio-l1-1-0.dll
        DLL Name: api-ms-win-crt-string-l1-1-0.dll
```

UCRT confirmed from the produced binary's own import table. No `msvcrt`.

---

## 2. CANDIDATE 2 — defconfig clang pinning, both stages

**Stage one — fails and still exits 0 (the silent-success pattern):**

```
$ make mingw64a_defconfig
...
.../scripts/gcc-version.sh: line 11: aarch64-w64-mingw32-clang: command not found
make exit=0
```

**Stage two — with only `CROSS_COMPILER=gcc`, the host-tool stage still dies:**

```
$ make CROSS_COMPILER=gcc V=1 -j8 busybox.exe
  clang -Wp,-MD,scripts/basic/.fixdep.d        -o scripts/basic/fixdep scripts/basic/fixdep.c
/bin/sh: line 1: clang: command not found
make[1]: *** [scripts/Makefile.host:123: scripts/basic/fixdep] Error 127
make: *** [Makefile:434: scripts_basic] Error 2
make exit=2
```

Config lines responsible:

```
$ grep -n '^CONFIG_\(CROSS\|HOST\)_COMPILER' configs/mingw64a_defconfig
83:CONFIG_HOST_COMPILER="clang"
84:CONFIG_CROSS_COMPILER="clang"

$ grep '^CONFIG_HOST_COMPILER=' configs/mingw*_defconfig
mingw32_defconfig:  CONFIG_HOST_COMPILER="gcc"
mingw32w_defconfig: CONFIG_HOST_COMPILER="gcc"
mingw64_defconfig:  CONFIG_HOST_COMPILER="gcc"
mingw64a_defconfig: CONFIG_HOST_COMPILER="clang"   <-- lone outlier
mingw64u_defconfig: CONFIG_HOST_COMPILER="gcc"
```

**Working build, both overrides:**

```
$ make CROSS_COMPILER=gcc HOST_COMPILER=gcc -j8 busybox.exe
  ...
  AR      libbb/lib.a
  LINK    busybox_unstripped.exe
Trying libraries: bcrypt secur32 ws2_32
 Library bcrypt is needed, can't exclude it (yet)
 Library secur32 is needed, can't exclude it (yet)
 Library ws2_32 is needed, can't exclude it (yet)
Final link with: bcrypt secur32 ws2_32
make exit=0

warnings/errors in log: 0
busybox.exe  756224 bytes
sha256 67665B44DB934B574C95A600955482D35F1BB421A9498998DF3E5BAA96313AA8
machine 0xAA64
```

**Fix verification — defconfig patched, ZERO command-line overrides:**

```
$ make mingw64a_defconfig          # no 'command not found', no clang reference
defconfig exit=0
$ make -j8 busybox.exe
  LINK    busybox_unstripped.exe
Final link with: bcrypt secur32 ws2_32
make exit=0
warnings/errors: 0
machine: 0xAA64
ash -c uname: MINGW(BusyBox/Win32) (exit 0)
```

---

## 3. CANDIDATE 1 — `make distclean` destroys the tree

Discovered while verifying the CANDIDATE 2 fix.

```
$ make distclean
  CLEAN   include/config
  CLEAN   .config include/NUM_APPLETS.h ...
$ echo $?
0

$ make mingw64a_defconfig && make -j8 busybox.exe
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

Blast radius — `win32/` drops from 75 tracked files to 58; the 17 deleted:

```
win32/arpa/inet.h       win32/sys/inotify.h     win32/sys/socket.h
win32/grp.h             win32/sys/ioctl.h       win32/sys/syscall.h
win32/net/if.h          win32/sys/mman.h        win32/sys/sysmacros.h
win32/netdb.h           win32/sys/select.h      win32/sys/times.h
win32/netinet/in.h      win32/resources/dummy.c win32/sys/un.h
win32/pwd.h             win32/sys/wait.h
```

All are tracked, none ignored, and all are zero bytes — the complete set of zero-byte
tracked files in the repo, i.e. a 100% hit rate:

```
$ git ls-files --error-unmatch win32/netdb.h ; echo $?
win32/netdb.h
0                                  # TRACKED

$ git check-ignore -v win32/netdb.h win32/pwd.h win32/sys/socket.h ; echo $?
1                                  # not ignored, no output

# all zero-byte TRACKED files in the whole repo:
count = 17                         # exactly the 17 deleted above
```

Culprit, `Makefile:1128-1134` — note `-o -size 0` on line 1132:

```make
distclean: mrproper
	@find $(srctree) $(RCS_FIND_IGNORE) \
		\( -name '*.orig' -o -name '*.rej' -o -name '*~' \
		-o -name '*.bak' -o -name '#*#' -o -name '.*.orig' \
		-o -name '.*.rej' -o -name '*.tmp' -o -size 0 \
		-o -name '*%' -o -name '.*.cmd' -o -name 'core' \) \
		-type f -print | xargs rm -f
```

---

## 4. Applet runs — evidence of effect

```
$ busybox.exe --list        ->  179 applets, exit 0
$ ash.exe -c uname
MINGW(BusyBox/Win32)
exit=0

$ busybox.exe sh -c 'echo hello'
hello
exit=0

$ busybox.exe sed 's/alpha/OMEGA/g' in.txt > sed-out.txt     # exit 0
--- sed-out.txt (37 bytes) ---
OMEGA beta
gamma delta
OMEGA zeta

$ busybox.exe awk '{ print $2 }' in.txt > awk-out.txt        # exit 0
--- awk-out.txt (19 bytes) ---
beta
delta
zeta

$ busybox.exe sh -c 'printf "z\na\nm\n" | sort > sorted.txt; wc -l < sorted.txt'
3
exit=0
--- sorted.txt (6 bytes) ---
a
m
z
```

---

## 5. Live-process nativity and module binding audit

```
=== LIVE PROCESS (pid 23924) IsWow64Process2 ===
ok=True processMachine=0x0000 nativeMachine=0xAA64

=== MODULES ACTUALLY BOUND BY THE LIVE PROCESS (raw COFF each) ===
0xAA64   ...\out\busybox.exe
0xAA64   C:\Windows\SYSTEM32\ntdll.dll
0xAA64   C:\Windows\System32\KERNEL32.DLL
0xAA64   C:\Windows\System32\KERNELBASE.dll
0xAA64   C:\Windows\System32\ADVAPI32.dll
0xAA64   C:\Windows\System32\msvcrt.dll
0xAA64   C:\Windows\System32\sechost.dll
0xAA64   C:\Windows\System32\RPCRT4.dll
0xAA64   C:\Windows\System32\bcrypt.dll
0xAA64   C:\Windows\System32\ucrtbase.dll
0xAA64   C:\Windows\System32\SHELL32.dll
0xAA64   C:\Windows\System32\msvcp_win.dll
0xAA64   C:\Windows\System32\USER32.dll
0xAA64   C:\Windows\System32\win32u.dll
0xAA64   C:\Windows\System32\GDI32.dll
0xAA64   C:\Windows\System32\gdi32full.dll
0xAA64   C:\Windows\SYSTEM32\Secur32.dll
0xAA64   C:\Windows\System32\WS2_32.dll
0xAA64   C:\Windows\SYSTEM32\CRYPTBASE.DLL
0xAA64   C:\Windows\SYSTEM32\SSPICLI.DLL
0xAA64   C:\Windows\System32\IMM32.DLL
0xAA64   C:\Windows\System32\shcore.dll
```

22 modules, all `0xAA64`, all from System32. No third-party DLL, no `msys-2.0.dll`, no
mingw runtime, no `libwinpthread-1.dll`, no `libgcc_s_*`.

Import table:

```
$ objdump -p busybox.exe | grep 'DLL Name'
        DLL Name: ADVAPI32.dll
        DLL Name: bcrypt.dll
        DLL Name: KERNEL32.dll
        DLL Name: api-ms-win-crt-conio-l1-1-0.dll
        DLL Name: api-ms-win-crt-convert-l1-1-0.dll
        DLL Name: api-ms-win-crt-environment-l1-1-0.dll
        DLL Name: api-ms-win-crt-filesystem-l1-1-0.dll
        DLL Name: api-ms-win-crt-heap-l1-1-0.dll
        DLL Name: api-ms-win-crt-locale-l1-1-0.dll
        DLL Name: api-ms-win-crt-math-l1-1-0.dll
        DLL Name: api-ms-win-crt-private-l1-1-0.dll
        DLL Name: api-ms-win-crt-process-l1-1-0.dll
        DLL Name: api-ms-win-crt-runtime-l1-1-0.dll
        DLL Name: api-ms-win-crt-stdio-l1-1-0.dll
        DLL Name: api-ms-win-crt-string-l1-1-0.dll
        DLL Name: api-ms-win-crt-time-l1-1-0.dll
        DLL Name: api-ms-win-crt-utility-l1-1-0.dll
        DLL Name: Secur32.dll
        DLL Name: SHELL32.dll
        DLL Name: USER32.dll
        DLL Name: WS2_32.dll
```

---

## 6. THE A/B — `git clone`, single variable

`git.exe` under test, named and hashed rather than taken from PATH:

```
path   : ...\gcc-native\git-install-FROZEN-69b1e704\bin\git.exe
sha256 : 69B1E704729CF69F0A0C029AA189EB9D38F74FC16EF37823048CB6A98B1523D1
machine: 0xAA64
size   : 4723261
git version 2.47.1
```

Source repo HEAD `e89204cd53de5625c56db2b5d1da7a354e48a8de`, two tracked files.

### ARM A — neutralised PATH, no shell

```
PATH = C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem
GIT_EXEC_PATH set? False  GIT_CONFIG_COUNT set? False  GIT_CONFIG_PARAMETERS set? False
  absent: sh.exe
  absent: bash.exe
  absent: sh
  absent: bash
  absent: busybox.exe

--- A1: NEGATIVE CONTROL: git submodule status ---
fatal: 'submodule' appears to be a git command, but we were not
able to execute it. Maybe git-submodule is broken?
EXIT = 128

--- A2: git clone ---
Cloning into '...\clone-noshell'...
EXIT = -1073741819              <-- 0xC0000005 ACCESS VIOLATION
worktree README.md present? False
worktree second.txt present? False
clone-noshell worktree files: 0
clone-noshell .git total: 18 files
```

### ARM B — same PATH plus our busybox as `sh.exe`

```
shell dir contains ONLY:
  sh.exe  756224 bytes

git will find sh at : ...\integ\shell\sh.exe
that file's sha256  : 67665B44DB934B574C95A600955482D35F1BB421A9498998DF3E5BAA96313AA8
handover  sha256    : 67665B44DB934B574C95A600955482D35F1BB421A9498998DF3E5BAA96313AA8

--- B1: POSITIVE CONTROL: git submodule status ---
.../git-submodule: .../git-sh-setup: line 303: builtin: not found
Unable to determine absolute path of git directory
EXIT = 1                        <-- off 128, so the shell IS found and executed

--- B2: git clone ---
Cloning into '...\clone-ourshell'...
done.
EXIT = 0
```

### Evidence of effect

```
--- worktree files actually on disk ---
Name       Length
.git
README.md  21
second.txt 30

README.md   : [hello arm64 busybox]
second.txt  : [second file for effect check]

source HEAD : e89204cd53de5625c56db2b5d1da7a354e48a8de
clone  HEAD : e89204cd53de5625c56db2b5d1da7a354e48a8de
HEADs EQUAL : True

--- git fsck on the clone ---
fsck exit=0
--- git status ---
## master...origin/master
--- git log ---
e89204c initial
```

---

## 7. CANDIDATE 3 — attribution control

Our build:

```
$ busybox sh -c 'uname -s'     -> MINGW(BusyBox/Win32)                exit 0
$ busybox sh -c 'builtin pwd'  -> sh: line 0: builtin: not found      exit 127
$ busybox sh -c 'pwd -W'       -> sh: pwd: line 0: illegal option -W  exit 2
```

Independent upstream-lineage ARM64 busybox, `0xAA64`, 336,384 bytes,
sha256 `4E510E35E642A32CC6B5A0E676E78513C91108DF6143F33737ECF5C3EEEB0369`:

```
$ ref sh -c 'uname -s'     -> MINGW(BusyBox/Win32)                exit 0
$ ref sh -c 'builtin pwd'  -> sh: line 0: builtin: not found      exit 127
$ ref sh -c 'pwd -W'       -> sh: pwd: line 0: illegal option -W  exit 2
applet count = 39
```

**Identical on all three probes.** The limitation is inherent to BusyBox ash and
pre-existing — not introduced by this build.

Offending code, `git-sh-setup:292-304`:

```sh
case $(uname -s) in
*MINGW*)
	sort () { /usr/bin/sort "$@"; }
	find () { /usr/bin/find "$@"; }
	pwd  () { builtin pwd -W; }
```

`MINGW(BusyBox/Win32)` matches `*MINGW*`, so ash takes the MSYS2-bash branch.

---

## 8. Correction to the first draft of this record

The initial A/B run used `...\git-clang-install\bin\git.exe`, sha256
`8F9F1D9FBDF4134F...`, 4,649,984 bytes — the **clang**-built git, not the pinned
`69b1e704...` GCC build. The directory name had been trusted instead of the hash. Found by
hashing every `git.exe` in the source session; the entire A/B was then re-run from scratch
against the pinned binary. **Both produce the same result**, but only the pinned run is
reported above.
