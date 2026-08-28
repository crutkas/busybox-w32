# Native Windows ARM64 diagnostics

These files define dormant, diagnostic-only checks for a future native Windows
ARM64 BusyBox build. They do not build BusyBox, acquire a toolchain, download a
binary, publish an artifact, or grant admission.

The C sources, configuration, build logic, and workflows remain byte-identical
to fork `main` commit
`d8d8bb397f1e200ba5a871dc6aa4af819b23f32a` (tree
`37fb55f5335e63c9f14c44208ed08a6e9aad4f91`). No native ARM64 execution was
performed when these diagnostics were added.

## Source checks

Run the source-only checks with PowerShell 7:

```powershell
pwsh -NoProfile -File testsuite\arm64\test-validation-assets.ps1
```

The checks inventory every current ARM64 dispatch surface, preserve the
existing x86/x64 `uname` mappings, inspect compiler/tool and link-mode
selection, parse deterministic synthetic PE files, and mutation-test:

- an AMD64 machine value in place of PE Machine `0xAA64`;
- missing imports or unexpected CHPE metadata;
- malformed DOS and PE signatures;
- x64 or emulated process-architecture fallbacks;
- `CONFIG_STATIC` or `CONFIG_STATIC_LIBGCC` being enabled;
- an x64 compiler prefix or missing/incorrect ARM64 `uname` case.

These checks inspect source policy only. They are not build or runtime evidence.

## Dormant native diagnostic

`validate-native.ps1` must be invoked manually on genuine ARM64 Windows
hardware, with an already-built binary and a module policy supplied by an
independent review:

```powershell
pwsh -NoProfile -File testsuite\arm64\validate-native.ps1 `
  -BusyBoxPath C:\candidate\busybox.exe `
  -ModulePolicyPath C:\independent\module-policy.json `
  -EvidencePath C:\evidence\busybox-arm64.json
```

The candidate must be named `busybox.exe` and have a sibling `.config`.
Ignoring generated comments, that configuration must exactly match every
setting in `configs/mingw64a_defconfig`; alternate Make assignments and other
noncanonical lines are rejected. The test harness receives explicit `bindir`
and `tsdir` values, fixes `ECHO=echo` so the inherited harness cannot compile
its fallback helper, verifies `busybox.exe --list`, and passes that exact
applet inventory to the full suite. A `SKIPPED: ... (not built)` result fails
the gate, and the harness never discovers a repository-root binary implicitly.

There is deliberately no mode to generate a module policy. A missing binary,
matching sibling config, policy, hardware capability, test harness, or
readable PE/module identity is reported as `blocked`, `failed`, or `skipped`,
produces a nonzero exit, and is never treated as a pass.

The diagnostic emits exactly 17 ordered records. Every record has the closed
key set `id`, `status`, `expected`, `observed`, and `detail`; statuses are
limited to `pass`, `fail`, `blocked`, and `skipped`. The document reports exact
totals and always identifies its authority as `diagnostic-only` with admission
`not-evaluated`.

Architecture evidence is layered:

1. .NET `RuntimeInformation` records the OS and diagnostic-process
   architectures. `PROCESSOR_ARCHITECTURE`, `PROCESSOR_ARCHITEW6432`, and
   `uname -m` are only corroborating observations.
2. The PE parser requires the DOS and PE signatures, COFF Machine `0xAA64`,
   PE32+, console subsystem, executable (not DLL) characteristics, and a
   pure ARM64 image without a CHPE metadata pointer.
3. Direct and delay imports are parsed structurally and compared with the
   independent policy.
4. A live, held BusyBox process is inspected through the OS process-module
   list. Each loaded file is recorded by the lexicographically first path from
   its filesystem hardlink set, volume serial, filesystem file ID, SHA-256,
   and PE Machine.
5. The live process image identity must match the supplied binary before
   its complete module set must match external policy. Only then are
   environment, `uname`, process/pipe behavior, 15-applet smoke cases, and the
   explicitly enumerated full suite run.

The current `mingw64a_defconfig` disables both `CONFIG_STATIC` and
`CONFIG_STATIC_LIBGCC`. Therefore the expected future criterion is explicitly
dynamic: imports must be nonempty and the exact imported and loaded module sets
must match an independently supplied policy. Nothing here is static-linkage
proof.

## External module policy

The policy is closed-schema JSON:

```json
{
  "schemaVersion": 1,
  "authority": "external-independent-review",
  "subject": {
    "canonicalPath": "C:\\candidate\\busybox.exe",
    "volumeSerial": "0123ABCD",
    "fileId": "00000000000000000000000000000001",
    "sha256": "<lowercase SHA-256>"
  },
  "imports": ["KERNEL32.dll"],
  "delayImports": [],
  "modules": [
    {
      "canonicalPath": "C:\\candidate\\busybox.exe",
      "volumeSerial": "0123ABCD",
      "fileId": "00000000000000000000000000000001",
      "sha256": "<lowercase SHA-256>",
      "peMachine": "0xAA64"
    }
  ]
}
```

Actual system DLL entries must also be enumerated. Unknown keys, duplicate
imports, duplicate canonical module paths, missing identities, and any
expected-versus-observed difference fail closed.

## Unmet gates

- No `git-for-windows/setup-git-for-windows-sdk` ref is approved. Its action
  implementation resolves a moving SDK branch and has no SDK-lock input.
- No exact SDK commit/tree/manifest bootstrap is admitted in this repository.
- No corrected runtime, compiler, binutils, package snapshot, or private-root
  authority is admitted.
- No genuine native ARM64 Windows run exists for this source packet.

Until those external gates are independently satisfied, the native diagnostic
must remain dormant and its output non-consumable.
