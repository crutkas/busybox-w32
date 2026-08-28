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

### PowerShell parameter contracts

The parameter sweep ranks contracts by trust boundary:

1. The manually supplied candidate and module-policy paths deliberately accept
   null and empty strings so the diagnostic records them as blocked. The
   evidence output path, executable paths, repository roots, record IDs, and
   schema labels reject null and empty values with
   `ValidateNotNullOrEmpty`.
2. Candidate PE byte arrays accept an empty collection so a zero-byte file
   reaches the structural parser and produces a field-specific failure; null
   byte arrays are rejected. Empty section and module collections likewise
   reach structural or exact-set comparison, while null collections do not.
3. Source/config text, captured output, and file content accept an empty string
   so missing content is evaluated or recorded; a true null string is rejected.
   Optional environment observations accept both because absence is itself
   evidence that the native-environment policy fails.
4. The canonical value writer accepts JSON null, empty strings, and empty
   arrays as distinct framed values. The outer evidence document and
   repository root reject absence. Policy-validation helpers admit null and
   empty external values only far enough to issue their explicit schema/type
   rejection instead of failing incidentally in PowerShell binding.

`ValidateNotNullOrEmpty` remains on parameters for which both cases are
invalid; the sweep does not make deliberate rejection permissive. The source
test extracts each exact declaration and exercises it in an isolated advanced
function. It uses `Language.NullString` to distinguish a true null string from
an empty string (ordinary PowerShell `$null` converts to empty during string
binding), creates a typed zero-length array for collection checks, requires
allowed cases to reach a sentinel body, and requires rejected cases to be a
`ParameterBindingValidationException` that names the parameter and the
null/empty reason. This prevents an unrelated function-body exception from
satisfying a contract test.

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

### Canonical evidence digest

The raw evidence JSON intentionally retains absolute observed paths, so its
file SHA-256 is checkout-local and must not be published as a reproducible
digest. The diagnostic also writes
`<EvidencePath>.canonical-sha256.json`. This closed-schema sidecar names
canonicalization `busybox-arm64-evidence-canonical-v1`, SHA-256, the canonical
byte length, and the lowercase digest.

The evidence JSON is written first. Any previous sidecar is removed, and the
new digest is computed from a fresh parse of the exact JSON just emitted. Thus
the documented auditor procedure and the publisher hash the same JSON value
model, including arbitrary-size integers. A canonicalization or sidecar-write
failure remains a nonzero diagnostic failure, leaves no stale digest, and does
not suppress the underlying evidence document.

The canonical byte stream starts with the ASCII scheme name followed by LF,
then recursively frames the complete evidence document:

- null is `N;`, booleans are `B0;` or `B1;`, and integers are `I`, their
  invariant decimal representation, and `;`;
- ordinary strings use `S<byte-count>:<strict-UTF-8-bytes>`, while object keys
  use the otherwise identical `K` tag;
- a fully qualified string scalar lexically beneath the repository root uses
  `P<byte-count>:<strict-UTF-8-bytes>`, with the root removed and directory
  separators changed to `/`; the repository root itself is `.`;
- arrays use `A<count>[<framed-values>]`; objects use
  `O<count>{<framed-key><framed-value>...}` with keys sorted by ordinal value.

There is no BOM or trailing newline. Unsupported value types abort
canonicalization. External paths and strings containing embedded paths remain
byte-exact. Distinct `P` and `S` tags prevent a normalized path from colliding
with an ordinary string, and length framing prevents field-boundary ambiguity.
Only the checkout-root prefix is deliberately nonsemantic; record content,
relative paths, array order, value types, and unknown keys all affect the
digest.

The versioned known-answer vector is the following two lines joined by one LF
and no terminal newline:

```text
busybox-arm64-evidence-canonical-v1
O3{K1:aP26:configs/mingw64a_defconfigK7:literalS26:configs/mingw64a_defconfigK1:zA6[N;B1;B0;I-2;I3;S1:x]}
```

It is 141 bytes and has SHA-256
`a4f09935a9b7fde67c6669d4fbcfba649fbbf71d6919bada2956172ad63d480e`.
The `a` value is an absolute repository path; `literal` contains the same
repository-relative text as an ordinary string. Floating-point and other
unspecified value types are rejected.

An auditor recomputes the sidecar from the parsed document and the checkout
root:

```powershell
Import-Module testsuite\arm64\Arm64Validation.psm1 -Force
$document = Get-Content C:\evidence\busybox-arm64.json -Raw |
  ConvertFrom-Json
Get-EvidenceCanonicalDigest -Document $document `
  -RepositoryRoot (Get-Location)
```

The source checks run the blocked diagnostic from two distinct working
directories, require different raw JSON hashes but identical canonical
digests, recompute both sidecars, and mutation-test record content, relative
paths, extra keys, the path-versus-string type boundary, rejected numeric
policy types, and `UInt64`/`BigInteger` JSON round trips. The digest is
diagnostic integrity metadata only and has no admission authority.

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
expected-versus-observed difference fail closed. `schemaVersion` must be the
JSON integer `1`; identities, authority, imports, and module fields must be
strings of the documented form; and `imports`, `delayImports`, and `modules`
must be JSON arrays. Alternate scalar types are rejected before they can enter
evidence as trusted policy values.

## Unmet gates

- No `git-for-windows/setup-git-for-windows-sdk` ref is approved. Its action
  implementation resolves a moving SDK branch and has no SDK-lock input.
- No exact SDK commit/tree/manifest bootstrap is admitted in this repository.
- No corrected runtime, compiler, binutils, package snapshot, or private-root
  authority is admitted.
- No genuine native ARM64 Windows run exists for this source packet.

Until those external gates are independently satisfied, the native diagnostic
must remain dormant and its output non-consumable.
