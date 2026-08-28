# SPDX-License-Identifier: GPL-2.0-only

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'Arm64Validation.psm1') -Force

$script:passed = 0
$script:failed = 0

function Invoke-TestCase {
	param(
		[Parameter(Mandatory)][string]$Name,
		[Parameter(Mandatory)][scriptblock]$Body
	)

	try {
		& $Body
		$script:passed++
		Write-Output "PASS: $Name"
	} catch {
		$script:failed++
		Write-Output "FAIL: $Name"
		Write-Output "  $($_.Exception.Message)"
	}
}

function Assert-True {
	param([bool]$Condition, [string]$Message)

	if (-not $Condition) {
		throw [InvalidOperationException]::new($Message)
	}
}

function Assert-Equal {
	param([object]$Expected, [object]$Observed, [string]$Message)

	if ([string]$Expected -cne [string]$Observed) {
		throw [InvalidOperationException]::new(
			"$Message; expected '$Expected', observed '$Observed'"
		)
	}
}

function Assert-NoFailures {
	param([object[]]$Failures, [string]$Scope)

	if ($Failures.Count -ne 0) {
		throw [InvalidOperationException]::new(
			"$Scope failed: $($Failures -join '; ')"
		)
	}
}

function Assert-Rejected {
	param([object[]]$Failures, [string]$Scope)

	if ($Failures.Count -eq 0) {
		throw [InvalidOperationException]::new(
			"$Scope was not rejected"
		)
	}
}

function Assert-Throws {
	param([scriptblock]$Body, [string]$Scope)

	$threw = $false
	try {
		& $Body
	} catch {
		$threw = $true
	}
	if (-not $threw) {
		throw [InvalidOperationException]::new(
			"$Scope did not throw"
		)
	}
}

function Set-UInt16LE {
	param([byte[]]$Bytes, [int]$Offset, [uint16]$Value)

	[BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset)
}

function Set-UInt32LE {
	param([byte[]]$Bytes, [int]$Offset, [uint32]$Value)

	[BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset)
}

function Set-UInt64LE {
	param([byte[]]$Bytes, [int]$Offset, [uint64]$Value)

	[BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset)
}

function Set-AsciiZ {
	param([byte[]]$Bytes, [int]$Offset, [string]$Value)

	$data = [Text.Encoding]::ASCII.GetBytes($Value)
	$data.CopyTo($Bytes, $Offset)
	$Bytes[$Offset + $data.Length] = 0
}

function New-SyntheticPe {
	param(
		[uint16]$Machine = [uint16]0xaa64,
		[bool]$IncludeImports = $true,
		[uint64]$ChpeMetadataPointer = 0
	)

	$bytes = [byte[]]::new(0x800)
	$peOffset = 0x80
	$optionalOffset = $peOffset + 24
	$optionalSize = 0xf0
	$sectionOffset = $optionalOffset + $optionalSize

	$bytes[0] = 0x4d
	$bytes[1] = 0x5a
	Set-UInt32LE $bytes 0x3c $peOffset
	$bytes[$peOffset] = 0x50
	$bytes[$peOffset + 1] = 0x45
	Set-UInt16LE $bytes ($peOffset + 4) $Machine
	Set-UInt16LE $bytes ($peOffset + 6) 1
	Set-UInt16LE $bytes ($peOffset + 20) $optionalSize
	Set-UInt16LE $bytes ($peOffset + 22) 0x0002

	Set-UInt16LE $bytes $optionalOffset 0x020b
	Set-UInt64LE $bytes ($optionalOffset + 24) 0x0000000140000000
	Set-UInt32LE $bytes ($optionalOffset + 32) 0x1000
	Set-UInt32LE $bytes ($optionalOffset + 36) 0x200
	Set-UInt32LE $bytes ($optionalOffset + 56) 0x2000
	Set-UInt32LE $bytes ($optionalOffset + 60) 0x200
	Set-UInt16LE $bytes ($optionalOffset + 68) 3
	Set-UInt32LE $bytes ($optionalOffset + 108) 16

	if ($IncludeImports) {
		Set-UInt32LE $bytes ($optionalOffset + 112 + 8) 0x1000
		Set-UInt32LE $bytes ($optionalOffset + 112 + 12) 40
		Set-UInt32LE $bytes 0x20c 0x1050
		Set-UInt32LE $bytes 0x210 0x1060
		Set-AsciiZ $bytes 0x250 'KERNEL32.dll'

		Set-UInt32LE $bytes ($optionalOffset + 112 + (13 * 8)) `
			0x1200
		Set-UInt32LE $bytes ($optionalOffset + 116 + (13 * 8)) 64
		Set-UInt32LE $bytes 0x400 1
		Set-UInt32LE $bytes 0x404 0x1250
		Set-UInt32LE $bytes 0x40c 0x1260
		Set-AsciiZ $bytes 0x450 'USER32.dll'
	}

	Set-UInt32LE $bytes ($optionalOffset + 112 + (10 * 8)) 0x1100
	Set-UInt32LE $bytes ($optionalOffset + 116 + (10 * 8)) 208
	Set-UInt32LE $bytes 0x300 208
	Set-UInt64LE $bytes (0x300 + 200) $ChpeMetadataPointer

	Set-AsciiZ $bytes $sectionOffset '.rdata'
	Set-UInt32LE $bytes ($sectionOffset + 8) 0x600
	Set-UInt32LE $bytes ($sectionOffset + 12) 0x1000
	Set-UInt32LE $bytes ($sectionOffset + 16) 0x600
	Set-UInt32LE $bytes ($sectionOffset + 20) 0x200
	return ,$bytes
}

function Get-ArchitectureSurfaceFiles {
	param([Parameter(Mandatory)][string]$RepositoryRoot)

	$tracked = @(& git -C $RepositoryRoot ls-files)
	if ($LASTEXITCODE -ne 0) {
		throw [InvalidOperationException]::new(
			'git ls-files failed while inventorying architecture surfaces'
		)
	}
	$surfaceFiles = @()
	foreach ($relativePath in $tracked) {
		if ($relativePath -notmatch '^(configs|examples/mswin-build|scripts|shell|win32)/') {
			continue
		}
		$path = Join-Path $RepositoryRoot `
			($relativePath -replace '/', '\')
		if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
			continue
		}
		$text = [IO.File]::ReadAllText($path)
		if ($text -match '(?i)aarch64|arm64|0xaa64') {
			$surfaceFiles += $relativePath
		}
	}
	return @($surfaceFiles | Sort-Object -Unique)
}

function Assert-MakeToolPolicy {
	param([Parameter(Mandatory)][string]$Text)

	$patterns = @(
		'(?m)^AS\s*=\s*\$\(CROSS_COMPILE\)as\r?$',
		'(?m)^CC\s*=\s*\$\(CROSS_COMPILE\)\$\(CROSS_COMPILER\)\r?$',
		'(?m)^AR\s*=\s*\$\(CROSS_COMPILE\)ar\r?$',
		'(?m)^NM\s*=\s*\$\(CROSS_COMPILE\)nm\r?$',
		'(?m)^STRIP\s*=\s*\$\(CROSS_COMPILE\)strip\r?$',
		'(?m)^OBJDUMP\s*=\s*\$\(CROSS_COMPILE\)objdump\r?$'
	)
	foreach ($pattern in $patterns) {
		$count = [regex]::Matches($Text, $pattern).Count
		if ($count -ne 1) {
			throw [InvalidOperationException]::new(
				"Make tool policy pattern '$pattern' occurs $count times"
			)
		}
	}
}

function Assert-LinkPolicy {
	param([Parameter(Mandatory)][string]$Text)

	foreach ($pattern in @(
		'(?s)ifeq\s+\(\$\(CONFIG_STATIC\),y\).*?CFLAGS_busybox\s*\+=\s*-static.*?endif',
		'(?s)ifeq\s+\(\$\(CONFIG_STATIC_LIBGCC\),y\).*?-static-libgcc.*?endif',
		'(?m)^LDLIBS\s*\+=\s*ws2_32 bcrypt secur32\r?$'
	)) {
		if (-not [regex]::IsMatch($Text, $pattern)) {
			throw [InvalidOperationException]::new(
				"Link policy pattern '$pattern' is absent"
			)
		}
	}
}

$repositoryRoot = [IO.Path]::GetFullPath(
	(Join-Path $PSScriptRoot '..\..')
)
$configText = Get-Content `
	-LiteralPath (Join-Path $repositoryRoot `
		'configs\mingw64a_defconfig') -Raw -Encoding UTF8
$unameText = Get-Content `
	-LiteralPath (Join-Path $repositoryRoot 'win32\uname.c') `
	-Raw -Encoding UTF8
$ashText = Get-Content `
	-LiteralPath (Join-Path $repositoryRoot 'shell\ash.c') `
	-Raw -Encoding UTF8
$makeText = Get-Content `
	-LiteralPath (Join-Path $repositoryRoot 'Makefile') `
	-Raw -Encoding UTF8
$makeFlagsText = Get-Content `
	-LiteralPath (Join-Path $repositoryRoot 'Makefile.flags') `
	-Raw -Encoding UTF8
$releaseText = Get-Content `
	-LiteralPath (Join-Path $repositoryRoot `
		'examples\mswin-build\mkrelease') -Raw -Encoding UTF8
$checkstackText = Get-Content `
	-LiteralPath (Join-Path $repositoryRoot `
		'scripts\checkstack.pl') -Raw -Encoding UTF8
$smokeText = Get-Content `
	-LiteralPath (Join-Path $repositoryRoot `
		'testsuite\all_git_critical.tests') -Raw -Encoding UTF8
$nativeScriptText = Get-Content `
	-LiteralPath (Join-Path $PSScriptRoot 'validate-native.ps1') `
	-Raw -Encoding UTF8

Invoke-TestCase 'ARM64 architecture surface inventory is closed' {
	$expected = @(
		'configs/mingw64a_defconfig',
		'examples/mswin-build/mkrelease',
		'scripts/checkstack.pl',
		'shell/ash.c',
		'win32/uname.c'
	)
	$observed = @(Get-ArchitectureSurfaceFiles $repositoryRoot)
	Assert-Equal ($expected -join "`n") ($observed -join "`n") `
		'Architecture surface inventory differs'
}

Invoke-TestCase 'ARM64 configuration remains dynamic clang MinGW' {
	Assert-NoFailures `
		@(Get-Mingw64aConfigPolicyFailures -Text $configText) `
		'mingw64a_defconfig'
}

Invoke-TestCase 'candidate build config must exactly match normalized source config' {
	$settings = @($configText -split '\r?\n' | Where-Object {
			$_ -match '^(?:# )?CONFIG_'
		})
	$generated = "# generated metadata may differ`n" +
		($settings -join "`n")
	Assert-NoFailures @(Get-ConfigEquivalenceFailures `
		-ExpectedText $configText -ObservedText $generated) `
		'normalized candidate config'
}

Invoke-TestCase 'candidate build config mutation is rejected' {
	$mutated = $configText.Replace(
		'CONFIG_CROSS_COMPILER="clang"',
		'CONFIG_CROSS_COMPILER="gcc"'
	)
	Assert-Rejected @(Get-ConfigEquivalenceFailures `
		-ExpectedText $configText -ObservedText $mutated) `
		'candidate config mutation'
}

Invoke-TestCase 'alternate Make assignment in candidate config is rejected' {
	$mutated = $configText + "`nCONFIG_STATIC := y`n"
	Assert-Throws {
		Get-ConfigEquivalenceFailures -ExpectedText $configText `
			-ObservedText $mutated
	} 'alternate CONFIG assignment'
}

Invoke-TestCase 'uname preserves every Windows architecture mapping' {
	Assert-NoFailures @(Get-UnameSourcePolicyFailures -Text $unameText) `
		'win32 uname'
}

Invoke-TestCase 'ash retains the reviewed Windows ARM nofork dispatch' {
	$pattern = '(?s)defined\(_ARM64_\).*?defined\(_ARM_\).*?!defined\(_UCRT\).*?ENABLE_PLATFORM_MINGW32'
	Assert-Equal 1 ([regex]::Matches($ashText, $pattern).Count) `
		'ARM nofork dispatch count differs'
}

Invoke-TestCase 'compiler and binary tools derive from explicit config' {
	Assert-MakeToolPolicy -Text $makeText
}

Invoke-TestCase 'static and dynamic link switches remain explicit' {
	Assert-LinkPolicy -Text $makeFlagsText
}

Invoke-TestCase 'release helper and stack parser retain ARM64 branches' {
	Assert-True ($releaseText -match
		'(?s)build_64a.*?CONFIG=mingw64a_defconfig') `
		'The release helper has no mingw64a config branch'
	Assert-True ($releaseText -match
		'if \[ \$i != "build_64a" \]') `
		'The AArch64 optimization exception is absent'
	Assert-True ($checkstackText -match
		"if \(\`$arch eq 'aarch64'\)") `
		'The stack parser has no aarch64 branch'
}

Invoke-TestCase 'Git-critical smoke definition names exactly 15 applets' {
	$match = [regex]::Match(
		$smokeText,
		'(?m)^# APPLETS: ([a-z0-9 ]+)\r?$'
	)
	Assert-True $match.Success 'The APPLETS declaration is absent'
	$applets = @($match.Groups[1].Value -split ' ' |
		Where-Object { $_ -ne '' })
	$expected = @(
		'awk', 'cat', 'cp', 'diff', 'find',
		'grep', 'mkdir', 'mv', 'rm', 'sed',
		'sh', 'sort', 'tr', 'unzip', 'xargs'
	)
	Assert-Equal 15 $applets.Count 'Applet count differs'
	Assert-Equal ($expected -join "`n") `
		(@($applets | Sort-Object -Unique) -join "`n") `
		'Applet names differ'
	Assert-Equal 5 `
		([regex]::Matches($smokeText, '(?m)^testing "').Count) `
		'Smoke test-case count differs'
	Assert-True ($smokeText.Contains(
		"printf '\120\113\003\004"
	)) `
		'The self-contained ZIP fixture is absent'
}

Invoke-TestCase 'native diagnostic contains a closed record ID set' {
	$tokens = $null
	$errors = $null
	$ast = [Management.Automation.Language.Parser]::ParseInput(
		$nativeScriptText,
		[ref]$tokens,
		[ref]$errors
	)
	Assert-Equal 0 $errors.Count 'Native diagnostic has parse errors'
	$assignment = @($ast.FindAll({
		param($node)
		$node -is
			[Management.Automation.Language.AssignmentStatementAst] -and
		$node.Left -is
			[Management.Automation.Language.VariableExpressionAst] -and
		$node.Left.VariablePath.UserPath -eq 'recordIds'
	}, $true))
	Assert-Equal 1 $assignment.Count 'recordIds assignment count differs'
	$ids = @($assignment[0].Right.FindAll({
		param($node)
		$node -is
			[Management.Automation.Language.StringConstantExpressionAst]
	}, $true) | ForEach-Object Value)
	Assert-Equal 17 $ids.Count 'Evidence record count differs'
	Assert-Equal 17 @($ids | Sort-Object -Unique).Count `
		'Evidence record IDs are not unique'
}

Invoke-TestCase 'native diagnostic cannot build or acquire inputs' {
	$forbidden = @(
		'Invoke-WebRequest',
		'Start-BitsTransfer',
		'pacman',
		'make ',
		'curl ',
		'git clone',
		'upload-artifact',
		'download-artifact'
	)
	foreach ($token in $forbidden) {
		Assert-True (-not $nativeScriptText.Contains($token)) `
			"Forbidden acquisition token '$token' is present"
	}
	Assert-True (-not $nativeScriptText.Contains('Add-Type')) `
		'Native diagnostic must not compile an interop helper'
}

Invoke-TestCase 'native tests bind explicitly to candidate and source harness' {
	foreach ($required in @(
		"Join-Path `$candidateDirectory '.config'",
		'Get-ConfigEquivalenceFailures',
		'bindir = $candidateDirectory',
		'tsdir = $testsuitePath',
		"ECHO = 'echo'",
		"-ArgumentList @('--list')",
		'$fullArguments = @(''sh'', ''./runtest'', ''-v'') +'
	)) {
		Assert-True ($nativeScriptText.Contains($required)) `
			"Candidate-binding expression '$required' is absent"
	}
}

Invoke-TestCase 'not-built suite skips are counted explicitly' {
	$accounting = Get-TestResultAccounting -Output (
		"PASS: one`nSKIPPED: two (not built)`n"
	)
	Assert-Equal 1 $accounting.pass 'Pass count differs'
	Assert-Equal 1 $accounting.skipped 'Skip count differs'
	Assert-Equal 1 $accounting.notBuiltSkipped `
		'Not-built skip count differs'
	Assert-Equal 2 $accounting.resultLines 'Result-line count differs'
}

Invoke-TestCase 'synthetic pure ARM64 PE passes structural policy' {
	$pe = Get-PeImageInfoFromBytes -Bytes (New-SyntheticPe)
	Assert-NoFailures @(Get-Arm64PePolicyFailures -Pe $pe) `
		'synthetic ARM64 PE'
	Assert-Equal 'KERNEL32.dll' $pe.imports[0] `
		'Direct import differs'
	Assert-Equal 'USER32.dll' $pe.delayImports[0] `
		'Delay import differs'
	Assert-Equal '0x0000000000000000' `
		$pe.loadConfig.chpeMetadataPointerHex `
		'CHPE pointer differs'
}

Invoke-TestCase 'import tables may terminate just beyond declared size' {
	$bytes = New-SyntheticPe
	$optionalOffset = 0x80 + 24
	Set-UInt32LE $bytes ($optionalOffset + 112 + 12) 20
	Set-UInt32LE $bytes ($optionalOffset + 116 + (13 * 8)) 32
	$pe = Get-PeImageInfoFromBytes -Bytes $bytes
	Assert-NoFailures @(Get-Arm64PePolicyFailures -Pe $pe) `
		'descriptor-size boundary'
	Assert-Equal 'KERNEL32.dll' $pe.imports[0] `
		'Direct import differs at size boundary'
	Assert-Equal 'USER32.dll' $pe.delayImports[0] `
		'Delay import differs at size boundary'
}

Invoke-TestCase 'AMD64 machine mutation is rejected' {
	$pe = Get-PeImageInfoFromBytes -Bytes (
		New-SyntheticPe -Machine 0x8664
	)
	Assert-Rejected @(Get-Arm64PePolicyFailures -Pe $pe) `
		'AMD64 machine mutation'
}

Invoke-TestCase 'CHPE metadata mutation is rejected' {
	$pe = Get-PeImageInfoFromBytes -Bytes (
		New-SyntheticPe -ChpeMetadataPointer 0x140001000
	)
	Assert-Rejected @(Get-Arm64PePolicyFailures -Pe $pe) `
		'CHPE mutation'
}

Invoke-TestCase 'GUI subsystem mutation is rejected' {
	$bytes = New-SyntheticPe
	Set-UInt16LE $bytes (0x80 + 24 + 68) 2
	$pe = Get-PeImageInfoFromBytes -Bytes $bytes
	Assert-Rejected @(Get-Arm64PePolicyFailures -Pe $pe) `
		'GUI subsystem mutation'
}

Invoke-TestCase 'DLL characteristic mutation is rejected' {
	$bytes = New-SyntheticPe
	Set-UInt16LE $bytes (0x80 + 22) 0x2002
	$pe = Get-PeImageInfoFromBytes -Bytes $bytes
	Assert-Rejected @(Get-Arm64PePolicyFailures -Pe $pe) `
		'DLL characteristic mutation'
}

Invoke-TestCase 'missing executable characteristic mutation is rejected' {
	$bytes = New-SyntheticPe
	Set-UInt16LE $bytes (0x80 + 22) 0
	$pe = Get-PeImageInfoFromBytes -Bytes $bytes
	Assert-Rejected @(Get-Arm64PePolicyFailures -Pe $pe) `
		'missing executable characteristic mutation'
}

Invoke-TestCase 'missing dynamic imports mutation is rejected' {
	$pe = Get-PeImageInfoFromBytes -Bytes (
		New-SyntheticPe -IncludeImports $false
	)
	Assert-Rejected @(Get-Arm64PePolicyFailures -Pe $pe) `
		'no-import mutation'
}

Invoke-TestCase 'malformed PE signatures fail closed' {
	$bytes = New-SyntheticPe
	$bytes[0] = 0
	Assert-Throws {
		Get-PeImageInfoFromBytes -Bytes $bytes
	} 'MZ mutation'

	$bytes = New-SyntheticPe
	$bytes[0x80] = 0
	Assert-Throws {
		Get-PeImageInfoFromBytes -Bytes $bytes
	} 'PE signature mutation'
}

Invoke-TestCase 'native environment policy accepts structural ARM64 only' {
	Assert-NoFailures @(Get-NativeEnvironmentPolicyFailures `
		-OsArchitecture Arm64 -ProcessArchitecture Arm64 `
		-ProcessorArchitecture ARM64 -ProcessorArchitew6432 '') `
		'native environment'
}

Invoke-TestCase 'x64 OS mutation cannot be masked by ARM64 strings' {
	Assert-Rejected @(Get-NativeEnvironmentPolicyFailures `
		-OsArchitecture X64 -ProcessArchitecture Arm64 `
		-ProcessorArchitecture ARM64 -ProcessorArchitew6432 '') `
		'x64 OS mutation'
}

Invoke-TestCase 'x64 diagnostic process mutation is rejected' {
	Assert-Rejected @(Get-NativeEnvironmentPolicyFailures `
		-OsArchitecture Arm64 -ProcessArchitecture X64 `
		-ProcessorArchitecture AMD64 `
		-ProcessorArchitew6432 ARM64) `
		'emulated diagnostic process mutation'
}

Invoke-TestCase 'external module policy accepts an exact observed set' {
	$pe = Get-PeImageInfoFromBytes -Bytes (New-SyntheticPe)
	$identity = [pscustomobject]@{
		canonicalPath = 'C:\candidate\busybox.exe'
		volumeSerial = '0123ABCD'
		fileId = '00000000000000000000000000000001'
		sha256 = ('a' * 64)
		length = 2048
	}
	$modules = @(
		[pscustomobject]@{
			canonicalPath = 'C:\candidate\busybox.exe'
			volumeSerial = '0123ABCD'
			fileId = '00000000000000000000000000000001'
			sha256 = ('a' * 64)
			peMachine = '0xAA64'
		},
		[pscustomobject]@{
			canonicalPath = 'C:\Windows\System32\KERNEL32.DLL'
			volumeSerial = '0123ABCD'
			fileId = '00000000000000000000000000000002'
			sha256 = ('b' * 64)
			peMachine = '0xAA64'
		}
	)
	$policy = [pscustomobject]@{
		schemaVersion = 1
		authority = 'external-independent-review'
		subject = [pscustomobject]@{
			canonicalPath = 'c:\CANDIDATE\busybox.exe'
			volumeSerial = '0123ABCD'
			fileId = '00000000000000000000000000000001'
			sha256 = ('a' * 64)
		}
		imports = @('KERNEL32.dll')
		delayImports = @('USER32.dll')
		modules = $modules
	}
	Assert-NoFailures @(Compare-ModulePolicy -Policy $policy `
		-SubjectIdentity $identity -Pe $pe -Modules $modules) `
		'exact module policy'
}

Invoke-TestCase 'unexpected loaded module mutation is rejected' {
	$pe = Get-PeImageInfoFromBytes -Bytes (New-SyntheticPe)
	$identity = [pscustomobject]@{
		canonicalPath = 'C:\candidate\busybox.exe'
		volumeSerial = '0123ABCD'
		fileId = '00000000000000000000000000000001'
		sha256 = ('a' * 64)
	}
	$expectedModule = [pscustomobject]@{
		canonicalPath = 'C:\candidate\busybox.exe'
		volumeSerial = '0123ABCD'
		fileId = '00000000000000000000000000000001'
		sha256 = ('a' * 64)
		peMachine = '0xAA64'
	}
	$extraModule = [pscustomobject]@{
		canonicalPath = 'C:\candidate\unexpected.dll'
		volumeSerial = '0123ABCD'
		fileId = '00000000000000000000000000000003'
		sha256 = ('c' * 64)
		peMachine = '0x8664'
	}
	$policy = [pscustomobject]@{
		subject = $identity
		imports = @('KERNEL32.dll')
		delayImports = @('USER32.dll')
		modules = @($expectedModule)
	}
	Assert-Rejected @(Compare-ModulePolicy -Policy $policy `
		-SubjectIdentity $identity -Pe $pe `
		-Modules @($expectedModule, $extraModule)) `
		'unexpected module mutation'
}

Invoke-TestCase 'CONFIG_STATIC mutation is rejected' {
	$mutated = $configText.Replace(
		'# CONFIG_STATIC is not set',
		'CONFIG_STATIC=y'
	)
	Assert-Rejected @(Get-Mingw64aConfigPolicyFailures `
		-Text $mutated) 'CONFIG_STATIC mutation'
}

Invoke-TestCase 'CONFIG_STATIC_LIBGCC mutation is rejected' {
	$mutated = $configText.Replace(
		'# CONFIG_STATIC_LIBGCC is not set',
		'CONFIG_STATIC_LIBGCC=y'
	)
	Assert-Rejected @(Get-Mingw64aConfigPolicyFailures `
		-Text $mutated) 'CONFIG_STATIC_LIBGCC mutation'
}

Invoke-TestCase 'ARM64 compiler-prefix mutation is rejected' {
	$mutated = $configText.Replace(
		'aarch64-w64-mingw32-',
		'x86_64-w64-mingw32-'
	)
	Assert-Rejected @(Get-Mingw64aConfigPolicyFailures `
		-Text $mutated) 'compiler-prefix mutation'
}

Invoke-TestCase 'ARM64 uname x64 fallback mutation is rejected' {
	$mutated = $unameText.Replace(
		'strcpy(name->machine, "aarch64");',
		'strcpy(name->machine, "x86_64");'
	)
	Assert-Rejected @(Get-UnameSourcePolicyFailures -Text $mutated) `
		'uname x64 fallback mutation'
}

Invoke-TestCase 'missing ARM64 uname case mutation is rejected' {
	$mutated = [regex]::Replace(
		$unameText,
		'(?s)#if defined\(PROCESSOR_ARCHITECTURE_ARM64\).*?#endif',
		''
	)
	Assert-Rejected @(Get-UnameSourcePolicyFailures -Text $mutated) `
		'missing ARM64 uname case'
}

Invoke-TestCase 'closed-key policy rejects extra candidate authority' {
	$object = [pscustomobject]@{
		schemaVersion = 1
		authority = 'external-independent-review'
		candidateAdmission = $true
	}
	Assert-Throws {
		Assert-ClosedKeys $object @(
			'authority',
			'schemaVersion'
		) 'mutated policy'
	} 'extra policy key'
}

Invoke-TestCase 'text evidence hashes UTF-8 deterministically' {
	Assert-Equal `
		'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' `
		(Get-TextSha256 -Text 'abc') `
		'UTF-8 SHA-256 differs'
}

Invoke-TestCase 'canonical evidence digest matches the versioned vector' {
	$relativePath = 'configs/mingw64a_defconfig'
	$fixture = [pscustomobject][ordered]@{
		z = @($null, $true, $false, [int64]-2, [uint64]3, 'x')
		a = Join-Path $repositoryRoot $relativePath
		literal = $relativePath
	}
	$digest = Get-EvidenceCanonicalDigest `
		-Document $fixture -RepositoryRoot $repositoryRoot
	Assert-Equal 'busybox-arm64-evidence-canonical-v1' `
		$digest.canonicalization 'Canonicalization identifier differs'
	Assert-Equal 141 $digest.canonicalByteLength `
		'Canonical vector byte length differs'
	Assert-Equal `
		'a4f09935a9b7fde67c6669d4fbcfba649fbbf71d6919bada2956172ad63d480e' `
		$digest.sha256 'Canonical vector SHA-256 differs'
	Assert-Throws {
		Get-EvidenceCanonicalDigest -Document (
			[pscustomobject]@{ unsupported = [double]1.5 }
		) -RepositoryRoot $repositoryRoot
	} 'unsupported floating-point canonical value'

	$wideIntegerDocument = [pscustomobject]@{
		value = [uint64]::MaxValue
	}
	$wideIntegerDigest = Get-EvidenceCanonicalDigest `
		-Document $wideIntegerDocument -RepositoryRoot $repositoryRoot
	$wideIntegerPublished = (
		$wideIntegerDocument | ConvertTo-Json
	) | ConvertFrom-Json
	$wideIntegerRecomputed = Get-EvidenceCanonicalDigest `
		-Document $wideIntegerPublished -RepositoryRoot $repositoryRoot
	Assert-Equal $wideIntegerDigest.canonicalByteLength `
		$wideIntegerRecomputed.canonicalByteLength `
		'Wide-integer canonical byte length did not round trip'
	Assert-Equal $wideIntegerDigest.sha256 `
		$wideIntegerRecomputed.sha256 `
		'Wide-integer canonical digest did not round trip'
}

Invoke-TestCase 'canonical evidence digest is stable across working directories' {
	$tempRoot = Join-Path ([IO.Path]::GetTempPath()) (
		'busybox-arm64-digest-' + [Guid]::NewGuid().ToString('N')
	)
	$documents = @()
	$rawHashes = @()
	$digests = @()
	$roots = @(
		(Join-Path $tempRoot 'root-a'),
		(Join-Path $tempRoot 'root-b')
	)
	try {
		foreach ($root in $roots) {
			$arm64Path = Join-Path $root 'testsuite\arm64'
			$configPath = Join-Path $root 'configs'
			[void](New-Item -ItemType Directory -Path $arm64Path -Force)
			[void](New-Item -ItemType Directory -Path $configPath -Force)
			Copy-Item -LiteralPath (
				Join-Path $PSScriptRoot 'Arm64Validation.psm1'
			) -Destination $arm64Path
			Copy-Item -LiteralPath (
				Join-Path $PSScriptRoot 'validate-native.ps1'
			) -Destination $arm64Path
			Copy-Item -LiteralPath (
				Join-Path $repositoryRoot 'configs\mingw64a_defconfig'
			) -Destination $configPath

			$evidencePath = Join-Path $root 'evidence.json'
			$result = Invoke-CapturedProcess `
				-FilePath ([Environment]::ProcessPath) `
				-ArgumentList @(
					'-NoLogo',
					'-NoProfile',
					'-File',
					(Join-Path $arm64Path 'validate-native.ps1'),
					'-EvidencePath',
					$evidencePath
				) `
				-WorkingDirectory $root
			Assert-Equal 1 $result.exitCode `
				'Missing-prerequisite diagnostic exit differs'

			$evidenceText = Get-Content -LiteralPath $evidencePath `
				-Raw -Encoding UTF8
			$document = $evidenceText | ConvertFrom-Json
			$digest = Get-Content -LiteralPath (
				"$evidencePath.canonical-sha256.json"
			) -Raw -Encoding UTF8 | ConvertFrom-Json
			Assert-ClosedKeys $digest @(
				'canonicalByteLength',
				'canonicalization',
				'hashAlgorithm',
				'schemaVersion',
				'sha256'
			) 'canonical digest sidecar'
			$recomputed = Get-EvidenceCanonicalDigest `
				-Document $document -RepositoryRoot $root
			Assert-Equal $recomputed.canonicalization `
				$digest.canonicalization `
				'Canonicalization identifier differs'
			Assert-Equal $recomputed.canonicalByteLength `
				$digest.canonicalByteLength `
				'Canonical byte length differs'
			Assert-Equal $recomputed.sha256 $digest.sha256 `
				'Canonical digest does not recompute'

			$documents += ,$document
			$rawHashes += Get-TextSha256 -Text $evidenceText
			$digests += $digest.sha256
		}

		Assert-True ($rawHashes[0] -cne $rawHashes[1]) `
			'Raw evidence unexpectedly hid checkout-local paths'
		Assert-Equal $digests[0] $digests[1] `
			'Canonical digest changed with the working directory'

		$contentMutation = (
			$documents[0] | ConvertTo-Json -Depth 20
		) | ConvertFrom-Json
		$contentMutation.records[0].detail += ' mutated'
		$contentDigest = Get-EvidenceCanonicalDigest `
			-Document $contentMutation -RepositoryRoot $roots[0]
		Assert-True ($contentDigest.sha256 -cne $digests[0]) `
			'Record-content mutation did not change canonical digest'

		$pathMutation = (
			$documents[0] | ConvertTo-Json -Depth 20
		) | ConvertFrom-Json
		$pathMutation.records[0].observed.path = Join-Path `
			$roots[0] 'configs\other_defconfig'
		$pathDigest = Get-EvidenceCanonicalDigest `
			-Document $pathMutation -RepositoryRoot $roots[0]
		Assert-True ($pathDigest.sha256 -cne $digests[0]) `
			'Repository-relative path mutation did not change digest'

		$stringMutation = (
			$documents[0] | ConvertTo-Json -Depth 20
		) | ConvertFrom-Json
		$stringMutation.records[0].observed.path =
			'configs/mingw64a_defconfig'
		$stringDigest = Get-EvidenceCanonicalDigest `
			-Document $stringMutation -RepositoryRoot $roots[0]
		Assert-True ($stringDigest.sha256 -cne $digests[0]) `
			'Path and ordinary-string encodings collided'

		$extraKeyMutation = (
			$documents[0] | ConvertTo-Json -Depth 20
		) | ConvertFrom-Json
		$extraKeyMutation | Add-Member -NotePropertyName unexpected `
			-NotePropertyValue 'mutation'
		$extraKeyDigest = Get-EvidenceCanonicalDigest `
			-Document $extraKeyMutation -RepositoryRoot $roots[0]
		Assert-True ($extraKeyDigest.sha256 -cne $digests[0]) `
			'Extra document key did not change canonical digest'

		$invalidPolicyPath = Join-Path $roots[0] 'invalid-policy.json'
		$invalidPolicyJson = @'
{
  "schemaVersion": 1.0,
  "authority": "external-independent-review",
  "subject": {
    "canonicalPath": "C:\\candidate\\busybox.exe",
    "volumeSerial": "0123ABCD",
    "fileId": "00000000000000000000000000000001",
    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "imports": ["KERNEL32.dll"],
  "delayImports": [],
  "modules": [
    {
      "canonicalPath": "C:\\candidate\\busybox.exe",
      "volumeSerial": "0123ABCD",
      "fileId": "00000000000000000000000000000001",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "peMachine": "0xAA64"
    }
  ]
}
'@
		$validPolicyPath = Join-Path $roots[0] 'valid-policy.json'
		[IO.File]::WriteAllText(
			$validPolicyPath,
			$invalidPolicyJson.Replace(
				'"schemaVersion": 1.0',
				'"schemaVersion": 1'
			),
			[Text.UTF8Encoding]::new($false)
		)
		$validPolicy = Read-ModulePolicy -Path $validPolicyPath
		Assert-Equal 1 $validPolicy.schemaVersion `
			'Valid typed policy schema differs'
		Assert-Equal 1 @($validPolicy.modules).Count `
			'Valid typed policy module count differs'

		[IO.File]::WriteAllText(
			$invalidPolicyPath,
			$invalidPolicyJson,
			[Text.UTF8Encoding]::new($false)
		)
		$invalidEvidencePath = Join-Path $roots[0] `
			'invalid-policy-evidence.json'
		$invalidResult = Invoke-CapturedProcess `
			-FilePath ([Environment]::ProcessPath) `
			-ArgumentList @(
				'-NoLogo',
				'-NoProfile',
				'-File',
				(Join-Path $roots[0] `
					'testsuite\arm64\validate-native.ps1'),
				'-ModulePolicyPath',
				$invalidPolicyPath,
				'-EvidencePath',
				$invalidEvidencePath
			) `
			-WorkingDirectory $roots[0]
		Assert-Equal 1 $invalidResult.exitCode `
			'Invalid-policy diagnostic exit differs'
		$invalidDocument = Get-Content -LiteralPath `
			$invalidEvidencePath -Raw -Encoding UTF8 | ConvertFrom-Json
		$policyRecord = @($invalidDocument.records |
			Where-Object id -eq 'prerequisite.module-policy')
		Assert-Equal 1 $policyRecord.Count `
			'Invalid-policy evidence record count differs'
		Assert-Equal 'fail' $policyRecord[0].status `
			'Invalid numeric policy schema did not fail closed'
		$invalidDigest = Get-Content -LiteralPath (
			"$invalidEvidencePath.canonical-sha256.json"
		) -Raw -Encoding UTF8 | ConvertFrom-Json
		$invalidRecomputed = Get-EvidenceCanonicalDigest `
			-Document $invalidDocument -RepositoryRoot $roots[0]
		Assert-Equal $invalidRecomputed.sha256 `
			$invalidDigest.sha256 `
			'Rejected-policy evidence digest does not recompute'
	} finally {
		if (Test-Path -LiteralPath $tempRoot -PathType Container) {
			Remove-Item -LiteralPath $tempRoot -Recurse -Force
		}
	}
}

Invoke-TestCase 'file identity uses filesystem path, volume and file ID' {
	$identity = Get-FileIdentity -Path (
		Join-Path $repositoryRoot 'README.md'
	)
	Assert-True ($identity.canonicalPath.EndsWith(
		'\README.md',
		[StringComparison]::Ordinal
	)) 'Filesystem canonical path did not preserve stored case'
	Assert-True ($identity.volumeSerial -match '^[0-9A-F]+$') `
		'Volume serial is not normalized hexadecimal'
	Assert-True ($identity.fileId -match
		'^(?:[0-9A-F]{16}|[0-9A-F]{32})$') `
		'File ID is not normalized hexadecimal'
	Assert-True ($identity.sha256 -match '^[0-9a-f]{64}$') `
		'File hash is not normalized SHA-256'
}

Write-Output (
	"SUMMARY: total={0} pass={1} fail={2} skipped=0" -f
	($script:passed + $script:failed),
	$script:passed,
	$script:failed
)
if ($script:failed -ne 0) {
	exit 1
}
