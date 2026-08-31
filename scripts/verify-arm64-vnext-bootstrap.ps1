[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string]$SourceDirectory,

	[Parameter(Mandatory = $true)]
	[string]$ExpectedRepositoryCommit,

	[Parameter(Mandatory = $true)]
	[string]$ExpectedSourceTree,

	[Parameter(Mandatory = $true)]
	[string]$ProvenanceLedger,

	[Parameter(Mandatory = $true)]
	[string[]]$ToolchainRoot,

	[string]$CandidatePatch,

	[Parameter(Mandatory = $true)]
	[string]$ArtifactPath,

	[Parameter(Mandatory = $true)]
	[string]$EvidencePath,

	[Parameter(Mandatory = $true)]
	[string]$ControlBash,

	[int]$Jobs = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$epoch = '2026-08-31-v1'
$nodeId = 'busybox-bootstrap-tools'
$expectedBranch = 'crutkas-arm64-vnext/busybox-w32/bootstrap-tools'
$expectedOrigin = 'https://github.com/crutkas/busybox-w32.git'
$baseCommit = 'd8d8bb397f1e200ba5a871dc6aa4af819b23f32a'
$baseTree = '37fb55f5335e63c9f14c44208ed08a6e9aad4f91'
$ledgerSha256 = '9f4ed99e12d67ef026eb7fb85c783edc9d8211a1ea80f5447e3a7dd3e1a00999'
$rejectedCommit = '3fe8e24a74a423e6f5aa2451676937bad3bc7055'
$auditSha256 = '768b2d0c34e31ca15cea942a17edd5ac06b03e6d922e1da84f6be919799f821f'
$expectedChangedFiles = @(
	'configs/arm64_vnext_bootstrap_applets',
	'configs/arm64_vnext_bootstrap_defconfig',
	'configs/arm64_vnext_payload_applets',
	'libbb/hash_md5_sha.c',
	'scripts/verify-arm64-vnext-bootstrap.ps1',
	'shell/ash.c',
	'testsuite/all_arm64_vnext_bootstrap.tests'
)

function Get-Sha256([string]$Path) {
	return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Invoke-Git([string[]]$Arguments) {
	$output = @(& git @Arguments)
	if ($LASTEXITCODE -ne 0) {
		throw "git $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
	}
	return ($output -join "`n").Trim()
}

function Get-PeMachine([string]$Path) {
	$bytes = [IO.File]::ReadAllBytes($Path)
	if ($bytes.Length -lt 64) {
		throw "Not a PE image: $Path"
	}
	$offset = [BitConverter]::ToInt32($bytes, 0x3c)
	if ($offset -lt 0 -or $offset + 12 -gt $bytes.Length) {
		throw "Invalid PE header: $Path"
	}
	return ('0x{0:X4}' -f [BitConverter]::ToUInt16($bytes, $offset + 4))
}

function Get-PeTimestamp([string]$Path) {
	$bytes = [IO.File]::ReadAllBytes($Path)
	$offset = [BitConverter]::ToInt32($bytes, 0x3c)
	return [BitConverter]::ToUInt32($bytes, $offset + 8)
}

function Get-CoffTimestamp([string]$Path) {
	$bytes = [IO.File]::ReadAllBytes($Path)
	if ($bytes.Length -lt 8) {
		throw "Invalid COFF object: $Path"
	}
	$archiveMagic = [Text.Encoding]::ASCII.GetString($bytes, 0, 8)
	if ($archiveMagic -eq "!<arch>`n") {
		$offset = 8
		while ($offset + 60 -le $bytes.Length) {
			$dateText = [Text.Encoding]::ASCII.GetString($bytes, $offset + 16, 12).Trim()
			if ($dateText -and $dateText -ne '0') {
				return [uint32]$dateText
			}
			$sizeText = [Text.Encoding]::ASCII.GetString($bytes, $offset + 48, 10).Trim()
			$memberSize = [int]$sizeText
			$dataOffset = $offset + 60
			if ($memberSize -ge 12 -and $dataOffset + $memberSize -le $bytes.Length) {
				$machine = [BitConverter]::ToUInt16($bytes, $dataOffset)
				if ($machine -in @(0x014c, 0x8664, 0xAA64)) {
					$timestamp = [BitConverter]::ToUInt32($bytes, $dataOffset + 4)
					if ($timestamp -ne 0) {
						return $timestamp
					}
				} elseif ($machine -eq 0 -and [BitConverter]::ToUInt16($bytes, $dataOffset + 2) -eq 0xffff) {
					$timestamp = [BitConverter]::ToUInt32($bytes, $dataOffset + 8)
					if ($timestamp -ne 0) {
						return $timestamp
					}
				}
			}
			$offset = $dataOffset + $memberSize + ($memberSize % 2)
		}
		return [uint32]0
	}
	$machine = [BitConverter]::ToUInt16($bytes, 0)
	if ($machine -in @(0x014c, 0x8664, 0xAA64)) {
		return [BitConverter]::ToUInt32($bytes, 4)
	}
	if ($machine -eq 0 -and [BitConverter]::ToUInt16($bytes, 2) -eq 0xffff) {
		return [BitConverter]::ToUInt32($bytes, 8)
	}
	throw "Unknown object format: $Path"
}

function ConvertTo-MsysPath([string]$Path) {
	$full = [IO.Path]::GetFullPath($Path)
	if ($full -notmatch '^([A-Za-z]):\\(.*)$') {
		throw "MSYS control requires a drive-qualified path: $full"
	}
	return '/' + $Matches[1].ToLowerInvariant() + '/' + ($Matches[2] -replace '\\', '/')
}

function Invoke-Control([string]$Command) {
	$startInfo = [Diagnostics.ProcessStartInfo]::new()
	$startInfo.FileName = $ControlBash
	$startInfo.ArgumentList.Add('-c')
	$startInfo.ArgumentList.Add($Command)
	$startInfo.UseShellExecute = $false
	$startInfo.RedirectStandardInput = $true
	$startInfo.RedirectStandardOutput = $true
	$startInfo.RedirectStandardError = $true
	$process = [Diagnostics.Process]::new()
	$process.StartInfo = $startInfo
	if (-not $process.Start()) {
		throw 'Failed to start the one-time build control'
	}
	$process.StandardInput.Close()
	$stdoutTask = $process.StandardOutput.ReadToEndAsync()
	$stderrTask = $process.StandardError.ReadToEndAsync()
	$process.WaitForExit()
	$stdout = $stdoutTask.GetAwaiter().GetResult()
	$stderr = $stderrTask.GetAwaiter().GetResult()
	if ($process.ExitCode -ne 0) {
		$diagnostic = (($stdout + "`n" + $stderr) -split "`n" | Select-Object -Last 80) -join "`n"
		throw "Control command failed with exit code $($process.ExitCode):`n$diagnostic"
	}
}

function Get-ConfigSettings([string]$Fragment) {
	$settings = @()
	$names = @{}
	foreach ($line in [IO.File]::ReadAllLines($Fragment)) {
		if ($line -match '^CONFIG_([A-Z0-9_]+)=(.*)$') {
			$name = $Matches[1]
			$value = $Matches[2]
			$type = if ($value -in @('y', 'm', 'n')) {
				'bool-or-tristate'
			} elseif ($value.StartsWith('"')) {
				'string'
			} elseif ($value -match '^0x[0-9A-Fa-f]+$') {
				'hex'
			} else {
				'integer'
			}
		} elseif ($line -match '^# CONFIG_([A-Z0-9_]+) is not set$') {
			$name = $Matches[1]
			$value = 'n'
			$type = 'disabled'
		} else {
			continue
		}
		if ($names.ContainsKey($name)) {
			throw "Duplicate requested config symbol: $name"
		}
		$names[$name] = $true
		$settings += [ordered]@{
			name = $name
			type = $type
			value = $value
			line = $line
		}
	}
	return $settings
}

function Merge-ConfigFragment([string]$Config, [object[]]$Settings) {
	$text = [IO.File]::ReadAllText($Config)
	foreach ($setting in $Settings) {
		$pattern = "(?m)^(?:# CONFIG_$($setting.name) is not set|CONFIG_$($setting.name)=.*)$"
		if ($text -notmatch $pattern) {
			throw "Unknown config symbol: $($setting.name)"
		}
		$text = [regex]::Replace($text, $pattern, $setting.line)
	}
	[IO.File]::WriteAllText($Config, $text, [Text.UTF8Encoding]::new($false))
}

function Assert-ResolvedConfig([string]$Config, [object[]]$Settings) {
	$resolved = @{}
	foreach ($line in [IO.File]::ReadAllLines($Config)) {
		if ($line -match '^CONFIG_([A-Z0-9_]+)=(.*)$' -or
			$line -match '^# CONFIG_([A-Z0-9_]+) is not set$') {
			$resolved[$Matches[1]] = $line
		}
	}
	$result = @()
	foreach ($setting in $Settings) {
		if (-not $resolved.ContainsKey($setting.name)) {
			throw "Requested config symbol disappeared: $($setting.name)"
		}
		if ($resolved[$setting.name] -cne $setting.line) {
			throw "Config resolution changed $($setting.name): requested '$($setting.line)', resolved '$($resolved[$setting.name])'"
		}
		$result += [ordered]@{
			name = $setting.name
			type = $setting.type
			value = $setting.value
			resolved_line = $resolved[$setting.name]
		}
	}
	return $result
}

function Get-TreeFromPatch([string]$Patch) {
	$tempIndex = Join-Path ([IO.Path]::GetTempPath()) "$epoch-index-$PID-$([guid]::NewGuid().ToString('N'))"
	$savedIndex = $env:GIT_INDEX_FILE
	try {
		$env:GIT_INDEX_FILE = $tempIndex
		Invoke-Git @('-C', $SourceDirectory, 'read-tree', $baseCommit) | Out-Null
		Invoke-Git @('-C', $SourceDirectory, 'apply', '--cached', '--binary', '--whitespace=nowarn', $Patch) | Out-Null
		return Invoke-Git @('-C', $SourceDirectory, 'write-tree')
	} finally {
		$env:GIT_INDEX_FILE = $savedIndex
		if (Test-Path -LiteralPath $tempIndex) {
			Remove-Item -LiteralPath $tempIndex -Force
		}
	}
}

function Assert-MaterializedTree([string]$Directory, [string]$ExpectedTree) {
	$tempIndex = Join-Path ([IO.Path]::GetTempPath()) "$epoch-materialized-$PID-$([guid]::NewGuid().ToString('N'))"
	$savedIndex = $env:GIT_INDEX_FILE
	try {
		$env:GIT_INDEX_FILE = $tempIndex
		Invoke-Git @('-C', $SourceDirectory, 'read-tree', $ExpectedTree) | Out-Null
		Invoke-Git @(
			'-c', 'core.autocrlf=false',
			'-c', 'core.filemode=false',
			'-C', $SourceDirectory,
			"--work-tree=$Directory",
			'update-index', '--really-refresh'
		) | Out-Null
		Invoke-Git @(
			'-c', 'core.autocrlf=false',
			'-c', 'core.filemode=false',
			'-C', $SourceDirectory,
			"--work-tree=$Directory",
			'diff-files', '--quiet'
		) | Out-Null
		$untracked = Invoke-Git @(
			'-c', 'core.autocrlf=false',
			'-C', $SourceDirectory,
			"--work-tree=$Directory",
			'ls-files', '--others', '--exclude-standard'
		)
		if ($untracked) {
			throw "Materialized source contains files outside the source tree: $untracked"
		}
		return $ExpectedTree
	} finally {
		$env:GIT_INDEX_FILE = $savedIndex
		if (Test-Path -LiteralPath $tempIndex) {
			Remove-Item -LiteralPath $tempIndex -Force
		}
	}
}

function Assert-ChangedFiles([string[]]$Actual) {
	$difference = @(Compare-Object ($expectedChangedFiles | Sort-Object) ($Actual | Sort-Object))
	if ($difference.Count -ne 0) {
		throw "Candidate changed-file set is not exact: $($difference | Out-String)"
	}
}

function Test-Binary([string]$Binary, [string[]]$PayloadApplets, [string[]]$BootstrapApplets) {
	if ((Get-PeMachine $Binary) -ne '0xAA64') {
		throw 'Built BusyBox PE Machine is not 0xAA64'
	}
	if ((Get-PeTimestamp $Binary) -ne 0) {
		throw 'Built BusyBox PE timestamp is not deterministic zero'
	}
	$actualApplets = @(& $Binary --list | Sort-Object)
	if ($LASTEXITCODE -ne 0) {
		throw 'BusyBox applet inventory command failed'
	}
	$expectedBinaryApplets = @(($PayloadApplets + $BootstrapApplets + @('lash')) | Sort-Object -Unique)
	if (Compare-Object $expectedBinaryApplets $actualApplets) {
		throw 'Binary applet inventory mismatch'
	}
	if ($actualApplets -contains 'ash') {
		throw 'The unsupported ash entry must not be exposed'
	}
	$smokeOutput = @(& $Binary sh -c 'set -eu; test "$(expr 20 + 22)" = 42; printf "z\na\n" | sort | head -n 1; printf "alpha beta\n" | awk "{ print \$2 }" | grep -x beta')
	if ($LASTEXITCODE -ne 0 -or ($smokeOutput -join "`n") -ne "a`nbeta") {
		throw 'Native shell/core smoke output mismatch'
	}
	$banner = (& $Binary --help | Select-Object -First 1)
	return [ordered]@{
		sha256 = Get-Sha256 $Binary
		size = (Get-Item -LiteralPath $Binary).Length
		pe_machine = Get-PeMachine $Binary
		pe_timestamp = Get-PeTimestamp $Binary
		binary_applet_count = $actualApplets.Count
		binary_applets = $actualApplets
		shell_core_smoke = $smokeOutput
		banner = $banner
	}
}

$SourceDirectory = [IO.Path]::GetFullPath($SourceDirectory)
$ProvenanceLedger = [IO.Path]::GetFullPath($ProvenanceLedger)
$ExpectedRepositoryCommit = $ExpectedRepositoryCommit.ToLowerInvariant()
$ExpectedSourceTree = $ExpectedSourceTree.ToLowerInvariant()
$ArtifactPath = [IO.Path]::GetFullPath($ArtifactPath)
$EvidencePath = [IO.Path]::GetFullPath($EvidencePath)
$ControlBash = [IO.Path]::GetFullPath($ControlBash)
$ToolchainRoot = @($ToolchainRoot | ForEach-Object { [IO.Path]::GetFullPath($_) })
if ($CandidatePatch) {
	$CandidatePatch = [IO.Path]::GetFullPath($CandidatePatch)
}

$requiredPaths = @($SourceDirectory, $ProvenanceLedger, $ControlBash)
if ($CandidatePatch) {
	$requiredPaths += $CandidatePatch
}
foreach ($requiredPath in $requiredPaths) {
	if (-not (Test-Path -LiteralPath $requiredPath)) {
		throw "Required path does not exist: $requiredPath"
	}
}
if ($Jobs -lt 1) {
	throw 'Jobs must be positive'
}
if ((Get-Sha256 $ProvenanceLedger) -ne $ledgerSha256) {
	throw 'Input provenance ledger hash mismatch'
}
if (Test-Path -LiteralPath $ArtifactPath) {
	throw "Fresh artifact path already exists: $ArtifactPath"
}
if (Test-Path -LiteralPath $EvidencePath) {
	throw "Fresh evidence path already exists: $EvidencePath"
}

$repositoryRoot = [IO.Path]::GetFullPath((Invoke-Git @('-C', $SourceDirectory, 'rev-parse', '--show-toplevel')))
if ($repositoryRoot.TrimEnd('\') -ine $SourceDirectory.TrimEnd('\')) {
	throw "SourceDirectory must be the repository worktree root: $repositoryRoot"
}
$repositoryBranch = Invoke-Git @('-C', $SourceDirectory, 'branch', '--show-current')
$repositoryCommit = Invoke-Git @('-C', $SourceDirectory, 'rev-parse', 'HEAD')
$repositoryTree = Invoke-Git @('-C', $SourceDirectory, 'rev-parse', 'HEAD^{tree}')
$origin = Invoke-Git @('-C', $SourceDirectory, 'remote', 'get-url', 'origin')
if ($repositoryBranch -ne $expectedBranch -or $origin -ne $expectedOrigin) {
	throw 'Repository branch or origin identity mismatch'
}
if ($repositoryCommit -ne $ExpectedRepositoryCommit) {
	throw "Repository HEAD mismatch: expected $ExpectedRepositoryCommit, found $repositoryCommit"
}

$candidatePatchEvidence = $null
if ($CandidatePatch) {
	if ($repositoryCommit -ne $baseCommit -or $repositoryTree -ne $baseTree) {
		throw 'Candidate-patch mode requires the exact reviewed base HEAD/tree'
	}
	$status = @(Invoke-Git @('-C', $SourceDirectory, 'status', '--porcelain=v1') -split "`n" | Where-Object { $_ })
	if ($status.Count -eq 0 -or @($status | Where-Object { $_.Substring(1, 1) -ne ' ' }).Count -ne 0) {
		throw 'Candidate-patch mode requires all and only candidate changes staged'
	}
	$patchTree = Get-TreeFromPatch $CandidatePatch
	$indexTree = Invoke-Git @('-C', $SourceDirectory, 'write-tree')
	if ($patchTree -ne $ExpectedSourceTree -or $indexTree -ne $ExpectedSourceTree) {
		throw "Candidate tree mismatch: expected $ExpectedSourceTree, patch $patchTree, index $indexTree"
	}
	$changedFileOutput = Invoke-Git @('-C', $SourceDirectory, 'diff', '--cached', '--name-only', $baseCommit)
	$changedFiles = @($changedFileOutput -split "`n")
	Assert-ChangedFiles $changedFiles
	$candidatePatchEvidence = [ordered]@{
		path = $CandidatePatch
		sha256 = Get-Sha256 $CandidatePatch
		temporary_index_tree = $patchTree
		staged_index_tree = $indexTree
	}
} else {
	if ($repositoryTree -ne $ExpectedSourceTree) {
		throw "Committed source tree mismatch: expected $ExpectedSourceTree, found $repositoryTree"
	}
	if (Invoke-Git @('-C', $SourceDirectory, 'status', '--porcelain=v1')) {
		throw 'Committed-source mode requires a clean worktree and index'
	}
	if ((Invoke-Git @('-C', $SourceDirectory, 'rev-parse', 'HEAD^')) -ne $baseCommit) {
		throw 'Committed source must have the fixed base as its sole parent'
	}
	if ((Invoke-Git @('-C', $SourceDirectory, 'rev-list', '--count', "$baseCommit..HEAD")) -ne '1') {
		throw 'Committed source must be exactly one commit above the fixed base'
	}
	$changedFileOutput = Invoke-Git @('-C', $SourceDirectory, 'diff-tree', '--no-commit-id', '--name-only', '-r', 'HEAD')
	$changedFiles = @($changedFileOutput -split "`n")
	Assert-ChangedFiles $changedFiles
}

$ledger = Get-Content -Raw -LiteralPath $ProvenanceLedger | ConvertFrom-Json -Depth 100
if ($ledger.payload.epoch -ne $epoch) {
	throw 'Input provenance epoch mismatch'
}
$requirement = @($ledger.payload.node_requirements | Where-Object node_id -eq $nodeId)
if ($requirement.Count -ne 1 -or $requirement[0].input_ids.Count -ne 55) {
	throw 'BusyBox node must have exactly 55 required inputs'
}
$inputById = @{}
foreach ($input in $ledger.payload.inputs) {
	$inputById[$input.id] = $input
}
foreach ($id in $requirement[0].input_ids) {
	if (-not $inputById.ContainsKey($id) -or $inputById[$id].status -ne 'ADMITTED') {
		throw "Required input is not admitted: $id"
	}
}

$resolvedTools = @()
$toolInputs = @($requirement[0].input_ids | Where-Object { $_ -like 'toolchain:file:*' })
foreach ($id in $toolInputs) {
	$record = $inputById[$id]
	$matches = @()
	foreach ($root in $ToolchainRoot) {
		$path = Join-Path $root $record.path
		if ((Test-Path -LiteralPath $path) -and (Get-Sha256 $path) -eq $record.sha256) {
			$matches += $path
		}
	}
	if ($matches.Count -ne 1) {
		throw "Expected exactly one hash-matching tool for ${id}, found $($matches.Count)"
	}
	if ($record.pe_machine -eq 'IMAGE_FILE_MACHINE_ARM64' -and (Get-PeMachine $matches[0]) -ne '0xAA64') {
		throw "Tool is not ARM64: $id"
	}
	$resolvedTools += [ordered]@{
		id = $id
		path = $matches[0]
		sha256 = $record.sha256
		pe_machine = $record.pe_machine
	}
}

$controlMake = Join-Path (Split-Path -Parent $ControlBash) 'make.exe'
if (-not (Test-Path -LiteralPath $controlMake)) {
	throw "One-time control make not found: $controlMake"
}
$control = [ordered]@{
	class = 'one-time emulated build control; never shipped'
	shipped = $false
	bash = [ordered]@{
		path = $ControlBash
		sha256 = Get-Sha256 $ControlBash
		pe_machine = Get-PeMachine $ControlBash
	}
	make = [ordered]@{
		path = $controlMake
		sha256 = Get-Sha256 $controlMake
		pe_machine = Get-PeMachine $controlMake
	}
}
if ($control.bash.pe_machine -ne '0x8664' -or $control.make.pe_machine -ne '0x8664') {
	throw 'The explicitly excluded one-time control must be x64'
}

$payloadApplets = @(Get-Content -LiteralPath (Join-Path $SourceDirectory 'configs\arm64_vnext_payload_applets') | Sort-Object)
$bootstrapApplets = @(Get-Content -LiteralPath (Join-Path $SourceDirectory 'configs\arm64_vnext_bootstrap_applets') | Sort-Object)
if ($payloadApplets.Count -ne 31 -or $bootstrapApplets.Count -ne 34) {
	throw 'Contract applet count mismatch'
}

$sourceDateEpoch = 946684800L + ([Convert]::ToUInt64($ExpectedSourceTree.Substring(0, 8), 16) % 1200000000L)
$buildTimestamp = [DateTimeOffset]::FromUnixTimeSeconds($sourceDateEpoch).UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss +0000')
$deterministicEnvironment = [ordered]@{
	SOURCE_DATE_EPOCH = $sourceDateEpoch
	KBUILD_BUILD_USER = 'arm64-vnext'
	KBUILD_BUILD_HOST = 'reproducible'
	KBUILD_BUILD_VERSION = '1'
	KBUILD_BUILD_TIMESTAMP = $buildTimestamp
	ZERO_AR_DATE = '1'
	TZ = 'UTC'
	LC_ALL = 'C'
	derivation = 'SOURCE_DATE_EPOCH = 946684800 + (uint32(source tree prefix) modulo 1200000000)'
	source_tree = $ExpectedSourceTree
}
$environmentExports = "export SOURCE_DATE_EPOCH='$sourceDateEpoch' KBUILD_BUILD_USER='arm64-vnext' KBUILD_BUILD_HOST='reproducible' KBUILD_BUILD_VERSION='1' KBUILD_BUILD_TIMESTAMP='$buildTimestamp' ZERO_AR_DATE='1' TZ='UTC' LC_ALL='C'"

$toolBinDirectories = @($resolvedTools | ForEach-Object { Split-Path -Parent $_.path } | Sort-Object -Unique)
$controlBin = Split-Path -Parent $ControlBash
$msysPath = @($toolBinDirectories | ForEach-Object { ConvertTo-MsysPath $_ })
$msysPath += ConvertTo-MsysPath $controlBin
$msysPath += '/c/Windows/System32'
$pathValue = $msysPath -join ':'
$fragmentRelative = 'configs\arm64_vnext_bootstrap_defconfig'
$requestedSettings = @(Get-ConfigSettings (Join-Path $SourceDirectory $fragmentRelative))

$evidenceDirectory = Split-Path -Parent $EvidencePath
$artifactDirectory = Split-Path -Parent $ArtifactPath
New-Item -ItemType Directory -Force -Path $evidenceDirectory, $artifactDirectory | Out-Null
$workRoot = Join-Path $evidenceDirectory ".$epoch-busybox-build-$PID"
if (Test-Path -LiteralPath $workRoot) {
	throw "Build work root already exists: $workRoot"
}
New-Item -ItemType Directory -Path $workRoot | Out-Null
$archive = Join-Path $workRoot 'source.tar'
Invoke-Git @('-c', 'core.autocrlf=false', '-C', $SourceDirectory, 'archive', '--format=tar', "--output=$archive", $ExpectedSourceTree) | Out-Null

$builds = @()
try {
	for ($buildNumber = 1; $buildNumber -le 2; $buildNumber++) {
		$buildDirectory = Join-Path $workRoot "build-$buildNumber"
		New-Item -ItemType Directory -Path $buildDirectory | Out-Null
		& tar -xf $archive -C $buildDirectory
		if ($LASTEXITCODE -ne 0) {
			throw "Source extraction failed for build $buildNumber"
		}
		$materializedTree = Assert-MaterializedTree $buildDirectory $ExpectedSourceTree
		if ([IO.File]::ReadAllBytes((Join-Path $buildDirectory 'Config.in')) -contains 13) {
			throw 'Materialized source is CRLF-transformed'
		}

		$buildMsys = ConvertTo-MsysPath $buildDirectory
		$config = Join-Path $buildDirectory '.config'
		$fragment = Join-Path $buildDirectory $fragmentRelative
		$timer = [Diagnostics.Stopwatch]::StartNew()
		Invoke-Control "set -e; $environmentExports; export PATH='$pathValue'; cd '$buildMsys'; make HOST_COMPILER=clang allnoconfig"
		Merge-ConfigFragment $config $requestedSettings

		$savedPath = $env:PATH
		$savedEnvironment = @{}
		foreach ($name in $deterministicEnvironment.Keys | Where-Object { $_ -ne 'derivation' -and $_ -ne 'source_tree' }) {
			$savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
			[Environment]::SetEnvironmentVariable($name, [string]$deterministicEnvironment[$name], 'Process')
		}
		try {
			$env:PATH = ($toolBinDirectories + 'C:\Windows\System32') -join ';'
			$conf = Join-Path $buildDirectory 'scripts\kconfig\conf'
			Push-Location $buildDirectory
			try {
				& $conf -o Config.in
				if ($LASTEXITCODE -ne 0) {
					throw "Kconfig resolution failed with exit code $LASTEXITCODE"
				}
			} finally {
				Pop-Location
			}
		} finally {
			$env:PATH = $savedPath
			foreach ($name in $savedEnvironment.Keys) {
				[Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
			}
		}
		$resolvedSettings = @(Assert-ResolvedConfig $config $requestedSettings)
		Start-Sleep -Seconds 1
		Invoke-Control "set -e; $environmentExports; export PATH='$pathValue'; cd '$buildMsys'; make -j$Jobs busybox.exe"
		$resolvedSettings = @(Assert-ResolvedConfig $config $requestedSettings)
		$timer.Stop()

		$binary = Join-Path $buildDirectory 'busybox.exe'
		if (-not (Test-Path -LiteralPath $binary)) {
			throw "Build $buildNumber completed without busybox.exe"
		}
		$pdbFiles = @(Get-ChildItem -LiteralPath $buildDirectory -Recurse -Filter '*.pdb' -File)
		if ($pdbFiles.Count -ne 0) {
			throw "Build $buildNumber emitted nonessential PDB files"
		}
		$coffFiles = @(
			Get-ChildItem -LiteralPath $buildDirectory -Recurse -File |
				Where-Object { $_.Extension -in @('.o', '.a') }
		)
		$nonzeroCoffTimestamps = @($coffFiles | Where-Object { (Get-CoffTimestamp $_.FullName) -ne 0 })
		if ($nonzeroCoffTimestamps.Count -ne 0) {
			throw "Build $buildNumber emitted COFF objects with wall-clock timestamps"
		}
		$binaryEvidence = Test-Binary $binary $payloadApplets $bootstrapApplets
		$autoconfTimestamp = [IO.File]::ReadAllLines((Join-Path $buildDirectory 'include\autoconf.h')) |
			Where-Object { $_ -match '^#define AUTOCONF_TIMESTAMP ' } |
			Select-Object -First 1
		if (-not $autoconfTimestamp) {
			throw 'Fixed BusyBox banner metadata is missing'
		}
		$builds += [ordered]@{
			number = $buildNumber
			source_directory = $buildDirectory
			materialized_tree = $materializedTree
			jobs = $Jobs
			elapsed_seconds = [Math]::Round($timer.Elapsed.TotalSeconds, 3)
			config_sha256 = Get-Sha256 $config
			requested_config_count = $requestedSettings.Count
			resolved_config = $resolvedSettings
			autoconf_timestamp = $autoconfTimestamp
			coff_or_archive_count = $coffFiles.Count
			nonzero_coff_timestamp_count = $nonzeroCoffTimestamps.Count
			pdb_count = $pdbFiles.Count
			binary = $binary
			artifact = $binaryEvidence
		}
	}

	if ($builds[0].artifact.sha256 -ne $builds[1].artifact.sha256) {
		throw 'The two clean builds are not byte-identical'
	}
	if ($builds[0].config_sha256 -ne $builds[1].config_sha256 -or
		$builds[0].autoconf_timestamp -ne $builds[1].autoconf_timestamp) {
		throw 'The two clean builds resolved different deterministic metadata'
	}

	$verifiedBinary = $builds[0].binary
	$testTimer = [Diagnostics.Stopwatch]::StartNew()
	$testSuite = ConvertTo-MsysPath (Join-Path $workRoot 'build-1\testsuite')
	Invoke-Control "set -e; $environmentExports; export PATH='$pathValue'; cd '$testSuite'; ../busybox.exe sh ./runtest -v all_arm64_vnext_bootstrap"
	$testTimer.Stop()

	if (-not ('Arm64VNextNativeMethods' -as [type])) {
		Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class Arm64VNextNativeMethods
{
    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessMachineInformation
    {
        public ushort ProcessMachine;
        public ushort Reserved;
        public uint MachineAttributes;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsWow64Process2(
        IntPtr process,
        out ushort processMachine,
        out ushort nativeMachine);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetProcessInformation(
        IntPtr process,
        int informationClass,
        out ProcessMachineInformation information,
        uint informationSize);
}
'@
	}

	$process = Start-Process -FilePath $verifiedBinary -ArgumentList @('sleep', '10') -PassThru -WindowStyle Hidden
	try {
		Start-Sleep -Milliseconds 200
		[ushort]$processMachine = 0
		[ushort]$nativeMachine = 0
		$machineInfo = [Arm64VNextNativeMethods+ProcessMachineInformation]::new()
		$wow64Ok = [Arm64VNextNativeMethods]::IsWow64Process2(
			$process.Handle,
			[ref]$processMachine,
			[ref]$nativeMachine)
		$machineInfoOk = [Arm64VNextNativeMethods]::GetProcessInformation(
			$process.Handle,
			9,
			[ref]$machineInfo,
			[Runtime.InteropServices.Marshal]::SizeOf($machineInfo))
		if (-not $wow64Ok -or -not $machineInfoOk) {
			throw 'Native process machine APIs failed'
		}
		if ($processMachine -ne 0 -or $nativeMachine -ne 0xAA64 -or $machineInfo.ProcessMachine -ne 0xAA64) {
			throw 'BusyBox process is not native ARM64'
		}
		$processEvidence = [ordered]@{
			is_wow64_process2 = [ordered]@{
				process_machine = ('0x{0:X4}' -f $processMachine)
				native_machine = ('0x{0:X4}' -f $nativeMachine)
			}
			process_machine_type_info = ('0x{0:X4}' -f $machineInfo.ProcessMachine)
			process_id = $process.Id
		}
	} finally {
		if (-not $process.HasExited) {
			Stop-Process -Id $process.Id -Force
		}
	}

	Copy-Item -LiteralPath $verifiedBinary -Destination $ArtifactPath
	if ((Get-PeMachine $ArtifactPath) -ne '0xAA64' -or
		(Get-Sha256 $ArtifactPath) -in @($control.bash.sha256, $control.make.sha256)) {
		throw 'The shipped artifact did not remain native or excluded-control clean'
	}

	$evidenceBuilds = @($builds | ForEach-Object {
		[ordered]@{
			number = $_.number
			materialized_tree = $_.materialized_tree
			jobs = $_.jobs
			elapsed_seconds = $_.elapsed_seconds
			config_sha256 = $_.config_sha256
			requested_config_count = $_.requested_config_count
			resolved_config = $_.resolved_config
			autoconf_timestamp = $_.autoconf_timestamp
			coff_or_archive_count = $_.coff_or_archive_count
			nonzero_coff_timestamp_count = $_.nonzero_coff_timestamp_count
			pdb_count = $_.pdb_count
			artifact_sha256 = $_.artifact.sha256
		}
	})
	$evidence = [ordered]@{
		schema = 'arm64-vnext-busybox-bootstrap-evidence-v2'
		epoch = $epoch
		node_id = $nodeId
		audit_remediation = [ordered]@{
			rejected_commit = $rejectedCommit
			audit_sha256 = $auditSha256
			audit_verdict = 'NO-GO'
		}
		source = [ordered]@{
			repository = 'crutkas/busybox-w32'
			origin = $origin
			branch = $repositoryBranch
			repository_commit = $repositoryCommit
			repository_tree = $repositoryTree
			base_commit = $baseCommit
			base_tree = $baseTree
			build_source_tree = $ExpectedSourceTree
			candidate_patch = $candidatePatchEvidence
			changed_files = $changedFiles
			materialized_tree_checks = @($builds.materialized_tree)
		}
		provenance = [ordered]@{
			ledger = $ProvenanceLedger
			ledger_sha256 = $ledgerSha256
			required_input_count = 55
			all_required_inputs_admitted = $true
			resolved_native_tools = $resolvedTools
			old_artifact_inputs = @()
			no_mutable_latest_inputs = $true
		}
		control = $control
		determinism = [ordered]@{
			environment = $deterministicEnvironment
			linker_option = '--no-insert-timestamp'
			full_binary_sha256_equal = $true
			builds = $evidenceBuilds
		}
		config_contract = [ordered]@{
			requested_count = $requestedSettings.Count
			all_requested_settings_resolved_exactly = $true
			utf8_output = [ordered]@{
				requested = $false
				rationale = 'Not required by the sealed payload/bootstrap applet contract; avoiding Win32 resource/manifest scope keeps this layer minimal.'
			}
			tar_autodetect = [ordered]@{
				requested = $false
				rationale = 'Win32 NOMMU delegates compressed tar input to an external decompressor, while gunzip is outside the exact applet contract; uncompressed native tar behavior is tested.'
			}
			ash_entry = [ordered]@{
				exposed = $false
				rationale = 'ASH implementation is selected for sh; the standalone ash applet is outside the supported contract.'
			}
			lash_entry = [ordered]@{
				exposed = $true
				rationale = 'The Win32 port forces lash when SH_IS_ASH is enabled.'
			}
		}
		tests = [ordered]@{
			name = 'all_arm64_vnext_bootstrap'
			elapsed_seconds = [Math]::Round($testTimer.Elapsed.TotalSeconds, 3)
			native_shell_core_smoke = $builds[0].artifact.shell_core_smoke
		}
		artifact = [ordered]@{
			path = $ArtifactPath
			size = (Get-Item -LiteralPath $ArtifactPath).Length
			sha256 = Get-Sha256 $ArtifactPath
			pe_machine = Get-PeMachine $ArtifactPath
			pe_timestamp = Get-PeTimestamp $ArtifactPath
			banner = $builds[0].artifact.banner
			binary_applet_count = $builds[0].artifact.binary_applet_count
			binary_applets = $builds[0].artifact.binary_applets
			shipped_payload_applet_count = $payloadApplets.Count
			shipped_payload_applets = $payloadApplets
			bootstrap_applet_count = $bootstrapApplets.Count
			bootstrap_applets = $bootstrapApplets
			process = $processEvidence
		}
	}
	[IO.File]::WriteAllText(
		$EvidencePath,
		($evidence | ConvertTo-Json -Depth 30),
		[Text.UTF8Encoding]::new($false))

	[ordered]@{
		artifact = $ArtifactPath
		artifact_sha256 = $evidence.artifact.sha256
		build_1_seconds = $builds[0].elapsed_seconds
		build_2_seconds = $builds[1].elapsed_seconds
		byte_identical = $true
		evidence = $EvidencePath
		evidence_sha256 = Get-Sha256 $EvidencePath
	} | ConvertTo-Json
} finally {
	if (Test-Path -LiteralPath $workRoot) {
		Remove-Item -LiteralPath $workRoot -Recurse -Force
	}
}
