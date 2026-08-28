# SPDX-License-Identifier: GPL-2.0-only

[CmdletBinding()]
param(
	[string]$BusyBoxPath,
	[string]$ModulePolicyPath,
	[string]$EvidencePath = (Join-Path (Get-Location) `
		'arm64-native-evidence.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'Arm64Validation.psm1') -Force

$recordIds = @(
	'policy.source-dynamic-link',
	'prerequisite.binary',
	'prerequisite.module-policy',
	'host.os-architecture',
	'host.diagnostic-process-architecture',
	'binary.identity',
	'binary.pe-machine',
	'binary.pe32-plus',
	'binary.chpe-metadata',
	'binary.dynamic-imports',
	'process.architecture',
	'process.environment',
	'process.uname',
	'process.modules',
	'process.abi-smoke',
	'tests.git-critical-applets',
	'tests.full-suite'
)
$records = [ordered]@{}

function Add-EvidenceRecord {
	param(
		[Parameter(Mandatory)][string]$Id,
		[Parameter(Mandatory)]
		[ValidateSet('pass', 'fail', 'blocked', 'skipped')]
		[string]$Status,
		[Parameter(Mandatory)][object]$Expected,
		[Parameter(Mandatory)][object]$Observed,
		[Parameter(Mandatory)][string]$Detail
	)

	if ($Id -notin $recordIds) {
		throw [InvalidOperationException]::new(
			"Unknown evidence record '$Id'"
		)
	}
	if ($records.Contains($Id)) {
		throw [InvalidOperationException]::new(
			"Duplicate evidence record '$Id'"
		)
	}
	$records[$Id] = [pscustomobject][ordered]@{
		id = $Id
		status = $Status
		expected = $Expected
		observed = $Observed
		detail = $Detail
	}
}

function Write-Utf8File {
	param(
		[Parameter(Mandatory)][string]$Path,
		[AllowEmptyString()][string]$Content
	)

	$fullPath = [IO.Path]::GetFullPath($Path)
	$parent = [IO.Path]::GetDirectoryName($fullPath)
	if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
		throw [IO.DirectoryNotFoundException]::new(
			"Output directory '$parent' does not exist"
		)
	}
	[IO.File]::WriteAllText(
		$fullPath,
		$Content,
		[Text.UTF8Encoding]::new($false)
	)
	return $fullPath
}

function Get-RunObservation {
	param(
		[Parameter(Mandatory)][object]$Result,
		[Parameter(Mandatory)][string]$LogPrefix
	)

	$stdoutPath = Write-Utf8File "$LogPrefix.stdout.txt" $Result.stdout
	$stderrPath = Write-Utf8File "$LogPrefix.stderr.txt" $Result.stderr
	$accounting = Get-TestResultAccounting -Output $Result.stdout
	return [pscustomobject][ordered]@{
		exitCode = $Result.exitCode
		stdoutSha256 = Get-TextSha256 -Text $Result.stdout
		stderrSha256 = Get-TextSha256 -Text $Result.stderr
		stdoutPath = $stdoutPath
		stderrPath = $stderrPath
		accounting = $accounting
	}
}

function Start-HeldBusyBoxProcess {
	param([Parameter(Mandatory)][string]$Path)

	$info = [Diagnostics.ProcessStartInfo]::new()
	$info.FileName = $Path
	$info.UseShellExecute = $false
	$info.CreateNoWindow = $true
	$info.RedirectStandardInput = $true
	$info.RedirectStandardOutput = $true
	$info.RedirectStandardError = $true
	[void]$info.ArgumentList.Add('sh')
	[void]$info.ArgumentList.Add('-c')
	[void]$info.ArgumentList.Add('read arm64_validation_hold')

	$process = [Diagnostics.Process]::new()
	$process.StartInfo = $info
	if (-not $process.Start()) {
		throw [InvalidOperationException]::new(
			"Failed to start '$Path'"
		)
	}
	Start-Sleep -Milliseconds 250
	$process.Refresh()
	if ($process.HasExited) {
		$stderr = $process.StandardError.ReadToEnd()
		$code = $process.ExitCode
		$process.Dispose()
		throw [InvalidOperationException]::new(
			"Held BusyBox process exited with ${code}: $stderr"
		)
	}
	return $process
}

$repositoryRoot = [IO.Path]::GetFullPath(
	(Join-Path $PSScriptRoot '..\..')
)
$testsuitePath = Join-Path $repositoryRoot 'testsuite'
$configPath = Join-Path $repositoryRoot 'configs\mingw64a_defconfig'
$evidenceFullPath = [IO.Path]::GetFullPath($EvidencePath)
$logPrefix = [IO.Path]::Combine(
	[IO.Path]::GetDirectoryName($evidenceFullPath),
	[IO.Path]::GetFileNameWithoutExtension($evidenceFullPath)
)

$configReady = $false
try {
	$configText = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8
	$configFailures = @(Get-Mingw64aConfigPolicyFailures -Text $configText)
	$configReady = $configFailures.Count -eq 0
	Add-EvidenceRecord 'policy.source-dynamic-link' `
		$(if ($configReady) { 'pass' } else { 'fail' }) `
		([pscustomobject][ordered]@{
			platform = 'MinGW'
			configStatic = 'disabled'
			configStaticLibgcc = 'disabled'
			compiler = 'clang'
			crossPrefix = 'aarch64-w64-mingw32-'
		}) `
		([pscustomobject][ordered]@{
			path = $configPath
			failures = $configFailures
		}) `
		'The source policy is dynamic; this record is not static-link proof.'
} catch {
	Add-EvidenceRecord 'policy.source-dynamic-link' 'fail' `
		'dynamic ARM64 MinGW configuration readable' `
		([pscustomobject]@{ error = $_.Exception.Message }) `
		'Source configuration could not be evaluated.'
}

$binaryReady = $false
$binaryFullPath = $null
$candidateDirectory = $null
$candidateConfigPath = $null
if ([string]::IsNullOrWhiteSpace($BusyBoxPath)) {
	Add-EvidenceRecord 'prerequisite.binary' 'blocked' `
		'an explicitly supplied busybox.exe with sibling .config' `
		'not supplied' `
		'No binary was supplied; native diagnostics are refused.'
} elseif (-not (Test-Path -LiteralPath $BusyBoxPath -PathType Leaf)) {
	Add-EvidenceRecord 'prerequisite.binary' 'blocked' `
		'an explicitly supplied busybox.exe with sibling .config' `
		([pscustomobject]@{ path = $BusyBoxPath; exists = $false }) `
		'The supplied binary does not exist; native diagnostics are refused.'
} else {
	$binaryFullPath = (Resolve-Path -LiteralPath $BusyBoxPath).Path
	$candidateDirectory = [IO.Path]::GetDirectoryName($binaryFullPath)
	$candidateConfigPath = Join-Path $candidateDirectory '.config'
	$binaryFailures = [Collections.Generic.List[string]]::new()
	$binaryBlocked = $false

	if ([IO.Path]::GetFileName($binaryFullPath) -ine 'busybox.exe') {
		$binaryFailures.Add(
			"The test harness requires the candidate name 'busybox.exe'"
		)
	}
	if (-not (Test-Path -LiteralPath $candidateConfigPath `
		-PathType Leaf)) {
		$binaryBlocked = $true
		$binaryFailures.Add(
			"The sibling build configuration '$candidateConfigPath' is absent"
		)
	} elseif ($configReady) {
		try {
			$candidateConfigText = Get-Content `
				-LiteralPath $candidateConfigPath -Raw `
				-Encoding UTF8
			foreach ($failure in @(Get-ConfigEquivalenceFailures `
				-ExpectedText $configText `
				-ObservedText $candidateConfigText)) {
				$binaryFailures.Add($failure)
			}
		} catch {
			$binaryFailures.Add($_.Exception.Message)
		}
	} else {
		$binaryFailures.Add(
			'The source configuration is not ready for comparison'
		)
	}

	$binaryReady = $binaryFailures.Count -eq 0
	Add-EvidenceRecord 'prerequisite.binary' `
		$(if ($binaryReady) {
			'pass'
		} elseif ($binaryBlocked) {
			'blocked'
		} else {
			'fail'
		}) `
		([pscustomobject][ordered]@{
			fileName = 'busybox.exe'
			siblingConfig = 'exact normalized mingw64a_defconfig'
		}) `
		([pscustomobject][ordered]@{
			path = $binaryFullPath
			configPath = $candidateConfigPath
			failures = @($binaryFailures)
		}) `
		'The tests bind to this directory and exact config; presence grants no authority.'
}

$policyReady = $false
$modulePolicy = $null
if ([string]::IsNullOrWhiteSpace($ModulePolicyPath)) {
	Add-EvidenceRecord 'prerequisite.module-policy' 'blocked' `
		'an external-independent-review module policy' `
		'not supplied' `
		'The diagnostic cannot generate or approve its own module allowlist.'
} elseif (-not (Test-Path -LiteralPath $ModulePolicyPath -PathType Leaf)) {
	Add-EvidenceRecord 'prerequisite.module-policy' 'blocked' `
		'an external-independent-review module policy' `
		([pscustomobject]@{
			path = $ModulePolicyPath
			exists = $false
		}) `
		'The external module policy is absent.'
} else {
	try {
		$modulePolicy = Read-ModulePolicy -Path $ModulePolicyPath
		$policyReady = $true
		Add-EvidenceRecord 'prerequisite.module-policy' 'pass' `
			([pscustomobject]@{
				schemaVersion = 1
				authority = 'external-independent-review'
			}) `
			([pscustomobject]@{
				path = (Resolve-Path -LiteralPath `
					$ModulePolicyPath).Path
				schemaVersion = $modulePolicy.schemaVersion
				authority = $modulePolicy.authority
			}) `
			'The policy is compared only; it is never generated here.'
	} catch {
		Add-EvidenceRecord 'prerequisite.module-policy' 'fail' `
			'a closed-schema external-independent-review policy' `
			([pscustomobject]@{ error = $_.Exception.Message }) `
			'The supplied module policy is invalid.'
	}
}

$osArchitecture = [Runtime.InteropServices.RuntimeInformation]::
	OSArchitecture.ToString()
$processArchitecture = [Runtime.InteropServices.RuntimeInformation]::
	ProcessArchitecture.ToString()
$hostReady = $osArchitecture -eq 'Arm64'
$harnessReady = $processArchitecture -eq 'Arm64'
Add-EvidenceRecord 'host.os-architecture' `
	$(if ($hostReady) { 'pass' } else { 'blocked' }) `
	'Arm64' $osArchitecture `
	'RuntimeInformation is OS-backed; an environment string is insufficient.'
Add-EvidenceRecord 'host.diagnostic-process-architecture' `
	$(if ($harnessReady) { 'pass' } else { 'blocked' }) `
	'Arm64' $processArchitecture `
	'The diagnostic process itself must be native ARM64 for module access.'

$identityReady = $false
$identityPolicyReady = $false
$binaryIdentity = $null
$peReady = $false
$pe = $null
$peMachineReady = $false
$peHeaderReady = $false
$peChpeReady = $false
$importPolicyReady = $false

if ($binaryReady) {
	try {
		$binaryIdentity = Get-FileIdentity -Path $binaryFullPath
		$identityReady = $true
		if ($policyReady) {
			$identityFailures = @()
			foreach ($property in @(
				'canonicalPath',
				'volumeSerial',
				'fileId',
				'sha256'
			)) {
				$differs = if ($property -eq 'canonicalPath') {
					[string]$modulePolicy.subject.$property -ine
						[string]$binaryIdentity.$property
				} else {
					[string]$modulePolicy.subject.$property -cne
						[string]$binaryIdentity.$property
				}
				if ($differs) {
					$identityFailures +=
						"$property differs from external policy"
				}
			}
			$identityPolicyReady =
				$identityFailures.Count -eq 0
			Add-EvidenceRecord 'binary.identity' `
				$(if ($identityPolicyReady) {
					'pass'
				} else {
					'fail'
				}) `
				$modulePolicy.subject $binaryIdentity `
				$(if ($identityFailures.Count -eq 0) {
					'Canonical path, volume serial, file ID, and hash match.'
				} else {
					$identityFailures -join '; '
				})
		} else {
			Add-EvidenceRecord 'binary.identity' 'blocked' `
				'exact identity from external module policy' `
				$binaryIdentity `
				'Identity was observed but has no independent expectation.'
		}
	} catch {
		Add-EvidenceRecord 'binary.identity' 'fail' `
			'canonical path, volume serial, file ID, and SHA-256' `
			([pscustomobject]@{ error = $_.Exception.Message }) `
			'Binary identity collection failed closed.'
	}

	try {
		$pe = Get-PeImageInfo -Path $binaryFullPath
		$peReady = $true
		$peMachineReady = $pe.machine -eq 0xaa64
		Add-EvidenceRecord 'binary.pe-machine' `
			$(if ($peMachineReady) { 'pass' } else { 'fail' }) `
			'0xAA64' $pe.machineHex `
			'Machine is read structurally from the COFF header.'

		$headerFailures = [Collections.Generic.List[string]]::new()
		if ($pe.optionalMagic -ne 0x020b) {
			$headerFailures.Add(
				"optional magic is $($pe.optionalMagicHex)"
			)
		}
		if ($pe.subsystem -ne 3) {
			$headerFailures.Add(
				"subsystem is $($pe.subsystem), expected 3"
			)
		}
		if (($pe.characteristics -band 0x0002) -eq 0) {
			$headerFailures.Add(
				'executable-image characteristic is absent'
			)
		}
		if (($pe.characteristics -band 0x2000) -ne 0) {
			$headerFailures.Add('DLL characteristic is present')
		}
		$peHeaderReady = $headerFailures.Count -eq 0
		Add-EvidenceRecord 'binary.pe32-plus' `
			$(if ($peHeaderReady) { 'pass' } else { 'fail' }) `
			([pscustomobject][ordered]@{
				optionalMagic = '0x020B'
				subsystem = 3
				executableImage = $true
				dll = $false
			}) `
			([pscustomobject][ordered]@{
				optionalMagic = $pe.optionalMagicHex
				subsystem = $pe.subsystem
				characteristics = '0x{0:X4}' -f `
					$pe.characteristics
				failures = @($headerFailures)
			}) `
			'PE32+, console subsystem, executable, and non-DLL flags are required.'

		$peChpeReady =
			$pe.loadConfig.chpeMetadataPointer -eq 0
		Add-EvidenceRecord 'binary.chpe-metadata' `
			$(if ($peChpeReady) { 'pass' } else { 'fail' }) `
			([pscustomobject]@{
				mode = 'pure-arm64'
				chpeMetadataPointer = '0x0000000000000000'
			}) `
			$pe.loadConfig `
			'CHPE/load-config data is parsed; hybrid images are not accepted.'

		$hasImports =
			@($pe.imports).Count + @($pe.delayImports).Count -gt 0
		$importsMatch = $false
		if ($policyReady) {
			$expectedImports = @($modulePolicy.imports |
				Sort-Object)
			$expectedDelay = @($modulePolicy.delayImports |
				Sort-Object)
			$observedImports = @($pe.imports | Sort-Object)
			$observedDelay = @($pe.delayImports | Sort-Object)
			$importsMatch =
				(($expectedImports -join "`n").ToLowerInvariant() `
					-ceq ($observedImports -join "`n").
					ToLowerInvariant()) -and
				(($expectedDelay -join "`n").ToLowerInvariant() `
					-ceq ($observedDelay -join "`n").
					ToLowerInvariant())
		}
		$importStatus = if (-not $hasImports) {
			'fail'
		} elseif (-not $policyReady) {
			'blocked'
		} elseif ($importsMatch) {
			'pass'
		} else {
			'fail'
		}
		$importPolicyReady = $importStatus -eq 'pass'
		Add-EvidenceRecord 'binary.dynamic-imports' $importStatus `
			$(if ($policyReady) {
				[pscustomobject]@{
					imports = @($modulePolicy.imports)
					delayImports =
						@($modulePolicy.delayImports)
				}
			} else {
				'exact nonempty imports from external module policy'
			}) `
			([pscustomobject]@{
				imports = @($pe.imports)
				delayImports = @($pe.delayImports)
			}) `
			'Dynamic imports must be nonempty and externally enumerated.'
	} catch {
		$pendingPeRecord = @(
			'binary.pe-machine',
			'binary.pe32-plus',
			'binary.chpe-metadata',
			'binary.dynamic-imports'
		) | Where-Object { -not $records.Contains($_) } |
			Select-Object -First 1
		if ($null -ne $pendingPeRecord) {
			Add-EvidenceRecord $pendingPeRecord 'fail' `
				'complete structural PE evaluation' `
				([pscustomobject]@{
					error = $_.Exception.Message
				}) `
				'PE evaluation failed closed without duplicating records.'
		}
	}
}

$runtimeReady = $configReady -and $binaryReady -and
	$hostReady -and $harnessReady -and $peReady -and
	$peMachineReady -and $peHeaderReady -and $peChpeReady -and
	$policyReady -and $identityPolicyReady -and $importPolicyReady

if ($runtimeReady) {
	$heldProcess = $null
	$liveProcessReady = $false
	$requiredSmokeApplets = @(
		'awk', 'cat', 'cp', 'diff', 'find',
		'grep', 'mkdir', 'mv', 'rm', 'sed',
		'sh', 'sort', 'tr', 'unzip', 'xargs'
	)
	$testEnvironment = @{
		bindir = $candidateDirectory
		tsdir = $testsuitePath
		DEBUG = 'true'
		LC_ALL = 'C'
		ECHO = 'echo'
		OPTIONFLAGS = ''
		SKIP_KNOWN_BUGS = ''
		TZ = 'UTC'
		VERBOSE = ''
	}
	try {
		$heldProcess = Start-HeldBusyBoxProcess -Path $binaryFullPath
		$mainPath = $heldProcess.MainModule.FileName
		$mainIdentity = Get-FileIdentity -Path $mainPath
		$mainPe = Get-PeImageInfo -Path $mainPath
		$processArchitectureReady =
			$mainPe.machine -eq 0xaa64 -and
			$identityReady -and
			$mainIdentity.volumeSerial -ceq
				$binaryIdentity.volumeSerial -and
			$mainIdentity.fileId -ceq $binaryIdentity.fileId
		Add-EvidenceRecord 'process.architecture' `
			$(if ($processArchitectureReady) {
				'pass'
			} else {
				'fail'
			}) `
			([pscustomobject]@{
				hostArchitecture = 'Arm64'
				processImageMachine = '0xAA64'
				processImageIdentity = 'input binary'
			}) `
			([pscustomobject]@{
				hostArchitecture = $osArchitecture
				processImageMachine = $mainPe.machineHex
				processImageIdentity = $mainIdentity
			}) `
			'The OS-launched process image, not uname, anchors this check.'

		$moduleSnapshot = @(Get-ProcessModuleSnapshot `
			-Process $heldProcess)
		if ($policyReady -and $identityReady) {
			$moduleFailures = @(Compare-ModulePolicy `
				-Policy $modulePolicy `
				-SubjectIdentity $binaryIdentity `
				-Pe $pe -Modules $moduleSnapshot)
			$modulePolicyMatchReady =
				$moduleFailures.Count -eq 0
			$liveProcessReady = $processArchitectureReady -and
				$modulePolicyMatchReady
			Add-EvidenceRecord 'process.modules' `
				$(if ($modulePolicyMatchReady) {
					'pass'
				} else {
					'fail'
				}) `
				@($modulePolicy.modules) $moduleSnapshot `
				$(if ($moduleFailures.Count -eq 0) {
					'Loaded module identities match external policy.'
				} else {
					$moduleFailures -join '; '
				})
		} else {
			Add-EvidenceRecord 'process.modules' 'blocked' `
				'exact loaded-module identities from external policy' `
				$moduleSnapshot `
				'Modules were observed but cannot authorize themselves.'
		}
	} catch {
		if (-not $records.Contains('process.architecture')) {
			Add-EvidenceRecord 'process.architecture' 'fail' `
				'a live native ARM64 BusyBox process' `
				([pscustomobject]@{
					error = $_.Exception.Message
				}) `
				'Native process inspection failed closed.'
		}
		if (-not $records.Contains('process.modules')) {
			Add-EvidenceRecord 'process.modules' 'fail' `
				'complete OS process-module inventory' `
				([pscustomobject]@{
					error = $_.Exception.Message
				}) `
				'Module enumeration or identity collection failed closed.'
		}
	} finally {
		if ($null -ne $heldProcess) {
			if (-not $heldProcess.HasExited) {
				$heldProcess.StandardInput.Close()
				if (-not $heldProcess.WaitForExit(1000)) {
					$heldProcess.Kill($true)
					$heldProcess.WaitForExit()
				}
			}
			$heldProcess.Dispose()
		}
	}

	if ($liveProcessReady) {
	$appletInventory = @()
	$smokeReady = $false
	try {
		$environmentResult = Invoke-CapturedProcess `
			-FilePath $binaryFullPath `
			-ArgumentList @(
				'sh',
				'-c',
				'printf "ARCH=%s\nW6432=%s\n" "${PROCESSOR_ARCHITECTURE-}" "${PROCESSOR_ARCHITEW6432-}"'
			) -WorkingDirectory $testsuitePath -TimeoutSeconds 30
		$environmentMatch = [regex]::Match(
			$environmentResult.stdout,
			'\AARCH=([^\r\n]*)\r?\nW6432=([^\r\n]*)\r?\n\z'
		)
		$childArchitecture = if ($environmentMatch.Success) {
			$environmentMatch.Groups[1].Value
		} else {
			'<unparseable>'
		}
		$childArchitew6432 = if ($environmentMatch.Success) {
			$environmentMatch.Groups[2].Value
		} else {
			'<unparseable>'
		}
		$environmentReady =
			$environmentResult.exitCode -eq 0 -and
			$environmentMatch.Success -and
			$childArchitecture -ceq 'ARM64' -and
			$childArchitew6432 -ceq ''
		Add-EvidenceRecord 'process.environment' `
			$(if ($environmentReady) { 'pass' } else { 'fail' }) `
			([pscustomobject]@{
				PROCESSOR_ARCHITECTURE = 'ARM64'
				PROCESSOR_ARCHITEW6432 = ''
				role = 'corroborating-only'
			}) `
			([pscustomobject]@{
				exitCode = $environmentResult.exitCode
				PROCESSOR_ARCHITECTURE =
					$childArchitecture
				PROCESSOR_ARCHITEW6432 =
					$childArchitew6432
				stderr = $environmentResult.stderr
			}) `
			'Environment values corroborate structural checks but cannot replace them.'
	} catch {
		Add-EvidenceRecord 'process.environment' 'fail' `
			'native child environment report' `
			([pscustomobject]@{ error = $_.Exception.Message }) `
			'Child environment observation failed closed.'
	}

	try {
		$unameResult = Invoke-CapturedProcess `
			-FilePath $binaryFullPath `
			-ArgumentList @('uname', '-m') `
			-WorkingDirectory $testsuitePath -TimeoutSeconds 30
		$uname = $unameResult.stdout.TrimEnd("`r", "`n")
		$unameReady = $unameResult.exitCode -eq 0 -and
			$uname -ceq 'aarch64'
		Add-EvidenceRecord 'process.uname' `
			$(if ($unameReady) { 'pass' } else { 'fail' }) `
			([pscustomobject]@{
				value = 'aarch64'
				role = 'corroborating-only'
			}) `
			([pscustomobject]@{
				exitCode = $unameResult.exitCode
				stdout = $uname
				stderr = $unameResult.stderr
			}) `
			'uname is checked only after OS and PE architecture checks pass.'
	} catch {
		Add-EvidenceRecord 'process.uname' 'fail' `
			'aarch64 from a structurally native process' `
			([pscustomobject]@{ error = $_.Exception.Message }) `
			'uname observation failed closed.'
	}

	try {
		$abiResult = Invoke-CapturedProcess `
			-FilePath $binaryFullPath `
			-ArgumentList @(
				'sh',
				'-c',
				'arm64_token=parent; export arm64_token; child=$(sh -c ''test "$arm64_token" = parent && printf child; exit 7''); code=$?; printf "%s:%s\n" "$child" "$code"; printf "b\na\n" | sort | tr a-z A-Z'
			) -WorkingDirectory $testsuitePath -TimeoutSeconds 30
		$abiExpected = "child:7`nA`nB`n"
		$abiOutput = $abiResult.stdout -replace "`r`n", "`n"
		$abiReady = $abiResult.exitCode -eq 0 -and
			$abiOutput -ceq $abiExpected -and
			$abiResult.stderr -ceq ''
		Add-EvidenceRecord 'process.abi-smoke' `
			$(if ($abiReady) { 'pass' } else { 'fail' }) `
			([pscustomobject]@{
				exitCode = 0
				stdout = $abiExpected
				stderr = ''
			}) `
			([pscustomobject]@{
				exitCode = $abiResult.exitCode
				stdout = $abiOutput
				stderr = $abiResult.stderr
			}) `
			'This exercises child creation, environment inheritance, exit status, pipes, and applet dispatch.'
	} catch {
		Add-EvidenceRecord 'process.abi-smoke' 'fail' `
			'deterministic process, environment, status, and pipe behavior' `
			([pscustomobject]@{ error = $_.Exception.Message }) `
			'ABI smoke execution failed closed.'
	}

	try {
		$listResult = Invoke-CapturedProcess `
			-FilePath $binaryFullPath `
			-ArgumentList @('--list') `
			-WorkingDirectory $testsuitePath -TimeoutSeconds 30
		$appletInventory = @($listResult.stdout -split '\r?\n' |
			Where-Object { $_ -match '^[A-Za-z0-9_.+\[\]-]+$' } |
			Sort-Object -Unique)
		$missingApplets = @($requiredSmokeApplets |
			Where-Object { $_ -notin $appletInventory })
		$inventoryReady = $listResult.exitCode -eq 0 -and
			$listResult.stderr -eq '' -and
			$appletInventory.Count -gt 15 -and
			$missingApplets.Count -eq 0
		if (-not $inventoryReady) {
			throw [InvalidOperationException]::new(
				"Candidate applet inventory is incomplete: $($missingApplets -join ', ')"
			)
		}

		$smokeResult = Invoke-CapturedProcess `
			-FilePath $binaryFullPath `
			-ArgumentList @(
				'sh',
				'./runtest',
				'-v',
				'all_git_critical'
			) -WorkingDirectory $testsuitePath `
			-Environment $testEnvironment
		$smokeObservation = Get-RunObservation `
			-Result $smokeResult `
			-LogPrefix "$logPrefix.git-critical"
		$smokeReady = $inventoryReady -and
			$smokeObservation.exitCode -eq 0 -and
			$smokeObservation.accounting.pass -eq 5 -and
			$smokeObservation.accounting.fail -eq 0 -and
			$smokeObservation.accounting.skipped -eq 0 -and
			$smokeObservation.accounting.untested -eq 0
		Add-EvidenceRecord 'tests.git-critical-applets' `
			$(if ($smokeReady) { 'pass' } else { 'fail' }) `
			([pscustomobject]@{
				definedApplets = 15
				testCases = 5
				exitCode = 0
				fail = 0
				skipped = 0
				untested = 0
			}) `
			([pscustomobject][ordered]@{
				requiredApplets = $requiredSmokeApplets
				candidateAppletCount = $appletInventory.Count
				missingApplets = $missingApplets
				run = $smokeObservation
			}) `
			'Five self-contained cases cover the declared 15 applets.'
	} catch {
		Add-EvidenceRecord 'tests.git-critical-applets' 'fail' `
			'five passing cases covering 15 applets' `
			([pscustomobject]@{ error = $_.Exception.Message }) `
			'Git-critical smoke execution failed closed.'
	}

	if ($smokeReady) {
	try {
		$fullArguments = @('sh', './runtest', '-v') +
			$appletInventory
		$fullTestEnvironment = $testEnvironment.Clone()
		$fullTestEnvironment.SKIP_KNOWN_BUGS = 'true'
		$fullResult = Invoke-CapturedProcess `
			-FilePath $binaryFullPath `
			-ArgumentList $fullArguments `
			-WorkingDirectory $testsuitePath `
			-Environment $fullTestEnvironment
		$fullObservation = Get-RunObservation `
			-Result $fullResult -LogPrefix "$logPrefix.full-suite"
		$testTargetCount = @($appletInventory |
			Where-Object {
				(Test-Path -LiteralPath (
					Join-Path $testsuitePath "$_.tests"
				) -PathType Leaf) -or
				(Test-Path -LiteralPath (
					Join-Path $testsuitePath $_
				) -PathType Container)
			}).Count
		$fullReady = $fullObservation.exitCode -eq 0 -and
			$fullObservation.accounting.fail -eq 0 -and
			$fullObservation.accounting.notBuiltSkipped -eq 0 -and
			$testTargetCount -gt 0 -and
			$fullObservation.accounting.pass -gt 0 -and
			$fullObservation.accounting.resultLines -ge
				$testTargetCount
		Add-EvidenceRecord 'tests.full-suite' `
			$(if ($fullReady) { 'pass' } else { 'fail' }) `
			([pscustomobject]@{
				exitCode = 0
				fail = 0
				notBuiltSkipped = 0
				resultLines = "at-least-$testTargetCount"
				requestedApplets = $appletInventory.Count
				knownBugPolicy = 'SKIP_KNOWN_BUGS=true'
			}) $fullObservation `
			'Skipped and untested cases remain explicit in the accounting.'
	} catch {
		Add-EvidenceRecord 'tests.full-suite' 'fail' `
			'a nonempty full-suite result with zero failures' `
			([pscustomobject]@{ error = $_.Exception.Message }) `
			'Full-suite execution failed closed.'
	}
	}
	}
}

foreach ($id in $recordIds) {
	if (-not $records.Contains($id)) {
		Add-EvidenceRecord $id 'skipped' `
			'all prerequisites satisfied' `
			'not run' `
			'One or more prerequisite records are blocked or failed.'
	}
}

$orderedRecords = @($recordIds | ForEach-Object { $records[$_] })
foreach ($record in $orderedRecords) {
	Assert-ClosedKeys $record @(
		'detail',
		'expected',
		'id',
		'observed',
		'status'
	) "evidence record $($record.id)"
}
$summary = [ordered]@{
	total = $orderedRecords.Count
	pass = @($orderedRecords | Where-Object status -eq 'pass').Count
	fail = @($orderedRecords | Where-Object status -eq 'fail').Count
	blocked = @($orderedRecords |
		Where-Object status -eq 'blocked').Count
	skipped = @($orderedRecords |
		Where-Object status -eq 'skipped').Count
}
$executionStatus = if ($summary.fail -gt 0) {
	'failed'
} elseif ($summary.blocked -gt 0) {
	'blocked'
} elseif ($summary.skipped -gt 0) {
	'incomplete'
} else {
	'complete'
}
$document = [pscustomobject][ordered]@{
	schemaVersion = 1
	authority = 'diagnostic-only'
	admission = 'not-evaluated'
	executionStatus = $executionStatus
	records = $orderedRecords
	summary = [pscustomobject]$summary
}
Assert-ClosedKeys $document @(
	'admission',
	'authority',
	'executionStatus',
	'records',
	'schemaVersion',
	'summary'
) 'evidence document'

$json = $document | ConvertTo-Json -Depth 20
[void](Write-Utf8File $evidenceFullPath ($json + "`n"))
$json

if ($executionStatus -ne 'complete') {
	exit 1
}
