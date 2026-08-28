# SPDX-License-Identifier: GPL-2.0-only

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ImageFileMachineArm64 = [uint16]0xaa64
$script:ImageFileMachineAmd64 = [uint16]0x8664
$script:Pe32PlusMagic = [uint16]0x020b

function Assert-ByteRange {
	param(
		[byte[]]$Bytes,
		[long]$Offset,
		[int]$Count,
		[string]$Field
	)

	if ($Offset -lt 0 -or $Count -lt 0 -or
	    $Offset -gt $Bytes.LongLength - $Count) {
		throw [IO.InvalidDataException]::new(
			"$Field extends beyond the input at offset $Offset"
		)
	}
}

function Read-UInt16LE {
	param([byte[]]$Bytes, [long]$Offset, [string]$Field)

	Assert-ByteRange $Bytes $Offset 2 $Field
	return [BitConverter]::ToUInt16($Bytes, [int]$Offset)
}

function Read-UInt32LE {
	param([byte[]]$Bytes, [long]$Offset, [string]$Field)

	Assert-ByteRange $Bytes $Offset 4 $Field
	return [BitConverter]::ToUInt32($Bytes, [int]$Offset)
}

function Read-UInt64LE {
	param([byte[]]$Bytes, [long]$Offset, [string]$Field)

	Assert-ByteRange $Bytes $Offset 8 $Field
	return [BitConverter]::ToUInt64($Bytes, [int]$Offset)
}

function Read-AsciiZ {
	param(
		[byte[]]$Bytes,
		[long]$Offset,
		[string]$Field,
		[int]$MaximumLength = 4096
	)

	Assert-ByteRange $Bytes $Offset 1 $Field
	$end = $Offset
	$limit = [Math]::Min($Bytes.LongLength, $Offset + $MaximumLength)
	while ($end -lt $limit -and $Bytes[$end] -ne 0) {
		$end++
	}
	if ($end -eq $limit) {
		throw [IO.InvalidDataException]::new(
			"$Field is not NUL-terminated within $MaximumLength bytes"
		)
	}

	return [Text.Encoding]::ASCII.GetString(
		$Bytes,
		[int]$Offset,
		[int]($end - $Offset)
	)
}

function Convert-RvaToFileOffset {
	param(
		[uint32]$Rva,
		[uint32]$SizeOfHeaders,
		[object[]]$Sections,
		[long]$FileLength,
		[string]$Field
	)

	if ($Rva -lt $SizeOfHeaders) {
		if ([long]$Rva -ge $FileLength) {
			throw [IO.InvalidDataException]::new(
				"$Field RVA 0x$($Rva.ToString('x8')) is outside the file"
			)
		}
		return [long]$Rva
	}

	foreach ($section in $Sections) {
		$span = [Math]::Max(
			[uint64]$section.virtualSize,
			[uint64]$section.rawSize
		)
		$start = [uint64]$section.virtualAddress
		$end = $start + $span
		if ([uint64]$Rva -ge $start -and [uint64]$Rva -lt $end) {
			$delta = [uint64]$Rva - $start
			if ($delta -ge [uint64]$section.rawSize) {
				throw [IO.InvalidDataException]::new(
					"$Field RVA points into an uninitialized section tail"
				)
			}
			$offset = [uint64]$section.rawPointer + $delta
			if ($offset -ge [uint64]$FileLength) {
				throw [IO.InvalidDataException]::new(
					"$Field RVA maps beyond the file"
				)
			}
			return [long]$offset
		}
	}

	throw [IO.InvalidDataException]::new(
		"$Field RVA 0x$($Rva.ToString('x8')) has no section mapping"
	)
}

function Read-ImportNames {
	param(
		[byte[]]$Bytes,
		[object]$Directory,
		[uint32]$SizeOfHeaders,
		[object[]]$Sections
	)

	if ($Directory.rva -eq 0 -and $Directory.size -eq 0) {
		return @()
	}
	if ($Directory.rva -eq 0 -or $Directory.size -lt 20) {
		throw [IO.InvalidDataException]::new(
			'The import directory is partially specified'
		)
	}

	$offset = Convert-RvaToFileOffset $Directory.rva $SizeOfHeaders `
		$Sections $Bytes.LongLength 'import directory'
	$maximum = [Math]::Min(
		[int](($Bytes.LongLength - $offset) / 20),
		4096
	)
	$names = [Collections.Generic.List[string]]::new()
	$terminated = $false

	for ($index = 0; $index -lt $maximum; $index++) {
		$descriptor = $offset + (20 * $index)
		Assert-ByteRange $Bytes $descriptor 20 'import descriptor'
		$values = 0..4 | ForEach-Object {
			Read-UInt32LE $Bytes ($descriptor + (4 * $_)) `
				"import descriptor field $_"
		}
		if (($values | Measure-Object -Sum).Sum -eq 0) {
			$terminated = $true
			break
		}
		if ($values[3] -eq 0) {
			throw [IO.InvalidDataException]::new(
				'An import descriptor has no DLL name RVA'
			)
		}
		$nameOffset = Convert-RvaToFileOffset $values[3] $SizeOfHeaders `
			$Sections $Bytes.LongLength 'import DLL name'
		$names.Add((Read-AsciiZ $Bytes $nameOffset 'import DLL name'))
	}

	if (-not $terminated) {
		throw [IO.InvalidDataException]::new(
			'The import descriptor table has no terminator'
		)
	}
	return @($names)
}

function Read-DelayImportNames {
	param(
		[byte[]]$Bytes,
		[object]$Directory,
		[uint32]$SizeOfHeaders,
		[object[]]$Sections,
		[uint64]$ImageBase
	)

	if ($Directory.rva -eq 0 -and $Directory.size -eq 0) {
		return @()
	}
	if ($Directory.rva -eq 0 -or $Directory.size -lt 32) {
		throw [IO.InvalidDataException]::new(
			'The delay-import directory is partially specified'
		)
	}

	$offset = Convert-RvaToFileOffset $Directory.rva $SizeOfHeaders `
		$Sections $Bytes.LongLength 'delay-import directory'
	$maximum = [Math]::Min(
		[int](($Bytes.LongLength - $offset) / 32),
		4096
	)
	$names = [Collections.Generic.List[string]]::new()
	$terminated = $false

	for ($index = 0; $index -lt $maximum; $index++) {
		$descriptor = $offset + (32 * $index)
		Assert-ByteRange $Bytes $descriptor 32 'delay-import descriptor'
		$values = 0..7 | ForEach-Object {
			Read-UInt32LE $Bytes ($descriptor + (4 * $_)) `
				"delay-import descriptor field $_"
		}
		if (($values | Measure-Object -Sum).Sum -eq 0) {
			$terminated = $true
			break
		}

		$nameRva = [uint64]$values[1]
		if (($values[0] -band 1) -eq 0) {
			if ($nameRva -lt $ImageBase) {
				throw [IO.InvalidDataException]::new(
					'Delay-import DLL name VA is below the image base'
				)
			}
			$nameRva -= $ImageBase
		}
		if ($nameRva -gt [uint32]::MaxValue) {
			throw [IO.InvalidDataException]::new(
				'Delay-import DLL name RVA exceeds 32 bits'
			)
		}
		$nameOffset = Convert-RvaToFileOffset ([uint32]$nameRva) `
			$SizeOfHeaders $Sections $Bytes.LongLength `
			'delay-import DLL name'
		$names.Add((Read-AsciiZ $Bytes $nameOffset `
			'delay-import DLL name'))
	}

	if (-not $terminated) {
		throw [IO.InvalidDataException]::new(
			'The delay-import descriptor table has no terminator'
		)
	}
	return @($names)
}

function Get-PeImageInfoFromBytes {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[byte[]]$Bytes,

		[string]$Source = '<memory>'
	)

	if (-not [BitConverter]::IsLittleEndian) {
		throw [PlatformNotSupportedException]::new(
			'PE parsing requires a little-endian host'
		)
	}
	Assert-ByteRange $Bytes 0 64 'DOS header'
	if ($Bytes[0] -ne 0x4d -or $Bytes[1] -ne 0x5a) {
		throw [IO.InvalidDataException]::new('The DOS MZ signature is absent')
	}

	$peOffset = Read-UInt32LE $Bytes 0x3c 'PE header offset'
	Assert-ByteRange $Bytes $peOffset 24 'PE and COFF headers'
	if ($Bytes[$peOffset] -ne 0x50 -or
	    $Bytes[$peOffset + 1] -ne 0x45 -or
	    $Bytes[$peOffset + 2] -ne 0 -or
	    $Bytes[$peOffset + 3] -ne 0) {
		throw [IO.InvalidDataException]::new('The PE signature is absent')
	}

	$machine = Read-UInt16LE $Bytes ($peOffset + 4) 'COFF machine'
	$numberOfSections = Read-UInt16LE $Bytes ($peOffset + 6) `
		'COFF section count'
	$optionalHeaderSize = Read-UInt16LE $Bytes ($peOffset + 20) `
		'COFF optional-header size'
	$characteristics = Read-UInt16LE $Bytes ($peOffset + 22) `
		'COFF characteristics'
	if ($numberOfSections -eq 0) {
		throw [IO.InvalidDataException]::new('The PE image has no sections')
	}

	$optionalOffset = [long]$peOffset + 24
	Assert-ByteRange $Bytes $optionalOffset $optionalHeaderSize `
		'optional header'
	$magic = Read-UInt16LE $Bytes $optionalOffset 'optional-header magic'
	switch ($magic) {
		0x020b {
			$numberOfDirectoriesOffset = 108
			$directoryOffset = 112
			$imageBase = Read-UInt64LE $Bytes ($optionalOffset + 24) `
				'image base'
		}
		0x010b {
			$numberOfDirectoriesOffset = 92
			$directoryOffset = 96
			$imageBase = [uint64](Read-UInt32LE $Bytes `
				($optionalOffset + 28) 'image base')
		}
		default {
			throw [IO.InvalidDataException]::new(
				"Unsupported optional-header magic 0x$($magic.ToString('x4'))"
			)
		}
	}

	if ($optionalHeaderSize -lt $directoryOffset) {
		throw [IO.InvalidDataException]::new(
			'The optional header is too short for data directories'
		)
	}
	$sizeOfHeaders = Read-UInt32LE $Bytes ($optionalOffset + 60) `
		'size of headers'
	$subsystem = Read-UInt16LE $Bytes ($optionalOffset + 68) 'subsystem'
	$numberOfDirectories = Read-UInt32LE $Bytes `
		($optionalOffset + $numberOfDirectoriesOffset) `
		'data-directory count'
	$availableDirectories = [int](($optionalHeaderSize -
		$directoryOffset) / 8)
	if ($numberOfDirectories -gt $availableDirectories) {
		throw [IO.InvalidDataException]::new(
			'The data-directory count exceeds the optional header'
		)
	}

	$directories = @()
	for ($index = 0; $index -lt $numberOfDirectories; $index++) {
		$entry = $optionalOffset + $directoryOffset + (8 * $index)
		$directories += [pscustomobject][ordered]@{
			index = $index
			rva = Read-UInt32LE $Bytes $entry `
				"data directory $index RVA"
			size = Read-UInt32LE $Bytes ($entry + 4) `
				"data directory $index size"
		}
	}

	$sectionTable = $optionalOffset + $optionalHeaderSize
	Assert-ByteRange $Bytes $sectionTable (40 * $numberOfSections) `
		'section table'
	$sections = @()
	for ($index = 0; $index -lt $numberOfSections; $index++) {
		$entry = $sectionTable + (40 * $index)
		$nameLength = 0
		while ($nameLength -lt 8 -and
		       $Bytes[$entry + $nameLength] -ne 0) {
			$nameLength++
		}
		$sections += [pscustomobject][ordered]@{
			name = [Text.Encoding]::ASCII.GetString(
				$Bytes,
				[int]$entry,
				$nameLength
			)
			virtualSize = Read-UInt32LE $Bytes ($entry + 8) `
				"section $index virtual size"
			virtualAddress = Read-UInt32LE $Bytes ($entry + 12) `
				"section $index virtual address"
			rawSize = Read-UInt32LE $Bytes ($entry + 16) `
				"section $index raw size"
			rawPointer = Read-UInt32LE $Bytes ($entry + 20) `
				"section $index raw pointer"
		}
	}

	function Get-Directory([int]$Index) {
		if ($Index -ge $directories.Count) {
			return [pscustomobject]@{ index = $Index; rva = 0; size = 0 }
		}
		return $directories[$Index]
	}

	$imports = Read-ImportNames $Bytes (Get-Directory 1) `
		$sizeOfHeaders $sections
	$delayImports = Read-DelayImportNames $Bytes (Get-Directory 13) `
		$sizeOfHeaders $sections $imageBase

	$loadConfigDirectory = Get-Directory 10
	$loadConfigSize = [uint32]0
	$chpeMetadataPointer = [uint64]0
	if ($loadConfigDirectory.rva -ne 0 -or
	    $loadConfigDirectory.size -ne 0) {
		if ($loadConfigDirectory.rva -eq 0 -or
		    $loadConfigDirectory.size -lt 4) {
			throw [IO.InvalidDataException]::new(
				'The load-config directory is partially specified'
			)
		}
		$loadConfigOffset = Convert-RvaToFileOffset `
			$loadConfigDirectory.rva $sizeOfHeaders $sections `
			$Bytes.LongLength 'load-config directory'
		$loadConfigSize = Read-UInt32LE $Bytes $loadConfigOffset `
			'load-config structure size'
		if ($loadConfigSize -gt $loadConfigDirectory.size) {
			throw [IO.InvalidDataException]::new(
				'The load-config structure exceeds its data directory'
			)
		}
		if ($magic -eq $script:Pe32PlusMagic -and
		    $loadConfigSize -ge 208) {
			$chpeMetadataPointer = Read-UInt64LE $Bytes `
				($loadConfigOffset + 200) 'CHPE metadata pointer'
		}
	}

	return [pscustomobject][ordered]@{
		source = $Source
		length = $Bytes.LongLength
		machine = $machine
		machineHex = '0x{0:X4}' -f $machine
		optionalMagic = $magic
		optionalMagicHex = '0x{0:X4}' -f $magic
		characteristics = $characteristics
		subsystem = $subsystem
		imageBase = $imageBase
		numberOfSections = $numberOfSections
		sizeOfHeaders = $sizeOfHeaders
		imports = @($imports | Sort-Object -Unique)
		delayImports = @($delayImports | Sort-Object -Unique)
		loadConfig = [pscustomobject][ordered]@{
			directoryRva = $loadConfigDirectory.rva
			directorySize = $loadConfigDirectory.size
			structureSize = $loadConfigSize
			chpeMetadataPointer = $chpeMetadataPointer
			chpeMetadataPointerHex = '0x{0:X16}' -f `
				$chpeMetadataPointer
		}
		sections = @($sections)
	}
}

function Get-PeImageInfo {
	[CmdletBinding()]
	param([Parameter(Mandatory)][string]$Path)

	$resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
	$bytes = [IO.File]::ReadAllBytes($resolved)
	return Get-PeImageInfoFromBytes -Bytes $bytes -Source $resolved
}

function Get-Arm64PePolicyFailures {
	[CmdletBinding()]
	param([Parameter(Mandatory)][object]$Pe)

	$failures = [Collections.Generic.List[string]]::new()
	if ([uint16]$Pe.machine -ne $script:ImageFileMachineArm64) {
		$failures.Add(
			"machine is $($Pe.machineHex), expected 0xAA64"
		)
	}
	if ([uint16]$Pe.optionalMagic -ne $script:Pe32PlusMagic) {
		$failures.Add(
			"optional-header magic is $($Pe.optionalMagicHex), expected 0x020B"
		)
	}
	if ([uint16]$Pe.subsystem -ne 3) {
		$failures.Add(
			"subsystem is $($Pe.subsystem), expected 3 (console)"
		)
	}
	if (([uint16]$Pe.characteristics -band 0x0002) -eq 0) {
		$failures.Add('COFF executable-image characteristic is absent')
	}
	if (([uint16]$Pe.characteristics -band 0x2000) -ne 0) {
		$failures.Add('COFF DLL characteristic is present')
	}
	if (@($Pe.imports).Count + @($Pe.delayImports).Count -eq 0) {
		$failures.Add(
			'dynamic-link policy requires at least one import'
		)
	}
	if ([uint64]$Pe.loadConfig.chpeMetadataPointer -ne 0) {
		$failures.Add(
			'CHPE metadata is present; a pure ARM64 image is required'
		)
	}
	return @($failures)
}

function Get-Mingw64aConfigPolicyFailures {
	[CmdletBinding()]
	param([Parameter(Mandatory)][string]$Text)

	$requiredLines = @(
		'CONFIG_PLATFORM_MINGW32=y',
		'# CONFIG_STATIC is not set',
		'# CONFIG_PIE is not set',
		'CONFIG_CROSS_COMPILER_PREFIX="aarch64-w64-mingw32-"',
		'CONFIG_HOST_COMPILER="clang"',
		'CONFIG_CROSS_COMPILER="clang"',
		'# CONFIG_STATIC_LIBGCC is not set'
	)
	$failures = [Collections.Generic.List[string]]::new()
	foreach ($line in $requiredLines) {
		$count = [regex]::Matches(
			$Text,
			'(?m)^' + [regex]::Escape($line) + '\r?$'
		).Count
		if ($count -ne 1) {
			$failures.Add(
				"configuration line '$line' occurs $count times"
			)
		}
	}

	foreach ($forbidden in @(
		'CONFIG_STATIC=y',
		'CONFIG_STATIC_LIBGCC=y'
	)) {
		if ([regex]::IsMatch(
			$Text,
			'(?m)^' + [regex]::Escape($forbidden) + '\r?$'
		)) {
			$failures.Add(
				"dynamic-link policy forbids '$forbidden'"
			)
		}
	}
	return @($failures)
}

function Get-ConfigEquivalenceFailures {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][string]$ExpectedText,
		[Parameter(Mandatory)][string]$ObservedText
	)

	function Get-Settings([string]$Text, [string]$Scope) {
		$settings = [ordered]@{}
		foreach ($line in @($Text -split '\r?\n')) {
			if ($line -eq '' -or $line -match '^#(?! CONFIG_)') {
				continue
			}
			$match = [regex]::Match(
				$line,
				'^(?:# )?(CONFIG_[A-Za-z0-9_]+)(?:=.*| is not set)$'
			)
			if (-not $match.Success) {
				throw [IO.InvalidDataException]::new(
					"$Scope contains a noncanonical line: '$line'"
				)
			}
			$key = $match.Groups[1].Value
			if ($settings.Contains($key)) {
				throw [IO.InvalidDataException]::new(
					"$Scope contains duplicate setting '$key'"
				)
			}
			$settings[$key] = $line
		}
		if ($settings.Count -eq 0) {
			throw [IO.InvalidDataException]::new(
				"$Scope contains no configuration settings"
			)
		}
		return $settings
	}

	$expected = Get-Settings $ExpectedText 'expected configuration'
	$observed = Get-Settings $ObservedText 'observed configuration'
	$failures = [Collections.Generic.List[string]]::new()

	foreach ($key in $expected.Keys) {
		if (-not $observed.Contains($key)) {
			$failures.Add("observed configuration is missing '$key'")
		} elseif ([string]$expected[$key] -cne
		          [string]$observed[$key]) {
			$failures.Add(
				"configuration setting '$key' differs"
			)
		}
	}
	foreach ($key in $observed.Keys) {
		if (-not $expected.Contains($key)) {
			$failures.Add(
				"observed configuration adds '$key'"
			)
		}
	}
	return @($failures)
}

function Get-UnameSourcePolicyFailures {
	[CmdletBinding()]
	param([Parameter(Mandatory)][string]$Text)

	$failures = [Collections.Generic.List[string]]::new()
	$mappings = [ordered]@{
		PROCESSOR_ARCHITECTURE_AMD64 = 'x86_64'
		PROCESSOR_ARCHITECTURE_INTEL = 'i686'
		PROCESSOR_ARCHITECTURE_ARM = 'armv7'
		PROCESSOR_ARCHITECTURE_ARM64 = 'aarch64'
	}
	foreach ($entry in $mappings.GetEnumerator()) {
		$pattern = '(?s)case\s+' +
			[regex]::Escape($entry.Key) +
			'\s*:\s*strcpy\s*\(\s*name->machine\s*,\s*"' +
			[regex]::Escape($entry.Value) +
			'"\s*\)\s*;'
		$count = [regex]::Matches($Text, $pattern).Count
		if ($count -ne 1) {
			$failures.Add(
				"uname mapping $($entry.Key) -> $($entry.Value) occurs $count times"
			)
		}
	}
	return @($failures)
}

function Get-NativeEnvironmentPolicyFailures {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][string]$OsArchitecture,
		[Parameter(Mandatory)][string]$ProcessArchitecture,
		[AllowEmptyString()][string]$ProcessorArchitecture,
		[AllowNull()][AllowEmptyString()][string]$ProcessorArchitew6432
	)

	$failures = [Collections.Generic.List[string]]::new()
	if ($OsArchitecture -ne 'Arm64') {
		$failures.Add(
			"OS architecture is '$OsArchitecture', expected 'Arm64'"
		)
	}
	if ($ProcessArchitecture -ne 'Arm64') {
		$failures.Add(
			"diagnostic process architecture is '$ProcessArchitecture', expected 'Arm64'"
		)
	}
	if ($ProcessorArchitecture -ne 'ARM64') {
		$failures.Add(
			"PROCESSOR_ARCHITECTURE is '$ProcessorArchitecture', expected 'ARM64'"
		)
	}
	if (-not [string]::IsNullOrEmpty($ProcessorArchitew6432)) {
		$failures.Add(
			"PROCESSOR_ARCHITEW6432 is '$ProcessorArchitew6432', expected absent"
		)
	}
	return @($failures)
}

function Assert-ClosedKeys {
	param(
		[Parameter(Mandatory)][object]$Object,
		[Parameter(Mandatory)][string[]]$Expected,
		[Parameter(Mandatory)][string]$Scope
	)

	$actual = @($Object.PSObject.Properties.Name | Sort-Object)
	$wanted = @($Expected | Sort-Object)
	if (($actual -join "`n") -cne ($wanted -join "`n")) {
		throw [IO.InvalidDataException]::new(
			"$Scope keys are [$($actual -join ', ')], expected [$($wanted -join ', ')]"
		)
	}
}

function Read-ModulePolicy {
	[CmdletBinding()]
	param([Parameter(Mandatory)][string]$Path)

	$resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
	$policy = Get-Content -LiteralPath $resolved -Raw -Encoding UTF8 |
		ConvertFrom-Json -Depth 20
	Assert-ClosedKeys $policy @(
		'authority',
		'delayImports',
		'imports',
		'modules',
		'schemaVersion',
		'subject'
	) 'module policy'
	if ($policy.schemaVersion -ne 1) {
		throw [IO.InvalidDataException]::new(
			"Unsupported module policy schema $($policy.schemaVersion)"
		)
	}
	if ($policy.authority -ne 'external-independent-review') {
		throw [IO.InvalidDataException]::new(
			'Module policy authority must be external-independent-review'
		)
	}
	Assert-ClosedKeys $policy.subject @(
		'canonicalPath',
		'fileId',
		'sha256',
		'volumeSerial'
	) 'module policy subject'

	foreach ($module in @($policy.modules)) {
		Assert-ClosedKeys $module @(
			'canonicalPath',
			'fileId',
			'peMachine',
			'sha256',
			'volumeSerial'
		) 'module policy entry'
	}

	foreach ($scope in @('imports', 'delayImports')) {
		$values = @($policy.$scope)
		$unique = @($values | Sort-Object -Unique)
		if ($values.Count -ne $unique.Count) {
			throw [IO.InvalidDataException]::new(
				"Module policy $scope contains duplicate entries"
			)
		}
	}
	$paths = @($policy.modules | ForEach-Object {
		$_.canonicalPath.ToLowerInvariant()
	})
	if ($paths.Count -ne @($paths | Sort-Object -Unique).Count) {
		throw [IO.InvalidDataException]::new(
			'Module policy contains duplicate canonical paths'
		)
	}

	return $policy
}

function Get-FileIdentity {
	[CmdletBinding()]
	param([Parameter(Mandatory)][string]$Path)

	$resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
	$item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
	if ($item.PSIsContainer) {
		throw [IO.InvalidDataException]::new(
			"$resolved is not a regular file"
		)
	}
	$inputPath = [IO.Path]::GetFullPath($item.FullName)
	$root = [IO.Path]::GetPathRoot($inputPath).TrimEnd('\')
	if ($root -notmatch '^[A-Za-z]:$') {
		throw [PlatformNotSupportedException]::new(
			"Cannot obtain a volume serial for '$inputPath'"
		)
	}

	$escapedRoot = $root.Replace("'", "''")
	$disk = Get-CimInstance Win32_LogicalDisk `
		-Filter "DeviceID='$escapedRoot'" -ErrorAction Stop
	if ($null -eq $disk -or
	    [string]::IsNullOrWhiteSpace($disk.VolumeSerialNumber)) {
		throw [IO.IOException]::new(
			"Volume serial is unavailable for '$inputPath'"
		)
	}

	$fsutil = Join-Path $env:SystemRoot 'System32\fsutil.exe'
	if (-not (Test-Path -LiteralPath $fsutil -PathType Leaf)) {
		throw [IO.FileNotFoundException]::new(
			'fsutil.exe is required for file-index evidence'
		)
	}
	$output = @(& $fsutil file queryfileid $inputPath 2>&1)
	if ($LASTEXITCODE -ne 0) {
		throw [IO.IOException]::new(
			"fsutil queryfileid failed for '$inputPath': $($output -join ' ')"
		)
	}
	$match = [regex]::Match(
		($output -join "`n"),
		'(?i)\b0x([0-9a-f]{16}|[0-9a-f]{32})\b'
	)
	if (-not $match.Success) {
		throw [IO.InvalidDataException]::new(
			"fsutil returned no file ID for '$inputPath'"
		)
	}

	$linkOutput = @(& $fsutil hardlink list $inputPath 2>&1)
	if ($LASTEXITCODE -ne 0) {
		throw [IO.IOException]::new(
			"fsutil hardlink list failed for '$inputPath': $($linkOutput -join ' ')"
		)
	}
	$linkPaths = @($linkOutput | ForEach-Object {
		$line = ([string]$_).Trim()
		if ($line -match '^\\(?!\\)') {
			$root + $line
		}
	} | Sort-Object -Unique)
	if ($linkPaths.Count -eq 0) {
		throw [IO.InvalidDataException]::new(
			"fsutil returned no canonical hardlink path for '$inputPath'"
		)
	}
	$canonicalPath = $linkPaths[0]

	return [pscustomobject][ordered]@{
		canonicalPath = $canonicalPath
		volumeSerial = $disk.VolumeSerialNumber.ToUpperInvariant()
		fileId = $match.Groups[1].Value.ToUpperInvariant()
		sha256 = (Get-FileHash -LiteralPath $inputPath `
			-Algorithm SHA256).Hash.ToLowerInvariant()
		length = [long]$item.Length
	}
}

function Get-ProcessModuleSnapshot {
	[CmdletBinding()]
	param([Parameter(Mandatory)][Diagnostics.Process]$Process)

	$Process.Refresh()
	if ($Process.HasExited) {
		throw [InvalidOperationException]::new(
			'The process exited before module enumeration'
		)
	}

	$modules = @()
	foreach ($module in @($Process.Modules)) {
		$identity = Get-FileIdentity -Path $module.FileName
		$pe = Get-PeImageInfo -Path $identity.canonicalPath
		$modules += [pscustomobject][ordered]@{
			canonicalPath = $identity.canonicalPath
			volumeSerial = $identity.volumeSerial
			fileId = $identity.fileId
			sha256 = $identity.sha256
			peMachine = $pe.machineHex
		}
	}
	if ($modules.Count -eq 0) {
		throw [InvalidOperationException]::new(
			'The OS returned an empty process-module list'
		)
	}
	$paths = @($modules | ForEach-Object {
		$_.canonicalPath.ToLowerInvariant()
	})
	if ($paths.Count -ne @($paths | Sort-Object -Unique).Count) {
		throw [IO.InvalidDataException]::new(
			'The OS returned duplicate canonical module paths'
		)
	}
	return @($modules | Sort-Object canonicalPath)
}

function Compare-ModulePolicy {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][object]$Policy,
		[Parameter(Mandatory)][object]$SubjectIdentity,
		[Parameter(Mandatory)][object]$Pe,
		[Parameter(Mandatory)][object[]]$Modules
	)

	$failures = [Collections.Generic.List[string]]::new()
	foreach ($property in @(
		'canonicalPath',
		'volumeSerial',
		'fileId',
		'sha256'
	)) {
		$differs = if ($property -eq 'canonicalPath') {
			[string]$Policy.subject.$property -ine
				[string]$SubjectIdentity.$property
		} else {
			[string]$Policy.subject.$property -cne
				[string]$SubjectIdentity.$property
		}
		if ($differs) {
			$failures.Add(
				"subject $property differs from external policy"
			)
		}
	}

	foreach ($scope in @('imports', 'delayImports')) {
		$expected = @($Policy.$scope | Sort-Object)
		$observed = @($Pe.$scope | Sort-Object)
		if (($expected -join "`n").ToLowerInvariant() -cne
		    ($observed -join "`n").ToLowerInvariant()) {
			$failures.Add("$scope differ from external policy")
		}
	}

	$expectedModules = @($Policy.modules | Sort-Object canonicalPath)
	$observedModules = @($Modules | Sort-Object canonicalPath)
	if ($expectedModules.Count -ne $observedModules.Count) {
		$failures.Add(
			"module count is $($observedModules.Count), expected $($expectedModules.Count)"
		)
	}
	foreach ($expected in $expectedModules) {
		$matches = @($observedModules | Where-Object {
			$_.canonicalPath -ieq $expected.canonicalPath
		})
		if ($matches.Count -ne 1) {
			$failures.Add(
				"module '$($expected.canonicalPath)' occurs $($matches.Count) times"
			)
			continue
		}
		$observed = $matches[0]
		foreach ($property in @(
			'volumeSerial',
			'fileId',
			'sha256',
			'peMachine'
		)) {
			if ([string]$expected.$property -cne
			    [string]$observed.$property) {
				$failures.Add(
					"module '$($expected.canonicalPath)' $property differs"
				)
			}
		}
	}
	return @($failures)
}

function Invoke-CapturedProcess {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][string]$FilePath,
		[string[]]$ArgumentList = @(),
		[string]$WorkingDirectory,
		[hashtable]$Environment = @{},
		[int]$TimeoutSeconds = 3600
	)

	$info = [Diagnostics.ProcessStartInfo]::new()
	$info.FileName = $FilePath
	$info.UseShellExecute = $false
	$info.CreateNoWindow = $true
	$info.RedirectStandardOutput = $true
	$info.RedirectStandardError = $true
	if (-not [string]::IsNullOrEmpty($WorkingDirectory)) {
		$info.WorkingDirectory = $WorkingDirectory
	}
	foreach ($argument in $ArgumentList) {
		[void]$info.ArgumentList.Add($argument)
	}
	foreach ($entry in $Environment.GetEnumerator()) {
		$info.Environment[$entry.Key] = [string]$entry.Value
	}

	$process = [Diagnostics.Process]::new()
	$process.StartInfo = $info
	if (-not $process.Start()) {
		throw [InvalidOperationException]::new(
			"Failed to start '$FilePath'"
		)
	}
	$stdoutTask = $process.StandardOutput.ReadToEndAsync()
	$stderrTask = $process.StandardError.ReadToEndAsync()
	if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
		$process.Kill($true)
		$process.WaitForExit()
		throw [TimeoutException]::new(
			"'$FilePath' exceeded $TimeoutSeconds seconds"
		)
	}
	$stdout = $stdoutTask.GetAwaiter().GetResult()
	$stderr = $stderrTask.GetAwaiter().GetResult()
	$exitCode = $process.ExitCode
	$process.Dispose()

	return [pscustomobject][ordered]@{
		exitCode = $exitCode
		stdout = $stdout
		stderr = $stderr
	}
}

function Get-TestResultAccounting {
	[CmdletBinding()]
	param([AllowEmptyString()][string]$Output)

	$lines = @($Output -split '\r?\n' | Where-Object { $_ -ne '' })
	$counts = [ordered]@{
		pass = 0
		fail = 0
		skipped = 0
		untested = 0
		notBuiltSkipped = 0
		resultLines = 0
		totalLines = $lines.Count
	}
	foreach ($line in $lines) {
		switch -Regex ($line) {
			'^PASS: ' { $counts.pass++; $counts.resultLines++; break }
			'^FAIL: ' { $counts.fail++; $counts.resultLines++; break }
			'^SKIPPED: ' {
				$counts.skipped++
				if ($line -match '\(not built\)$') {
					$counts.notBuiltSkipped++
				}
				$counts.resultLines++
				break
			}
			'^UNTESTED: ' {
				$counts.untested++
				$counts.resultLines++
				break
			}
		}
	}
	return [pscustomobject]$counts
}

function Get-TextSha256 {
	[CmdletBinding()]
	param([AllowEmptyString()][string]$Text)

	$bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
	$algorithm = [Security.Cryptography.SHA256]::Create()
	try {
		$hash = $algorithm.ComputeHash($bytes)
		return ($hash | ForEach-Object {
			$_.ToString('x2')
		}) -join ''
	} finally {
		$algorithm.Dispose()
	}
}

Export-ModuleMember -Function @(
	'Assert-ClosedKeys',
	'Compare-ModulePolicy',
	'Get-Arm64PePolicyFailures',
	'Get-ConfigEquivalenceFailures',
	'Get-FileIdentity',
	'Get-Mingw64aConfigPolicyFailures',
	'Get-NativeEnvironmentPolicyFailures',
	'Get-PeImageInfo',
	'Get-PeImageInfoFromBytes',
	'Get-ProcessModuleSnapshot',
	'Get-TestResultAccounting',
	'Get-TextSha256',
	'Get-UnameSourcePolicyFailures',
	'Invoke-CapturedProcess',
	'Read-ModulePolicy'
)
