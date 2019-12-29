param(
    [Parameter(Mandatory = $true, HelpMessage = "Enter the environment (dev|qat|stg|prod)")]
    [ValidateSet('dev', 'qat', 'stg', 'prod')]
    [String]$Environment,

    [Parameter(Mandatory = $true, HelpMessage = "Enter the version")]
    [String]$Version,

    [Parameter(Mandatory = $true, HelpMessage = "Enter the Regions")]
    [String[]] $Regions,

    [Parameter(Mandatory = $true, HelpMessage = "Enter the Username")]
    [String] $Username,

    [Parameter(Mandatory = $true, HelpMessage = "Enter the Password")]
    [SecureString] $Password
)

#=====================
#Function declarations
#=====================

function Send-File
{
	<#
	.SYNOPSIS
		This function sends a file (or folder of files recursively) to a destination WinRm session. This function was originally
		built by Lee Holmes (http://poshcode.org/2216) but has been modified to recursively send folders of files as well
		as to support UNC paths.
	.PARAMETER Path
		The local or UNC folder path that you'd like to copy to the session. This also support multiple paths in a comma-delimited format.
		If this is a UNC path, it will be copied locally to accomodate copying.  If it's a folder, it will recursively copy
		all files and folders to the destination.
	.PARAMETER Destination
		The local path on the remote computer where you'd like to copy the folder or file.  If the folder does not exist on the remote
		computer it will be created.
	.PARAMETER Session
		The remote session. Create with New-PSSession.
	.EXAMPLE
		$session = New-PSSession -ComputerName MYSERVER
		Send-File -Path C:\test.txt -Destination C:\ -Session $session
		This example will copy the file C:\test.txt to be C:\test.txt on the computer MYSERVER
	.INPUTS
		None. This function does not accept pipeline input.
	.OUTPUTS
		System.IO.FileInfo
	#>
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string[]]$Path,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Destination,

		[Parameter(Mandatory)]
		[System.Management.Automation.Runspaces.PSSession]$Session
	)
	process
	{
		foreach ($p in $Path)
		{
			try
			{
				if ($p.StartsWith('\\'))
				{
					Write-Verbose -Message "[$($p)] is a UNC path. Copying locally first"
					Copy-Item -Path $p -Destination ([environment]::GetEnvironmentVariable('TEMP', 'Machine'))
					$p = "$([environment]::GetEnvironmentVariable('TEMP', 'Machine'))\$($p | Split-Path -Leaf)"
				}
				if (Test-Path -Path $p -PathType Container)
				{
					Write-Log -Source $MyInvocation.MyCommand -Message "[$($p)] is a folder. Sending all files"
					$files = Get-ChildItem -Path $p -File -Recurse
					$sendFileParamColl = @()
					foreach ($file in $Files)
					{
						$sendParams = @{
							'Session' = $Session
							'Path' = $file.FullName
						}
						if ($file.DirectoryName -ne $p) ## It's a subdirectory
						{
							$subdirpath = $file.DirectoryName.Replace("$p\", '')
							$sendParams.Destination = "$Destination\$subDirPath"
						}
						else
						{
							$sendParams.Destination = $Destination
						}
						$sendFileParamColl += $sendParams
					}
					foreach ($paramBlock in $sendFileParamColl)
					{
						Send-File @paramBlock
					}
				}
				else
				{
					Write-Verbose -Message "Starting WinRM copy of [$($p)] to [$($Destination)]"
					# Get the source file, and then get its contents
					$sourceBytes = [System.IO.File]::ReadAllBytes($p);
					$streamChunks = @();

					# Now break it into chunks to stream.
					$streamSize = 1MB;
					for ($position = 0; $position -lt $sourceBytes.Length; $position += $streamSize)
					{
						$remaining = $sourceBytes.Length - $position
						$remaining = [Math]::Min($remaining, $streamSize)

						$nextChunk = New-Object byte[] $remaining
						[Array]::Copy($sourcebytes, $position, $nextChunk, 0, $remaining)
						$streamChunks +=, $nextChunk
					}
					$remoteScript = {
						if (-not (Test-Path -Path $using:Destination -PathType Container))
						{
							$null = New-Item -Path $using:Destination -Type Directory -Force
						}
						$fileDest = "$using:Destination\$($using:p | Split-Path -Leaf)"
						## Create a new array to hold the file content
						$destBytes = New-Object byte[] $using:length
						$position = 0

						## Go through the input, and fill in the new array of file content
						foreach ($chunk in $input)
						{
							[GC]::Collect()
							[Array]::Copy($chunk, 0, $destBytes, $position, $chunk.Length)
							$position += $chunk.Length
						}

						[IO.File]::WriteAllBytes($fileDest, $destBytes)

						Get-Item $fileDest
						[GC]::Collect()
					}

					# Stream the chunks into the remote script.
					$Length = $sourceBytes.Length
					$streamChunks | Invoke-Command -Session $Session -ScriptBlock $remoteScript
					Write-Verbose -Message "WinRM copy of [$($p)] to [$($Destination)] complete"
				}
			}
			catch
			{
				Write-Error $_.Exception.Message
			}
		}
    }
}

function Optimize-ConfigFiles () {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Enter the config file environment extension. Ex: dev")]
        [String] $environment
    )

    process {
        $configFiles = Get-ChildItem *.config.* -Recurse

        $configFiles |
            Where-Object {$_.Extension -ne ".$environment"} |
            Remove-Item

        $configFiles |
            Where-Object {$_.Extension -eq ".$environment"} |
            Rename-Item -NewName appSettings.config

        return Get-ChildItem *.config* -Recurse |
            Select-Object -ExpandProperty FullName
    }
}

function Publish-Release () {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Enter the session")]
        [System.Management.Automation.Runspaces.PSSession] $Session,

        [Parameter(Mandatory = $true, HelpMessage = "Enter the version")]
        [String] $Version,

        [Parameter(Mandatory = $true, HelpMessage = "Enter the Publish Directory")]
        [String] $publishDir
    )
    begin {
        $extractCommand = {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            function Unzip {
                param([string]$zipfile, [string]$outpath)
                [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
            }
            if (Test-Path ([System.IO.Path]::Combine($using:publishDir, $using:Version))) {
                Write-Host "Deleting exising release files..."
                Remove-Item -Recurse (Join-Path $using:publishDir $using:Version)
            }
            Write-Host "Writing new release files..."
            New-Item -ItemType Directory -Path $using:publishDir -Name $using:Version
            Unzip -zipfile (Join-Path $using:publishDir "$using:Version.zip") -outpath (Join-Path $using:PublishDir $using:Version)
        }
    }
    process {
        Write-Host "Creating zip file if necessary..."
        $versionPath = Join-Path (Get-Location) ".\$version"
        $zipPath = "$(Get-Location)\$Version.zip"
        if (-Not(Test-Path $zipPath)) {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [IO.Compression.ZipFile]::CreateFromDirectory($versionPath, $zipPath)
        } else {
            Write-Host "Zip found. Skipping..."
        }

        Write-Host "Publishing on host $($Session.ComputerName)..."
        Send-File -Path $zipPath -Session $Session -Destination $publishDir

        Write-Host "Extracting new release..."
        Invoke-Command -Session $Session -ScriptBlock $extractCommand
    }
}

function Update-Version {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Enter the session")]
        [System.Management.Automation.Runspaces.PSSession] $Session,

        [Parameter(Mandatory = $true, HelpMessage = "Enter the region")]
        [String] $region,

        [Parameter(Mandatory = $true, HelpMessage = "Enter the version")]
        [String] $Version,

        [Parameter(Mandatory = $true, HelpMessage = "Enter the Publish Directory")]
        [String] $publishDir
    )
    begin {
        $updateVersionCommand = {
            Write-Host "Updating IIS vdir for region $using:region..."
            $physicalPath = (Join-Path $using:publishDir $using:Version)
            C:\Windows\system32\inetsrv\APPCMD.exe set vdir "Default Web Site/$using:region/" /physicalPath:"$physicalPath"
            if (-Not($?)) {
                Throw "Could not update IIS"
            }

            Write-Host "Updating web.config for region $using:region..."
            $path = Join-Path $using:PublishDir 'web.config'
            $path2 = "$using:version\SiteSpecific\$using:region\appSettings.config"
            $config = [xml](Get-Content $path)
            $node = $config.configuration.location | Where-Object {$_.path -eq $using:region}
            if ($node -eq $null) {
                write-host "Could not find location $using:region, creating it..."
                $node = $newlocation = $config.createelement('location')
                $newlocation.setattribute('path', $using:region)
                $newlocation.setattribute('allowOverride', 'true')
                $config.configuration.appendchild($newlocation)

                $newappsettings = $config.createelement('appSettings')
                $newappsettings.setattribute('configSource', $path2)
                $newlocation.appendchild($newappsettings)

                $newsitespecific = $config.createelement('siteSpecific')
                $newlocation.appendchild($newsitespecific)

                $newadd = $config.createelement('add')
                $newadd.setattribute('key', 'siteName')
                $newadd.setattribute('value', $using:region)
                $newsitespecific.appendchild($newadd)
            }
            else {
                $node.appsettings.configsource = $path2
            }
            $config.Save($path)
        }
    }
    process {
        Invoke-Command -Session $Session -ScriptBlock $updateVersionCommand
    }
}

#Execute the program
$PSDefaultParameterValues = @{}
$PSDefaultParameterValues += @{'*:ErrorAction' = 'Stop'}

Write-Host "Reading environments.xml..."
$xml = [xml](Get-Content ".\environments.xml")

Write-Host "Getting environment settings..."
$publishDir = ($xml.environments.settings.setting | Where-Object name -eq 'PublishDir').value
$groups = (($xml.environments.environment | Where-Object name -eq $Environment).group | Where-Object {Compare-Object $_.regions.region.name $Regions -PassThru -IncludeEqual -ExcludeDifferent})
if (-not $groups) {
    Write-Host "No groups found for environment $Environment and region(s) $Regions"
    exit 1
}

Write-Host "Optimizing config files..."
Optimize-ConfigFiles $Environment

Write-Host "Renaming directory..."
Rename-Item -Path '.\crmplus' -NewName "$Version"

$excludeRegex = ($xml.environments.settings.setting | Where-Object name -eq 'ExcludeRegex').value
Write-Host "Excluding items that match `"$excludeRegex`" from hash comparison."

Write-Host "Getting release hash..."
$localFolder = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) ".\$Version"))
$localHash = Get-ChildItem $localFolder -Recurse | Where-Object FullName -notmatch $excludeRegex | Get-FileHash | Select-Object @{Label = "Path"; Expression = {$_.Path.Replace($localFolder, "")}}, Hash

Write-Host "Preparing remote commands..."
$existsCommand = { Test-Path (Join-Path $using:publishDir $using:Version) }
$hashCommand = {
    $remoteFolder = [System.IO.Path]::GetFullPath((Join-Path $using:publishDir $using:Version))
    Get-ChildItem $remoteFolder -Recurse | Where-Object FullName -notmatch $using:excludeRegex | Get-FileHash | Select-Object @{Label = "Path"; Expression = {$_.Path.Replace($remoteFolder, "")}}, Hash
}

Write-Host "Creating remote credential..."
$credential = New-Object System.Management.Automation.PSCredential ($Username, $Password)

foreach ($group in $groups) {
    foreach ($remoteHost in $group.hosts.host) {
        Write-Host "Opening session on host $($remoteHost.name)..."
        $psSession = New-PSSession -ComputerName $remoteHost.name -Credential $credential
        try {
            Write-Host "Checking if the version exists on host $($remoteHost.name)..."
            $exists = Invoke-Command -Session $psSession -ScriptBlock $existsCommand
            if ($exists) {
                Write-Host "Version exists. Getting hash..."
                $remoteHash = Invoke-Command -Session $psSession -ScriptBlock $hashCommand

                Write-Host "Comparing hashes..."
                $diff = Compare-Object $localHash $remoteHash -Property Path, Hash
                if ($diff -eq $null) {
                    Write-Host "Hashes match. Skipping publish..."
                }
                else {
                    Write-Host "Hashes don't match. Differences:`n$($diff | Out-String)"
                    Write-Host "Publishing version..."
                    Publish-Release -Session $psSession -Version $Version -publishDir $publishDir
                }
            }
            else {
                Write-Host "Version doesn't exist. Publishing version..."
                Publish-Release -Session $psSession -Version $Version -publishDir $publishDir
            }

            Write-Host "Updating settings for regions..."
            $regions = $group.regions.region.name | Compare-Object $Regions -PassThru -IncludeEqual -ExcludeDifferent
            foreach ($region in $regions) {
                Write-Host "Working on region $region..."
                Update-Version -Session $psSession -Region $region -Version $Version -publishDir $publishDir
            }
        }
        finally {
            Write-Host "Closing session on host $($remoteHost.name)..."
            Remove-PSSession $psSession.Id
        }
    }
}
Write-Host "Done."