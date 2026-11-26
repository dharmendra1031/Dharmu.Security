param([Parameter(Mandatory)][string]$Project)
$ErrorActionPreference = 'Stop'

# Installs IIS prerequisites and changes test key ACLs only on disposable runners.
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
  throw 'IIS acceptance is restricted to a disposable GitHub-hosted runner.'
}

function Run-Native([string]$Command, [string[]]$Arguments) {
  & $Command @Arguments
  if ($LASTEXITCODE -ne 0) { throw "$Command failed ($LASTEXITCODE)." }
}

$appcmd = Join-Path $env:windir 'System32\inetsrv\appcmd.exe'
if (-not (Test-Path $appcmd)) {
  Run-Native 'powershell.exe' @('-NoProfile', '-Command', '$ErrorActionPreference = "Stop"; Import-Module ServerManager; $r = Install-WindowsFeature Web-Server -IncludeManagementTools; if (-not $r.Success -or $r.RestartNeeded -eq "Yes") { throw "IIS installation failed or requires restart." }')
}
if (-not (Test-Path $appcmd)) { throw 'IIS appcmd is unavailable.' }

# Official .NET release metadata and SHA-512 verification before execution.
$metadata = Invoke-RestMethod 'https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json'
$release = @($metadata.releases | Where-Object { $_.'release-version' -eq $metadata.'latest-release' })
if ($release.Count -ne 1) { throw 'Cannot resolve .NET 10 hosting bundle release.' }
$bundle = @($release[0].'aspnetcore-runtime'.files | Where-Object { $_.name -eq 'dotnet-hosting-win.exe' })
if ($bundle.Count -ne 1 -or -not $bundle[0].hash) { throw 'Hosting bundle metadata is incomplete.' }
$installer = Join-Path $env:RUNNER_TEMP 'dotnet-hosting-win.exe'
Invoke-WebRequest $bundle[0].url -OutFile $installer
if ((Get-FileHash $installer -Algorithm SHA512).Hash -ne $bundle[0].hash) {
  throw 'Hosting bundle checksum mismatch.'
}
$process = Start-Process $installer -ArgumentList '/install /quiet /norestart' -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "Hosting bundle installation returned $($process.ExitCode)." }
Restart-Service W3SVC -Force

$site = 'DharmuIisAcceptance-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$root = Join-Path "$env:SystemDrive\inetpub" $site
$publish = Join-Path $root 'site'
$data = Join-Path $root 'data'
$state = Join-Path $data 'state'
$ledger = Join-Path $env:RUNNER_TEMP ($site + '-ledger')
$requestFile = Join-Path $env:RUNNER_TEMP ($site + '-activation.json')
$keySlot = 'iis-' + [Guid]::NewGuid().ToString('N')
$baseUrl = 'http://127.0.0.1:18764'
$poolCreated = $false
$siteCreated = $false

function Expect-Status([string]$Path, [int]$Expected) {
  $response = Invoke-WebRequest ($baseUrl + $Path) -SkipHttpErrorCheck -TimeoutSec 15
  if ([int]$response.StatusCode -ne $Expected) {
    throw "$Path expected $Expected, got $($response.StatusCode)."
  }
  Write-Host "IIS_ACCEPTANCE $Path $Expected"
  return $response
}

function Wait-Health([int]$PreviousPid = 0) {
  for ($attempt = 0; $attempt -lt 30; $attempt++) {
    try {
      $response = Invoke-WebRequest ($baseUrl + '/health') -SkipHttpErrorCheck -TimeoutSec 5
      if ($response.StatusCode -eq 200) {
        $health = $response.Content | ConvertFrom-Json
        if ($health.identity -ne "IIS APPPOOL\$site" -or $health.administrator) {
          throw "Unexpected worker identity: $($health.identity)"
        }
        if ($health.pid -ne $PreviousPid) { return $health }
      }
    } catch {
      if ($_.Exception.Message -like 'Unexpected worker identity:*') { throw }
      if ($attempt -eq 29) { throw }
    }
    Start-Sleep -Seconds 1
  }
  throw 'IIS worker did not become healthy with the expected identity and PID.'
}

try {
  New-Item -ItemType Directory -Path $publish,$state,$ledger -Force | Out-Null
  Run-Native 'dotnet' @($env:DHARMU_SMOKE_DEVICE_TOOL)
  Run-Native 'dotnet' @($env:DHARMU_SMOKE_LICENSE_TOOL, '--key-slot', $keySlot, 'init', (Join-Path $data 'issuer.pem'))
  Run-Native 'dotnet' @('publish', $Project, '--configuration', 'Release', '--no-build', '--no-restore', '--output', $publish)
  if (-not (Test-Path (Join-Path $publish 'web.config'))) { throw 'IIS publish did not create web.config.' }

  Run-Native $appcmd @('add', 'apppool', "/name:$site", '/processModel.identityType:ApplicationPoolIdentity')
  $poolCreated = $true
  Run-Native $appcmd @('set', 'apppool', $site, '/managedRuntimeVersion:', '/processModel.maxProcesses:1')
  $sid = ([System.Security.Principal.NTAccount]::new("IIS APPPOOL\$site")).Translate([System.Security.Principal.SecurityIdentifier]).Value
  # The pool may read site and license; only the state directory is writable.
  Run-Native 'icacls.exe' @($root, '/grant', ('*' + $sid + ':(OI)(CI)(RX)'))
  Run-Native 'icacls.exe' @($state, '/grant', ('*' + $sid + ':(OI)(CI)(M)'))
  foreach ($name in @('DharmuSecurityDeviceIdentity', 'DharmuSecuritySecretProtection')) {
    $key = [System.Security.Cryptography.CngKey]::Open(
      $name, [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,
      [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey)
    try {
      $keyFile = Join-Path "$env:ProgramData\Microsoft\Crypto\Keys" $key.UniqueName
      if (-not (Test-Path $keyFile)) { throw "CNG key file missing for $name." }
      Run-Native 'icacls.exe' @($keyFile, '/grant', ('*' + $sid + ':(R)'))
    } finally { $key.Dispose() }
  }

  Run-Native $appcmd @('add', 'site', "/name:$site", '/bindings:http/127.0.0.1:18764:', "/physicalPath:$publish")
  $siteCreated = $true
  Run-Native $appcmd @('set', 'app', "$site/", "/applicationPool:$site")

  $first = Wait-Health
  Write-Host "IIS_ACCEPTANCE identity=$($first.identity) pid=$($first.pid) administrator=false"
  $null = Expect-Status '/protected' 403
  $request = Expect-Status '/license/activation-request' 200
  [IO.File]::WriteAllText($requestFile, [string]$request.Content)
  Run-Native 'dotnet' @($env:DHARMU_SMOKE_LICENSE_TOOL, '--key-slot', $keySlot, 'issue', $ledger, $requestFile, 'IIS_SMOKE', '1', '1', '30')
  $signed = @(Get-ChildItem $ledger -Filter '*.lic' -File)
  if ($signed.Count -ne 1) { throw 'Expected exactly one test license.' }
  $current = Join-Path $data 'license.lic'
  Copy-Item $signed[0].FullName $current
  $original = [IO.File]::ReadAllText($current)
  $null = Expect-Status '/protected' 200
  if (-not (Test-Path (Join-Path $state 'runtime.state'))) { throw 'Runtime state missing.' }

  Run-Native $appcmd @('recycle', 'apppool', $site)
  $second = Wait-Health ([int]$first.pid)
  $null = Expect-Status '/protected' 200
  Run-Native 'dotnet' @($env:DHARMU_SMOKE_LICENSE_TOOL, '--key-slot', $keySlot, 'revoke', $ledger, $signed[0].BaseName)
  Copy-Item $signed[0].FullName $current -Force
  $null = Expect-Status '/protected' 403
  [IO.File]::WriteAllText($current, $original)
  $null = Expect-Status '/protected' 403
  Run-Native $appcmd @('recycle', 'apppool', $site)
  $third = Wait-Health ([int]$second.pid)
  $null = Expect-Status '/protected' 403
  Write-Host "IIS_ACCEPTANCE PASS: non-admin worker, real CNG and DPAPI, activation, recycle, revocation and stale license rejection; pid=$($third.pid)"
}
finally {
  if ($siteCreated) { & $appcmd delete site $site }
  if ($poolCreated) { & $appcmd delete apppool $site }
}
