$ErrorActionPreference = 'Stop'
$projectDir = Join-Path $env:RUNNER_TEMP 'DharmuPackageSmoke'
New-Item -ItemType Directory -Path $projectDir -Force | Out-Null
$projectXml = @'
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net10.0-windows</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Dharmu.Security.AspNetCore" Version="PACKAGE_VERSION" />
  </ItemGroup>
</Project>
'@
$version = ([xml](Get-Content -Raw 'src/Dharmu.Security.AspNetCore/Dharmu.Security.AspNetCore.csproj')).Project.PropertyGroup.Version
$projectXml.Replace('PACKAGE_VERSION', $version) | Set-Content (Join-Path $projectDir 'DharmuPackageSmoke.csproj')
Copy-Item 'tests/PackageSmoke/Program.cs' (Join-Path $projectDir 'Program.cs')

$project = Join-Path $projectDir 'DharmuPackageSmoke.csproj'
$packages = Join-Path $PWD 'artifacts'
$config = Join-Path $projectDir 'NuGet.Config'
@"
<configuration>
  <packageSources>
    <clear />
    <add key="packages" value="$packages" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
  <packageSourceMapping>
    <packageSource key="packages">
      <package pattern="Dharmu.Security.*" />
    </packageSource>
    <packageSource key="nuget.org">
      <package pattern="*" />
    </packageSource>
  </packageSourceMapping>
</configuration>
"@ | Set-Content $config

$env:NUGET_PACKAGES = Join-Path $projectDir 'packages'
dotnet restore $project --configfile $config
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
dotnet build $project --configuration Release --no-restore
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$env:DHARMU_SMOKE_DEVICE_TOOL = (Resolve-Path 'src/Dharmu.Security.DeviceTool/bin/Release/net10.0-windows/Dharmu.Security.DeviceTool.dll').Path
if (-not $env:DHARMU_SMOKE_COPY_INPUT) {
  $env:DHARMU_SMOKE_LICENSE_TOOL = (Resolve-Path 'src/Dharmu.Security.LicenseTool/bin/Release/net10.0-windows/Dharmu.Security.LicenseTool.dll').Path
}
dotnet run --project $project --configuration Release --no-build --no-restore
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
