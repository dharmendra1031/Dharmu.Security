@echo off
setlocal
cd /d "%~dp0"
where dotnet >nul 2>&1
if errorlevel 1 (
  echo .NET 10 SDK is required on the trusted owner workstation.
  pause
  exit /b 1
)
set "OUT=%LOCALAPPDATA%\DharmuSecurity\OwnerTool-%RANDOM%-%RANDOM%"
if exist "%OUT%" (
  echo Output already exists. Run again to select a new output.
  pause
  exit /b 1
)
dotnet publish "src\Dharmu.Security.LicenseTool\Dharmu.Security.LicenseTool.csproj" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o "%OUT%"
if errorlevel 1 (
  echo Publish failed. Do not use the partial output.
  pause
  exit /b 1
)
if not exist "%OUT%\Dharmu.Security.LicenseTool.exe" (
  echo Owner executable missing.
  pause
  exit /b 1
)
echo Owner tool published locally. Do not distribute it to customers.
echo %OUT%
explorer.exe "%OUT%"
pause
