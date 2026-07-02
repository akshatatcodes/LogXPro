# PowerShell Script to install Sysmon and Winlogbeat on Windows
# RUN AS ADMINISTRATOR

$ErrorActionPreference = "Stop"

# Check Admin Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator! Please reopen PowerShell as Administrator."
}

# Create temp download directory
$tempDir = "C:\temp_logxpro_install"
if (-not (Test-Path $tempDir)) {
    New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
}

Write-Host "=========================================" -ForegroundColor Green
Write-Host "  Installing Sysmon (System Monitor)     " -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green

# 1. Download & Install Sysmon
$sysmonZip = "$tempDir\Sysmon.zip"
$sysmonExe = "$tempDir\Sysmon64.exe"
$sysmonConfig = "$tempDir\sysmonconfig.xml"

Write-Host "[*] Downloading SwiftOnSecurity Sysmon Config..."
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile $sysmonConfig

Write-Host "[*] Downloading Sysmon from Microsoft..."
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $sysmonZip

Write-Host "[*] Extracting Sysmon..."
Expand-Archive -Path $sysmonZip -DestinationPath $tempDir -Force

if (Test-Path $sysmonExe) {
    Write-Host "[*] Installing Sysmon service with SwiftOnSecurity configuration..."
    Start-Process -FilePath $sysmonExe -ArgumentList "-accepteula -i $sysmonConfig" -Wait -NoNewWindow
    Write-Host "[+] Sysmon installed successfully." -ForegroundColor Green
} else {
    Write-Warning "[!] Could not find Sysmon64.exe in extraction path."
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Green
Write-Host "  Installing Winlogbeat (Log Shipper)   " -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green

# 2. Download & Install Winlogbeat
$winlogbeatVersion = "8.13.0"
$winlogbeatZip = "$tempDir\winlogbeat-$winlogbeatVersion.zip"
$installDir = "C:\Program Files\Winlogbeat"

Write-Host "[*] Downloading Winlogbeat v$winlogbeatVersion..."
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-$winlogbeatVersion-windows-x86_64.zip" -OutFile $winlogbeatZip

Write-Host "[*] Extracting Winlogbeat..."
Expand-Archive -Path $winlogbeatZip -DestinationPath $tempDir -Force

$extractedDir = "$tempDir\winlogbeat-$winlogbeatVersion-windows-x86_64"

if (Test-Path $extractedDir) {
    if (-not (Test-Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir | Out-Null
    }
    
    Write-Host "[*] Copying files to $installDir..."
    Copy-Item -Path "$extractedDir\*" -Destination $installDir -Recurse -Force
    
    # Copy our winlogbeat.yml configuration file
    $localConfig = Join-Path $PSScriptRoot "winlogbeat.yml"
    if (Test-Path $localConfig) {
        Write-Host "[*] Copying local winlogbeat.yml configuration..."
        Copy-Item -Path $localConfig -Destination "$installDir\winlogbeat.yml" -Force
    } else {
        Write-Warning "[!] Local winlogbeat.yml not found. Please place it manually in $installDir."
    }

    # Register service
    Write-Host "[*] Registering Winlogbeat Windows Service..."
    Set-Location $installDir
    Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File .\install-service-winlogbeat.ps1" -Wait -NoNewWindow
    
    Write-Host "[+] Winlogbeat registered as a service." -ForegroundColor Green
    Write-Host "[*] Starting Winlogbeat service..."
    Start-Service -Name "winlogbeat"
    Write-Host "[+] Winlogbeat service started successfully!" -ForegroundColor Green
} else {
    Write-Error "Failed to locate extracted Winlogbeat files."
}

# Cleanup
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "=========================================" -ForegroundColor Green
Write-Host "  Setup Completed Successfully!          " -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
