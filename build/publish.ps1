#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Publish NuGet packages from nupkgs folder to NuGet.org
.DESCRIPTION
    Script finds all .nupkg files in nupkgs folder and pushes them to specified NuGet source
.PARAMETER ApiKey
    NuGet API key for authentication
.PARAMETER Source
    NuGet source URL (default: https://api.nuget.org/v3/index.json)
.PARAMETER PackagePattern
    Pattern to filter packages (e.g. "Quantropic.Security.*.nupkg")
.PARAMETER WhatIf
    Show what would be pushed without actually pushing
.PARAMETER SkipDuplicate
    Skip packages that already exist on server
.PARAMETER NoConfirm
    Skip confirmation prompt (useful for CI/CD)
.EXAMPLE
    ./publish.ps1 -ApiKey "your-api-key"
.EXAMPLE
    ./publish.ps1 -ApiKey "your-api-key" -PackagePattern "Quantropic.Security.*.nupkg" -WhatIf
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ApiKey,
    
    [Parameter(Mandatory=$false)]
    [string]$Source = "https://api.nuget.org/v3/index.json",
    
    [Parameter(Mandatory=$false)]
    [string]$PackagePattern = "*.nupkg",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipDuplicate,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoConfirm
)

$ErrorActionPreference = "Stop"

$rootPath = Split-Path -Parent $PSScriptRoot
$packagesPath = Join-Path $rootPath "nupkgs"

if (-not (Test-Path $packagesPath)) {
    Write-Error "Packages folder not found at: $packagesPath"
    exit 1
}

$packages = Get-ChildItem -Path $packagesPath -Filter $PackagePattern -File

if ($packages.Count -eq 0) {
    Write-Warning "No packages found matching pattern '$PackagePattern' in: $packagesPath"
    exit 0
}

$packages = $packages | Where-Object { $_.Extension -eq ".nupkg" }

if ($packages.Count -eq 0) {
    Write-Warning "No .nupkg files found (only symbol packages). Please adjust pattern."
    exit 0
}

Write-Host "Found packages: $($packages.Count)" -ForegroundColor Cyan
Write-Host "Source: $Source" -ForegroundColor Cyan
if ($WhatIf) {
    Write-Host "WHAT-IF MODE: No packages will be actually pushed" -ForegroundColor Yellow
}
Write-Host ""

Write-Host "Packages to publish:" -ForegroundColor Cyan
foreach ($package in $packages) {
    $fileInfo = [System.IO.FileInfo]$package.FullName
    $sizeKB = [math]::Round($fileInfo.Length / 1KB, 2)
    Write-Host "  - $($package.Name) ($sizeKB KB)" -ForegroundColor White
}
Write-Host ""

if (-not $WhatIf -and -not $NoConfirm) {
    $confirmation = Read-Host "Do you want to push these packages to NuGet.org? (y/N)"
    if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
        Write-Host "Operation cancelled by user" -ForegroundColor Yellow
        exit 0
    }
    Write-Host ""
}

$successCount = 0
$failCount = 0
$skippedCount = 0

foreach ($package in $packages) {
    $packageName = $package.Name
    $packagePath = $package.FullName
    
    Write-Host "[$packageName]" -ForegroundColor Yellow
    
    if ($WhatIf) {
        Write-Host "  [WHAT-IF] Would push: dotnet nuget push `"$packagePath`" --api-key [HIDDEN] --source $Source" -ForegroundColor Gray
        $successCount++
        continue
    }
    
    Write-Host "  Pushing to $Source..." -NoNewline
    
    try {
        $pushArgs = @(
            'nuget', 'push', $packagePath,
            '--api-key', $ApiKey,
            '--source', $Source
        )
        
        if ($SkipDuplicate) {
            $pushArgs += '--skip-duplicate'
        }
        
        $output = & dotnet $pushArgs 2>&1
        $outputString = $output -join "`n"
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host " Done!" -ForegroundColor Green
            $successCount++
        }
        elseif ($outputString -match "409|Conflict|already exists") {
            Write-Host " Skipped (already exists)" -ForegroundColor Yellow
            $skippedCount++
        }
        else {
            throw $outputString
        }
    }
    catch {
        Write-Host " Error!" -ForegroundColor Red
        Write-Host "  Details: $_" -ForegroundColor Red
        $failCount++
    }
    
    Write-Host ""
}

Write-Host "========================" -ForegroundColor Cyan
if ($WhatIf) {
    Write-Host "WHAT-IF COMPLETED!" -ForegroundColor Yellow
} else {
    Write-Host "PUBLISHING COMPLETED!" -ForegroundColor Cyan
}
Write-Host "Successful: $successCount" -ForegroundColor Green
if ($skippedCount -gt 0) {
    Write-Host "Skipped: $skippedCount (already exist)" -ForegroundColor Yellow
}
if ($failCount -gt 0) {
    Write-Host "Failed: $failCount" -ForegroundColor Red
}

if ($failCount -gt 0) {
    exit 1
}