#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build and pack all projects from src folder into NuGet packages
.DESCRIPTION
    Script finds all .csproj files in src folder and runs dotnet pack for each
    in Release configuration with symbols (snupkg)
#>

$ErrorActionPreference = "Stop"

$rootPath = Split-Path -Parent $PSScriptRoot
$srcPath = Join-Path $rootPath "src"
$outputPath = Join-Path $rootPath "nupkgs"

if (-not (Test-Path $srcPath)) {
    Write-Error "Src folder not found at: $srcPath"
    exit 1
}

if (-not (Test-Path $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    Write-Host "Created packages folder: $outputPath" -ForegroundColor Green
}

$projects = Get-ChildItem -Path $srcPath -Recurse -Filter "*.csproj" -File

if ($projects.Count -eq 0) {
    Write-Warning "No projects (.csproj) found in src folder"
    exit 0
}

Write-Host "Found projects: $($projects.Count)" -ForegroundColor Cyan
Write-Host ""

$successCount = 0
$failCount = 0

foreach ($project in $projects) {
    $projectName = $project.Name
    $projectPath = $project.FullName
    
    Write-Host "[$projectName]" -ForegroundColor Yellow
    Write-Host "  Path: $projectPath"
    Write-Host "  Packing..." -NoNewline
    
    try {
        & dotnet pack $projectPath `
            -c Release `
            --include-symbols `
            -p:SymbolPackageFormat=snupkg `
            -o $outputPath `
            --nologo
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host " Done!" -ForegroundColor Green
            $successCount++
        } else {
            Write-Host " Failed!" -ForegroundColor Red
            $failCount++
        }
    }
    catch {
        Write-Host " Error: $_" -ForegroundColor Red
        $failCount++
    }
    
    Write-Host ""
}

Write-Host "========================" -ForegroundColor Cyan
Write-Host "Packing completed!" -ForegroundColor Cyan
Write-Host "Successful: $successCount" -ForegroundColor Green
if ($failCount -gt 0) {
    Write-Host "Failed: $failCount" -ForegroundColor Red
}
Write-Host "Packages saved to: $outputPath" -ForegroundColor Cyan

if ($failCount -gt 0) {
    exit 1
}