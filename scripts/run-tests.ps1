
$ErrorActionPreference = "Stop"

# ==========================================
# NetSentinel - Automated Test Runner
# ==========================================

# Project paths
$ProjectRoot = Split-Path -Parent $PSScriptRoot

$Suricata = "C:\Program Files\Suricata\suricata.exe"

$Config = Join-Path $ProjectRoot "suricata\windows\suricata.yaml"
$Rules = Join-Path $ProjectRoot "suricata\rules\netsentinel.rules"

$Processed = Join-Path $ProjectRoot "sample-data\external-datasets\CIC-IDS2017\processed"

$LogsDirectory = Join-Path $ProjectRoot "suricata\logs"
$OriginalEveFile = Join-Path $LogsDirectory "eve.json"

$BackendUrl = "http://localhost:5000/api/ingestion/import"

# ==========================================
# Available Tests
# ==========================================

$Tests = @(
    [PSCustomObject]@{
        Name   = "SQL Injection"
        Folder = "sql-injection"
        Pcap   = "attack.pcap"
    }
)

# ==========================================
# Validate Configuration
# ==========================================

function Test-Configuration {

    if (-not (Test-Path -LiteralPath $Suricata -PathType Leaf)) {
        throw "Suricata executable not found: $Suricata"
    }

    if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
        throw "Suricata configuration not found: $Config"
    }

    if (-not (Test-Path -LiteralPath $Rules -PathType Leaf)) {
        throw "NetSentinel rules file not found: $Rules"
    }

    if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot "backend"))) {
        throw "Backend directory not found."
    }
}

# ==========================================
# Execute a Test
# ==========================================

function Invoke-Test {

    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Test
    )

    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "       NetSentinel Automated Testing"
    Write-Host "==========================================" -ForegroundColor Cyan

    Write-Host "Test: $($Test.Name)" -ForegroundColor Cyan

    $TestFolder = Join-Path $Processed $Test.Folder
    $Pcap = Join-Path $TestFolder $Test.Pcap
    $Output = Join-Path $TestFolder "suricata-output"

    # ======================================
    # STEP 1: Validate Extracted PCAP
    # ======================================

    Write-Host ""
    Write-Host "[1/5] Checking extracted dataset..." -ForegroundColor Yellow

    if (-not (Test-Path -LiteralPath $Pcap -PathType Leaf)) {
        throw "Extracted PCAP not found: $Pcap. Run extract-dataset.py first."
    }

    $PcapInfo = Get-Item -LiteralPath $Pcap

    Write-Host "PCAP found: $($PcapInfo.Name)" -ForegroundColor Green
    Write-Host "File size: $([math]::Round($PcapInfo.Length / 1MB, 2)) MB"

    # ======================================
    # STEP 2: Run Suricata
    # ======================================

    Write-Host ""
    Write-Host "[2/5] Running Suricata analysis..." -ForegroundColor Yellow

    if (-not (Test-Path -LiteralPath $Output)) {
        New-Item -ItemType Directory -Path $Output -Force | Out-Null
    }

    # Clear only previous Suricata output files
    Get-ChildItem -LiteralPath $Output -File -ErrorAction SilentlyContinue |
        Remove-Item -Force

    & $Suricata `
        -c $Config `
        -S $Rules `
        -r $Pcap `
        -l $Output

    $SuricataExitCode = $LASTEXITCODE

    if ($SuricataExitCode -ne 0) {
        throw "Suricata execution failed. Exit code: $SuricataExitCode"
    }

    Write-Host "Suricata analysis completed." -ForegroundColor Green

    # ======================================
    # STEP 3: Validate EVE JSON
    # ======================================

    Write-Host ""
    Write-Host "[3/5] Processing Suricata results..." -ForegroundColor Yellow

    $EveFile = Join-Path $Output "eve.json"
    $FastLog = Join-Path $Output "fast.log"

    if (-not (Test-Path -LiteralPath $EveFile -PathType Leaf)) {
        throw "Suricata did not generate eve.json."
    }

    $Events = @()
    $InvalidLines = 0

    foreach ($Line in Get-Content -LiteralPath $EveFile) {

        if ([string]::IsNullOrWhiteSpace($Line)) {
            continue
        }

        try {
            $Event = $Line | ConvertFrom-Json -ErrorAction Stop

            if ($Event.event_type -and $Event.timestamp) {
                $Events += $Event
            }
            else {
                $InvalidLines++
            }
        }
        catch {
            $InvalidLines++
        }
    }

    if ($Events.Count -eq 0) {
        throw "No valid Suricata events found in eve.json."
    }

    $Alerts = @(
        $Events | Where-Object {
            $_.event_type -eq "alert" -and $_.alert
        }
    )

    Write-Host "Valid EVE events: $($Events.Count)" -ForegroundColor Green
    Write-Host "Detected alerts: $($Alerts.Count)" -ForegroundColor Green
    Write-Host "Invalid lines: $InvalidLines"

    Write-Host ""
    Write-Host "Detected Signatures:" -ForegroundColor Cyan

    if ($Alerts.Count -gt 0) {

        $Alerts |
            Group-Object { $_.alert.signature } |
            ForEach-Object {
                Write-Host "  $($_.Name): $($_.Count)"
            }

    }
    else {
        Write-Host "  No alerts detected." -ForegroundColor Yellow
    }

    # ======================================
    # STEP 4: Import into PostgreSQL
    # ======================================

    Write-Host ""
    Write-Host "[4/5] Importing results into NetSentinel..." -ForegroundColor Yellow

    if (-not (Test-Path -LiteralPath $LogsDirectory)) {
        New-Item -ItemType Directory -Path $LogsDirectory -Force | Out-Null
    }

    # Create a unique backup path for the original EVE file
    $OriginalEveExisted = Test-Path -LiteralPath $OriginalEveFile

    $BackupEveFile = Join-Path $LogsDirectory (
        "eve.json.backup-" + [guid]::NewGuid().ToString()
    )

    $IngestionResult = $null

    if ($OriginalEveExisted) {
        Copy-Item -LiteralPath $OriginalEveFile -Destination $BackupEveFile
        Write-Host "Original EVE log backed up." -ForegroundColor Green
    }

    try {

        # Place test results at the EVE path read by the backend
        Copy-Item -LiteralPath $EveFile -Destination $OriginalEveFile -Force

        Write-Host "Submitting results to backend API..."

        $IngestionResult = Invoke-RestMethod `
            -Uri $BackendUrl `
            -Method POST `
            -TimeoutSec 120 `
            -ErrorAction Stop

        if ($IngestionResult.success -eq $false) {
            throw "Backend reported an unsuccessful ingestion."
        }

        Write-Host "Backend ingestion completed." -ForegroundColor Green

    }
    finally {

        # Always restore the original EVE file
        Write-Host ""
        Write-Host "Restoring original EVE log..." -ForegroundColor Yellow

        if ($OriginalEveExisted) {

            if (Test-Path -LiteralPath $BackupEveFile -PathType Leaf) {

                Copy-Item `
                    -LiteralPath $BackupEveFile `
                    -Destination $OriginalEveFile `
                    -Force

                Remove-Item -LiteralPath $BackupEveFile -Force

                Write-Host "Original EVE log restored." -ForegroundColor Green
            }
            else {
                throw "EVE backup is missing. Original log was not restored."
            }

        }
        else {

            if (Test-Path -LiteralPath $OriginalEveFile) {
                Remove-Item -LiteralPath $OriginalEveFile -Force
            }

            Write-Host "Temporary EVE log removed. No original log existed." -ForegroundColor Green
        }
    }

    # ======================================
    # STEP 5: Display Database Report
    # ======================================

    Write-Host ""
    Write-Host "[5/5] Database ingestion report..." -ForegroundColor Yellow

    Write-Host ""
    Write-Host "========== DATABASE REPORT ==========" -ForegroundColor Cyan

    foreach ($Field in @(
        "totalLines",
        "eventsImported",
        "alertsImported",
        "duplicatesSkipped",
        "invalidEvents"
    )) {

        $Property = $IngestionResult.PSObject.Properties[$Field]

        if ($null -ne $Property) {
            Write-Host "$Field : $($Property.Value)"
        }
    }

    Write-Host "=====================================" -ForegroundColor Cyan

    # ======================================
    # Final Test Report
    # ======================================

    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host "          TEST EXECUTION COMPLETE"
    Write-Host "==========================================" -ForegroundColor Green

    Write-Host "Test:             $($Test.Name)"
    Write-Host "PCAP:             $($Test.Pcap)"
    Write-Host "EVE events:       $($Events.Count)"
    Write-Host "Suricata alerts:  $($Alerts.Count)"

    if ($null -ne $IngestionResult.eventsImported) {
        Write-Host "Events imported:  $($IngestionResult.eventsImported)"
    }

    if ($null -ne $IngestionResult.alertsImported) {
        Write-Host "Alerts imported:  $($IngestionResult.alertsImported)"
    }

    Write-Host ""
    Write-Host "Suricata output: $Output"
    Write-Host "==========================================" -ForegroundColor Green

    Write-Host ""
    Write-Host "New records should now appear in the frontend." -ForegroundColor Green
}

# ==========================================
# Main Menu
# ==========================================

while ($true) {

    Clear-Host

    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "          NetSentinel Test Runner"
    Write-Host "==========================================" -ForegroundColor Cyan

    Write-Host ""
    Write-Host "1. Run SQL Injection Test"
    Write-Host "2. Exit"
    Write-Host ""

    $Choice = Read-Host "Select an option"

    switch ($Choice) {

        "1" {
            try {
                Test-Configuration
                Invoke-Test -Test ($Tests[0])
            }
            catch {
                Write-Host ""
                Write-Host "TEST FAILED: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Check that PostgreSQL and the backend are running."
            }

            Write-Host ""
            Read-Host "Press Enter to return to menu"
        }

        "2" {
            Write-Host "Exiting NetSentinel Test Runner..." -ForegroundColor Green
            break
        }

        default {
            Write-Host "Invalid option. Please select 1 or 2." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }

    if ($Choice -eq "2") {
        break
    }
}
