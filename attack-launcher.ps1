
# ============================================================
# NETSENTINEL - ONE CLICK ATTACK DEMONSTRATION LAUNCHER
# ============================================================

$ErrorActionPreference = "Stop"

$ProjectRoot = $PSScriptRoot

$SuricataExe = "C:\Program Files\Suricata\suricata.exe"
$ConfigPath = Join-Path $ProjectRoot "suricata\windows\suricata.yaml"
$BackendEve = Join-Path $ProjectRoot "suricata\logs\eve.json"

$OutputRoot = Join-Path $ProjectRoot "suricata\windows\logs\launcher"

$Container = "netsentinel-postgres"
$Database = "netsentinel_db"
$DbUser = "netsentinel"

$BackupEve = Join-Path $ProjectRoot "suricata\logs\eve_before_launcher.json"

# ------------------------------------------------------------
# ATTACK TEST DEFINITIONS
# ------------------------------------------------------------

$Tests = @(
    @{
        Id = 1
        Name = "TCP SYN Port Scan"
        File = "port_scan_test.pcap"
    },
    @{
        Id = 2
        Name = "UDP Port Scan"
        File = "udp_port_scan_test.pcap"
    },
    @{
        Id = 3
        Name = "ICMP Flood"
        File = "icmp_flood_test.pcap"
    },
    @{
        Id = 4
        Name = "SQL Injection - UNION SELECT"
        File = "sqli_test.pcap"
    },
    @{
        Id = 5
        Name = "SQL Injection - OR 1=1"
        File = "sqli_test.pcap"
    },
    @{
        Id = 6
        Name = "Suspicious DNS Query"
        File = "dns_test.pcap"
    },
    @{
        Id = 7
        Name = "High Connection Rate"
        File = "high_connection_rate_test.pcap"
    }
)

# ------------------------------------------------------------
# DATABASE COUNT
# ------------------------------------------------------------

function Get-DatabaseCounts {

    $sql = @"
SELECT
    (SELECT COUNT(*) FROM network_events),
    (SELECT COUNT(*) FROM alerts);
"@

    $output = & docker exec $Container psql `
        -U $DbUser `
        -d $Database `
        -t -A -F "|" `
        -c $sql

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read PostgreSQL counts."
    }

    $values = ($output | Out-String).Trim().Split("|")

    if ($values.Count -lt 2) {
        throw "Invalid database count response."
    }

    return @{
        Events = [int]$values[0].Trim()
        Alerts = [int]$values[1].Trim()
    }
}

# ------------------------------------------------------------
# DISPLAY DETECTED SIGNATURES
# ------------------------------------------------------------

function Show-DetectedSignatures($EvePath) {

    $signatures = @()

    foreach ($line in Get-Content -LiteralPath $EvePath) {

        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $event = $line | ConvertFrom-Json

        if ($event.event_type -eq "alert" -and $event.alert.signature) {
            $signatures += $event.alert.signature
        }
    }

    $signatures = $signatures | Select-Object -Unique

    if ($signatures.Count -eq 0) {
        Write-Host "No Suricata signature alerts in this PCAP." -ForegroundColor Yellow
    }
    else {
        foreach ($signature in $signatures) {
            Write-Host "  DETECTED: $signature" -ForegroundColor Green
        }
    }
}

# ------------------------------------------------------------
# RUN ONE ATTACK TEST
# ------------------------------------------------------------

function Invoke-AttackTest($Test) {

    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host " RUNNING: $($Test.Name)" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan

    $PcapPath = Join-Path $ProjectRoot "sample-data\$($Test.File)"

    if (!(Test-Path $PcapPath)) {
        throw "PCAP file not found: $PcapPath"
    }

    $RunId = Get-Date -Format "yyyyMMdd-HHmmssfff"

    $OutputDir = Join-Path $OutputRoot "$($Test.Id)-$RunId"

    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    # Capture database baseline.

    $before = Get-DatabaseCounts

    Write-Host "[1/5] Running Suricata..." -ForegroundColor Yellow

    & $SuricataExe -r $PcapPath -c $ConfigPath -l $OutputDir

    if ($LASTEXITCODE -ne 0) {
        throw "Suricata execution failed."
    }

    $GeneratedEve = Join-Path $OutputDir "eve.json"

    if (!(Test-Path $GeneratedEve)) {
        throw "Suricata did not generate eve.json."
    }

    Write-Host "[2/5] Checking detection results..." -ForegroundColor Yellow

    Show-DetectedSignatures $GeneratedEve

    # Refresh timestamps so repeated PCAP demonstrations
    # produce unique database event hashes and recent flows.

    Write-Host "[3/5] Preparing fresh EVE records..." -ForegroundColor Yellow

    $lines = Get-Content -LiteralPath $GeneratedEve

    $updatedLines = [System.Collections.Generic.List[string]]::new()

    $index = 0

    foreach ($line in $lines) {

        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $event = $line | ConvertFrom-Json

        $event.timestamp = [DateTimeOffset]::Now.
            AddMilliseconds($index).
            ToString("yyyy-MM-ddTHH:mm:ss.fffzzz")

        $updatedLines.Add(
            ($event | ConvertTo-Json -Compress -Depth 100)
        )

        $index++
    }

    if ($updatedLines.Count -eq 0) {
        throw "The EVE file contains no valid records."
    }

    $TemporaryEve = "$BackendEve.launcher.tmp"

    [System.IO.File]::WriteAllLines(
        $TemporaryEve,
        $updatedLines.ToArray(),
        [System.Text.UTF8Encoding]::new($false)
    )

    # Replace backend input file.

    Move-Item -LiteralPath $TemporaryEve -Destination $BackendEve -Force

    Write-Host "[4/5] Waiting for backend ingestion..." -ForegroundColor Yellow

    $deadline = (Get-Date).AddSeconds(90)
    $after = $before

    do {

        Start-Sleep -Seconds 2

        $after = Get-DatabaseCounts

        if ($after.Events -gt $before.Events) {
            break
        }

    } while ((Get-Date) -lt $deadline)

    if ($after.Events -le $before.Events) {
        throw "Ingestion timeout. Check backend logs and EVE processing."
    }

    # Allow behavioral analysis to finish.

    Start-Sleep -Seconds 3

    $after = Get-DatabaseCounts

    $eventDelta = $after.Events - $before.Events
    $alertDelta = $after.Alerts - $before.Alerts

    Write-Host "[5/5] Ingestion completed." -ForegroundColor Green

    Write-Host ""
    Write-Host "RESULT: $($Test.Name)" -ForegroundColor Green
    Write-Host "Network events imported: $eventDelta"
    Write-Host "Security alerts created: $alertDelta"
    Write-Host "Output folder: $OutputDir"

    return $true
}

# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "       NETSENTINEL ATTACK LAUNCHER"
Write-Host "===============================================" -ForegroundColor Cyan

# Preflight checks.

if (!(Test-Path $SuricataExe)) {
    throw "Suricata executable not found."
}

if (!(Test-Path $ConfigPath)) {
    throw "Suricata configuration not found."
}

if (!(Test-Path $BackendEve)) {
    throw "Backend EVE input file not found."
}

$null = Get-DatabaseCounts

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null

Write-Host ""
Write-Host "Select an attack scenario:" -ForegroundColor White

foreach ($test in $Tests) {
    Write-Host "$($test.Id). $($test.Name)"
}

Write-Host "8. RUN ALL TESTS"
Write-Host "0. EXIT"

$choice = Read-Host "`nEnter your choice"

if ($choice -eq "0") {
    exit
}

$selectedTests = @()

if ($choice -eq "8") {
    $selectedTests = $Tests
}
else {
    $selectedTests = @($Tests | Where-Object { $_.Id -eq [int]$choice })

    if ($selectedTests.Count -eq 0) {
        Write-Host "Invalid selection." -ForegroundColor Red
        exit
    }
}

# Preserve the original backend input.

Copy-Item $BackendEve $BackupEve -Force

$results = @()

try {

    foreach ($test in $selectedTests) {

        try {
            $success = Invoke-AttackTest $test

            $results += @{
                Name = $test.Name
                Success = $success
            }
        }
        catch {

            Write-Host ""
            Write-Host "FAILED: $($test.Name)" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red

            $results += @{
                Name = $test.Name
                Success = $false
            }
        }
    }

}
finally {

    # Restore original EVE input.

    Copy-Item $BackupEve $BackendEve -Force

    Write-Host ""
    Write-Host "Original EVE input restored." -ForegroundColor Green
}

# ------------------------------------------------------------
# FINAL REPORT
# ------------------------------------------------------------

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "             DEMONSTRATION REPORT"
Write-Host "===============================================" -ForegroundColor Cyan

foreach ($result in $results) {

    if ($result.Success) {
        Write-Host "[PASS] $($result.Name)" -ForegroundColor Green
    }
    else {
        Write-Host "[FAIL] $($result.Name)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "NetSentinel demonstration finished." -ForegroundColor Cyan
Write-Host "Check your browser dashboard for the imported results."
