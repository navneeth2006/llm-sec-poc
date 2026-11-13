# One command for the whole real run. Usage:  .\run_all.ps1            (3 trials)
#                                             .\run_all.ps1 -Trials 5
param([int]$Trials = 3)
if (-not $env:VIRTUAL_ENV) { & .\.venv\Scripts\Activate.ps1 }
function Run($cmd) { Write-Host "`n>>> $cmd" -ForegroundColor Cyan; Invoke-Expression $cmd; if ($LASTEXITCODE -ne 0) { Write-Host "Step failed: $cmd" -ForegroundColor Red; exit 1 } }

if (Test-Path results\results.csv) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    New-Item -ItemType Directory -Force results\old | Out-Null
    Move-Item results\results.csv "results\old\results-$stamp.csv"
    if (Test-Path results\utility.csv) { Move-Item results\utility.csv "results\old\utility-$stamp.csv" }
    Write-Host "Old results archived to results\old\"
}
Run "python runner.py --models claude gemini --trials $Trials"
Run "python runner.py --models claude gemini --utility"
Run "python make_sheet.py"
Run "python analyze.py results\results.csv | Tee-Object results\analysis_notes.txt"
Run "python report\make_report.py results\results.csv"
Write-Host "`nDONE. Now write report\analysis.md, rebuild the report, then run: python check_ready.py" -ForegroundColor Green
