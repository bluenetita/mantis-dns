# One-shot local install: generates a .env with real secrets (if missing)
# and brings the whole stack up via docker compose.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

function New-Secret {
    param([int]$Bytes = 32)
    $buf = New-Object byte[] $Bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($buf)
    -join ($buf | ForEach-Object { $_.ToString("x2") })
}

if (Test-Path .env) {
    Write-Host ".env already exists — leaving it as-is. Delete it to regenerate secrets."
} else {
    Write-Host "Creating .env with generated secrets..."
    Copy-Item .env.example .env

    $replacements = @{
        "AEGIS_INTERNAL_TOKEN"     = New-Secret
        "AEGIS_SERVICE_TOKEN"      = New-Secret
        "AEGIS_JWT_SECRET"         = New-Secret
        "AEGIS_WEBHOOK_SECRET_KEY" = New-Secret
        "POSTGRES_PASSWORD"        = New-Secret 16
    }

    $content = Get-Content .env
    foreach ($key in $replacements.Keys) {
        $content = $content -replace "^$key=.*", "$key=$($replacements[$key])"
    }
    Set-Content -Path .env -Value $content

    Write-Host "Secrets generated. ADMIN_PASSWORD is still 'change-me-now' -- change it after first login."
}

Write-Host "Starting stack (docker compose up --build -d)..."
docker compose up --build -d

Write-Host ""
Write-Host "Done. UI: http://localhost:5173  API: http://localhost:8000"
Write-Host "Log in with ADMIN_EMAIL / ADMIN_PASSWORD from .env, then rotate the password."
