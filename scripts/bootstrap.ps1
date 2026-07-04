<#
Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
#>

# One-shot install: generates a .env with real secrets (if missing) and
# brings the stack up via docker compose.
#
# Dev mode (default): builds images from source, Vite dev server on :5173.
# Prod mode (-Prod):   pulls published GHCR images (docker-compose.prod.yml),
#                       generates a strong ADMIN_PASSWORD too, sets
#                       MANTIS_ENV=production. You must still set
#                       CORS_ALLOW_ORIGINS (and IMAGE_PREFIX/MANTIS_VERSION if
#                       not using the default registry) in .env yourself.
param(
    [switch]$Prod
)
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
        "MANTIS_INTERNAL_TOKEN"     = New-Secret
        "MANTIS_SERVICE_TOKEN"      = New-Secret
        "MANTIS_JWT_SECRET"         = New-Secret
        "MANTIS_WEBHOOK_SECRET_KEY" = New-Secret
        "POSTGRES_PASSWORD"        = New-Secret 16
    }

    if ($Prod) {
        $adminPassword = New-Secret 16
        $replacements["ADMIN_PASSWORD"] = $adminPassword
        $replacements["MANTIS_ENV"] = "production"
    }

    $content = Get-Content .env
    foreach ($key in $replacements.Keys) {
        $content = $content -replace "^$key=.*", "$key=$($replacements[$key])"
    }
    Set-Content -Path .env -Value $content

    if ($Prod) {
        Write-Host "Secrets generated, including ADMIN_PASSWORD (shown once): $adminPassword"
        Write-Host "Before starting: set CORS_ALLOW_ORIGINS in .env to your UI's public origin(s)."
    } else {
        Write-Host "Secrets generated. ADMIN_PASSWORD is still 'change-me-now' -- change it after first login."
    }
}

if ($Prod) {
    Write-Host "Pulling images and starting stack (docker compose -f docker-compose.prod.yml up -d)..."
    docker compose -f docker-compose.prod.yml pull
    docker compose -f docker-compose.prod.yml up -d
    Write-Host ""
    Write-Host "Done. UI: http://localhost/  API: http://localhost:8000"
} else {
    Write-Host "Starting stack (docker compose up --build -d)..."
    docker compose up --build -d
    Write-Host ""
    Write-Host "Done. UI: http://localhost:5173  API: http://localhost:8000"
}
Write-Host "Log in with ADMIN_EMAIL / ADMIN_PASSWORD from .env, then rotate the password."
