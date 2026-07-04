# Renders infra/cloud-init/user-data.yaml.tmpl into a ready-to-paste
# cloud-init user-data document: embeds the current docker-compose.prod.yml
# and a .env pre-filled with your CORS origin / image registry / version
# (secrets are left for the instance to generate at first boot -- see the
# template's runcmd). Single source of truth stays docker-compose.prod.yml
# and .env.example; nothing is duplicated by hand here.
param(
    [Parameter(Mandatory = $true)]
    [string]$Cors,
    [string]$ImagePrefix = "ghcr.io/mantis-dns/mantis-dns",
    [string]$Version = "latest",
    [string]$Output = "infra/cloud-init/user-data.yaml"
)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$template = Get-Content "infra/cloud-init/user-data.yaml.tmpl"
$composeLines = Get-Content "docker-compose.prod.yml"

$envLines = (Get-Content ".env.example") | ForEach-Object {
    if ($_ -match "^CORS_ALLOW_ORIGINS=") { "CORS_ALLOW_ORIGINS=$Cors" }
    elseif ($_ -match "^MANTIS_ENV=") { "MANTIS_ENV=production" }
    else { $_ }
}
$envLines += "IMAGE_PREFIX=$ImagePrefix"
$envLines += "MANTIS_VERSION=$Version"

function Splice-Marker {
    param([string[]]$Lines, [string[]]$Content, [string]$Marker)
    $result = New-Object System.Collections.Generic.List[string]
    foreach ($line in $Lines) {
        if ($line.Trim() -eq $Marker) {
            $indent = $line.Substring(0, $line.Length - $line.TrimStart().Length)
            foreach ($contentLine in $Content) {
                if ($contentLine -eq "") { $result.Add("") }
                else { $result.Add("$indent$contentLine") }
            }
        } else {
            $result.Add($line)
        }
    }
    return $result
}

$pass1 = Splice-Marker -Lines $template -Content $composeLines -Marker "__COMPOSE_FILE_CONTENT__"
$final = Splice-Marker -Lines $pass1 -Content $envLines -Marker "__ENV_FILE_CONTENT__"

Set-Content -Path $Output -Value $final
Write-Host "Wrote $Output"
Write-Host "Paste its contents into your provider's user-data / cloud-init field when launching the VM."
